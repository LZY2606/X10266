"""LEB128 codec.

Core principle: a *non-canonical encoding* (overlong form) and a *numeric
overflow* (value does not fit the target width) are two distinct defects and
are reported separately.  Every decoded value keeps its original byte range
so the raw representation is never lost.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Leb:
    offset: int            # file offset of first byte (unit: wasm-file-offset)
    raw: bytes             # original bytes, preserved verbatim
    value: int | None      # decoded value; None when truncated/overflow
    canonical: bool
    overflow: bool
    truncated: bool
    signed: bool = False

    @property
    def end(self) -> int:
        return self.offset + len(self.raw)

    def to_dict(self) -> dict:
        return {
            "offset": {"value": self.offset, "unit": "wasm-file-offset"},
            "end": {"value": self.end, "unit": "wasm-file-offset"},
            "raw_hex": self.raw.hex(),
            "value": self.value,
            "canonical": self.canonical,
            "overflow": self.overflow,
            "truncated": self.truncated,
            "signed": self.signed,
        }


def encode_u32(n: int) -> bytes:
    if n < 0 or n > 0xFFFFFFFF:
        raise ValueError("u32 out of range")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def encode_s32(n: int) -> bytes:
    if n < -(1 << 31) or n > (1 << 31) - 1:
        raise ValueError("s32 out of range")
    out = bytearray()
    more = True
    while more:
        b = n & 0x7F
        n >>= 7
        if (n == 0 and not (b & 0x40)) or (n == -1 and (b & 0x40)):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)


def decode_u32(data: bytes, offset: int) -> Leb:
    raw = bytearray()
    value = 0
    shift = 0
    for i in range(5):
        if offset + i >= len(data):
            return Leb(offset, bytes(raw), None, False, False, True)
        b = data[offset + i]
        raw.append(b)
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            if i == 4 and (b & 0x70):
                # bits beyond bit 31 set in the 5th byte: numeric overflow,
                # NOT an encoding-canonicality problem.
                return Leb(offset, bytes(raw), None, False, True, False)
            canonical = bytes(raw) == encode_u32(value)
            return Leb(offset, bytes(raw), value, canonical, False, False)
        shift += 7
    # 5 continuation bytes: value cannot fit u32.
    return Leb(offset, bytes(raw), None, False, True, False)


def decode_s32(data: bytes, offset: int) -> Leb:
    raw = bytearray()
    value = 0
    shift = 0
    for i in range(5):
        if offset + i >= len(data):
            return Leb(offset, bytes(raw), None, False, False, True, signed=True)
        b = data[offset + i]
        raw.append(b)
        value |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if shift < 32 and (b & 0x40):
                value |= -(1 << shift)
            if i == 4:
                # remaining bits must be a sign-extension of bit 31
                sign = 1 if value < 0 else 0
                residue = (b & 0x7F) >> 4 if False else None
                # check unused bits of 5th byte equal the sign bit
                unused = (b & 0x70) >> 4
                expect = 0x7 if sign else 0x0
                if unused not in (expect,):
                    if not (sign and unused == 0x7) and not (not sign and unused == 0x0):
                        return Leb(offset, bytes(raw), None, False, True, False, signed=True)
            canonical = bytes(raw) == encode_s32(value)
            return Leb(offset, bytes(raw), value, canonical, False, False, signed=True)
    return Leb(offset, bytes(raw), None, False, True, False, signed=True)
