"""LEB128 decoding.

Hard requirement: a non-canonical (overlong) encoding is a *different*
diagnostic from a numeric overflow. Decoders therefore return the decoded
value plus the raw encoding, and report `leb.noncanonical` separately from
`leb.overflow`.
"""
from __future__ import annotations

from dataclasses import dataclass


class LebError(Exception):
    code = "leb.error"

    def __init__(self, message: str, span: tuple[int, int]):
        super().__init__(message)
        self.span = span


class LebTruncated(LebError):
    code = "leb.truncated"


class LebOverflow(LebError):
    code = "leb.overflow"


@dataclass
class Leb:
    value: int
    start: int
    end: int  # exclusive
    raw: bytes
    canonical: bool
    signed: bool
    bits: int

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "span": [self.start, self.end],
            "raw_hex": self.raw.hex(),
            "canonical": self.canonical,
            "signed": self.signed,
            "bits": self.bits,
        }


def _min_unsigned_len(value: int) -> int:
    if value == 0:
        return 1
    return (value.bit_length() + 6) // 7


def _min_signed_len(value: int, bits: int) -> int:
    # Smallest n such that value fits in n*7 sign-carrying bits.
    for n in range(1, (bits + 6) // 7 + 1):
        width = n * 7
        lo = -(1 << (width - 1))
        hi = (1 << (width - 1)) - 1
        if lo <= value <= hi:
            return n
    return (bits + 6) // 7


def decode_unsigned(data: bytes, pos: int, bits: int) -> Leb:
    start = pos
    result = 0
    shift = 0
    max_bytes = (bits + 6) // 7
    while True:
        if pos >= len(data):
            raise LebTruncated("truncated unsigned LEB128", (start, pos))
        byte = data[pos]
        pos += 1
        n_bytes = pos - start
        if n_bytes > max_bytes:
            raise LebOverflow(
                f"unsigned LEB128 exceeds {max_bytes} bytes for u{bits}", (start, pos)
            )
        result |= (byte & 0x7F) << shift
        shift += 7
        if byte & 0x80 == 0:
            break
    if result >= (1 << bits):
        raise LebOverflow(f"value {result} does not fit u{bits}", (start, pos))
    raw = data[start:pos]
    return Leb(result, start, pos, raw, len(raw) == _min_unsigned_len(result), False, bits)


def decode_signed(data: bytes, pos: int, bits: int) -> Leb:
    start = pos
    result = 0
    shift = 0
    max_bytes = (bits + 6) // 7
    byte = 0
    while True:
        if pos >= len(data):
            raise LebTruncated("truncated signed LEB128", (start, pos))
        byte = data[pos]
        pos += 1
        n_bytes = pos - start
        if n_bytes > max_bytes:
            raise LebOverflow(
                f"signed LEB128 exceeds {max_bytes} bytes for s{bits}", (start, pos)
            )
        result |= (byte & 0x7F) << shift
        shift += 7
        if byte & 0x80 == 0:
            break
    if shift < bits and (byte & 0x40):
        result |= -(1 << shift)
    lo = -(1 << (bits - 1))
    hi = (1 << (bits - 1)) - 1
    if not (lo <= result <= hi):
        raise LebOverflow(f"value {result} does not fit s{bits}", (start, pos))
    raw = data[start:pos]
    return Leb(result, start, pos, raw, len(raw) == _min_signed_len(result, bits), True, bits)


def decode_u32(data: bytes, pos: int) -> Leb:
    return decode_unsigned(data, pos, 32)


def decode_s32(data: bytes, pos: int) -> Leb:
    return decode_signed(data, pos, 32)


def decode_s33(data: bytes, pos: int) -> Leb:
    return decode_signed(data, pos, 33)


def decode_s64(data: bytes, pos: int) -> Leb:
    return decode_signed(data, pos, 64)
