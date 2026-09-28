"""LEB128 decoding with three separable outcomes.

* ``NONCANONICAL_LEB128`` — the integer fits and decodes, but the byte encoding
  is not the unique shortest form. Decided by re-encoding the decoded value and
  comparing bytes byte-for-byte; hence it can never be confused with overflow.
* ``INTEGER_OUT_OF_RANGE`` — the encoded integer overflows the declared bit
  width (u32 / s33 / s7). This is a numeric-range error, never reported as a
  non-canonical encoding.
* truncated input — no unique terminal value; every legal terminal byte/value
  consistent with the observed prefix is returned as a candidate.
"""
from __future__ import annotations

from dataclasses import dataclass

from .model import Candidate, Span


@dataclass
class LebResult:
    value: int | None
    kind: str          # u32 | s33 | s7
    start: int
    end: int           # bytes consumed (partial if terminated is False)
    terminated: bool
    noncanonical: bool
    overflow: bool
    overflow_value: int | None
    canonical_bytes: list[int]
    raw_hex: str
    candidates: list[Candidate]
    note: str = ""

    @property
    def span(self) -> Span:
        return Span(self.start, self.end)


def _hex(data: bytes) -> str:
    return data.hex(" ")


def decode_unsigned(data: bytes, pos: int, kind: str = "u32", source_id: str = "v1") -> LebResult:
    max_bits = 32 if kind == "u32" else 33
    start = pos
    result = 0
    shift = 0
    for count in range(5):
        if pos >= len(data):
            return _truncated_unsigned(data, start, pos, result, shift, kind, source_id,
                                       "continuation bit set but input ended")
        byte = data[pos]
        pos += 1
        payload = byte & 0x7F
        bits_left = max_bits - shift
        if count == 4:
            # last permitted byte may carry only the remaining bits
            if payload > (1 << bits_left) - 1:
                return LebResult(
                    value=None, kind=kind, start=start, end=pos, terminated=False,
                    noncanonical=False, overflow=True, overflow_value=result | (payload << shift),
                    canonical_bytes=[], raw_hex=_hex(data[start:pos]), candidates=[],
                    note=f"last byte payload {payload} exceeds {bits_left} available bits of {kind}",
                )
        result |= payload << shift
        shift += 7
        if byte & 0x80 == 0:
            canonical = encode_unsigned(result)
            consumed = bytes(data[start:pos])
            noncanonical = list(canonical) != list(consumed)
            return LebResult(
                value=result, kind=kind, start=start, end=pos, terminated=True,
                noncanonical=noncanonical, overflow=False, overflow_value=None,
                canonical_bytes=list(canonical), raw_hex=_hex(consumed), candidates=[],
                note="canonical" if not noncanonical else "value re-encodes to a shorter byte sequence",
            )
    # five bytes consumed while the fifth still asks for more
    return LebResult(
        value=None, kind=kind, start=start, end=pos, terminated=False,
        noncanonical=False, overflow=True, overflow_value=result,
        canonical_bytes=[], raw_hex=_hex(data[start:pos]), candidates=[],
        note=f"LEB128 exceeds the 5-byte limit for {kind}",
    )


def _truncated_unsigned(data: bytes, start: int, end: int, partial: int, shift: int,
                        kind: str, source_id: str, why: str) -> LebResult:
    bits_here = min(7, (32 if kind == "u32" else 33) - shift)
    limit = 1 << bits_here
    candidates: list[Candidate] = []
    for payload in range(limit):
        value = partial | (payload << shift)
        terminal = bytes(data[start:end]) + bytes([payload])
        candidates.append(
            Candidate(
                value=str(value),
                basis=f"terminal byte 0x{payload:02x} ({terminal.hex(' ')})",
                spans=[Span(end, end + 1, source_id)],
            )
        )
    return LebResult(
        value=None, kind=kind, start=start, end=end, terminated=False,
        noncanonical=False, overflow=False, overflow_value=None,
        canonical_bytes=[], raw_hex=_hex(data[start:end]),
        candidates=candidates, note=why,
    )


def decode_signed(data: bytes, pos: int, kind: str = "s33", source_id: str = "v1") -> LebResult:
    max_bits = 33 if kind == "s33" else 7
    max_bytes = 5 if kind == "s33" else 1
    start = pos
    result = 0
    shift = 0
    for count in range(max_bytes):
        if pos >= len(data):
            return _truncated_signed(data, start, pos, result, shift, kind, source_id,
                                     "continuation bit set but input ended")
        byte = data[pos]
        pos += 1
        payload = byte & 0x7F
        bits_left = max_bits - shift
        if count == max_bytes - 1 and kind == "s33":
            # s33 fifth byte carries exactly one value bit: 0x00 or 0x01
            if payload > 0x01:
                return LebResult(
                    value=None, kind=kind, start=start, end=pos,
                    terminated=False, noncanonical=False, overflow=True,
                    overflow_value=result | (payload << shift),
                    canonical_bytes=[], raw_hex=_hex(data[start:pos]), candidates=[],
                    note=f"s33 final byte must be 0x00/0x01, got 0x{payload:02x}",
                )
        result |= payload << shift
        shift += 7
        if byte & 0x80 == 0:
            if payload & 0x40:
                result |= -(1 << shift)
            value = result
            canonical = encode_signed(value, max_bits)
            consumed = bytes(data[start:pos])
            noncanonical = list(canonical) != list(consumed)
            return LebResult(
                value=value, kind=kind, start=start, end=pos, terminated=True,
                noncanonical=noncanonical, overflow=False, overflow_value=None,
                canonical_bytes=list(canonical), raw_hex=_hex(consumed), candidates=[],
                note="canonical" if not noncanonical else "sign extension repeats prior bits",
            )
    return LebResult(
        value=None, kind=kind, start=start, end=pos, terminated=False,
        noncanonical=False, overflow=True, overflow_value=result,
        canonical_bytes=[], raw_hex=_hex(data[start:pos]), candidates=[],
        note=f"LEB128 exceeds the {max_bytes}-byte limit for {kind}",
    )


def _truncated_signed(data: bytes, start: int, end: int, partial: int, shift: int,
                      kind: str, source_id: str, why: str) -> LebResult:
    max_bits = 33 if kind == "s33" else 7
    bits_here = min(7, max_bits - shift)
    candidates: list[Candidate] = []
    for payload in range(1 << bits_here):
        value = partial | (payload << shift)
        if payload & (1 << (bits_here - 1)):
            value |= -(1 << (shift + bits_here))
        terminal = bytes(data[start:end]) + bytes([payload])
        candidates.append(
            Candidate(
                value=str(value),
                basis=f"terminal byte 0x{payload:02x} ({terminal.hex(' ')})",
                spans=[Span(end, end + 1, source_id)],
            )
        )
    return LebResult(
        value=None, kind=kind, start=start, end=end, terminated=False,
        noncanonical=False, overflow=False, overflow_value=None,
        canonical_bytes=[], raw_hex=_hex(data[start:end]),
        candidates=candidates, note=why,
    )


def encode_unsigned(value: int) -> bytes:
    if value < 0:
        raise ValueError("unsigned cannot encode negative")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def encode_signed(value: int, bits: int = 33) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        next_value = value >> 7
        sign_bit = byte & 0x40
        if (next_value == 0 and not sign_bit) or (next_value == -1 and sign_bit):
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)
        value = next_value
