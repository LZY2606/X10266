"""LEB128 decoding for the module-boundary court.

Domain rule (non-canonical encoding != value out of range):

* ``non_canonical`` — the bytes decode to a representable value, but they are
  not the unique shortest encoding.  The decoded value is still trustworthy.
* ``overflow`` — the represented integer cannot fit the target bit width.
  No trustworthy value is produced; callers go into error recovery.
* truncated input (running into the payload boundary mid-byte) is reported by
  ``truncated`` and also implies ``overflow`` (no value available).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LEBResult:
    value: int
    signed: bool
    bits: int
    start: int
    end: int                 # exclusive byte offset of consumed bytes
    raw: bytes
    truncated: bool
    non_canonical: bool
    overflow: bool
    candidates: tuple        # legal values; empty whenever value untrusted


def minimal_unsigned_len(value: int) -> int:
    n = 1
    while value >= 0x80:
        value >>= 7
        n += 1
    return n


def minimal_signed_len(value: int) -> int:
    n = 0
    while True:
        byte = value & 0x7F
        value >>= 7
        n += 1
        sign_bit = byte & 0x40
        if (value == 0 and not sign_bit) or (value == -1 and sign_bit):
            return n


def _read_bytes(data: bytes, pos: int, end: int) -> tuple[bytes, bool, int]:
    raw = bytearray()
    truncated = False
    while True:
        if pos >= end:
            return bytes(raw), True, pos
        byte = data[pos]
        raw.append(byte)
        pos += 1
        if not (byte & 0x80):
            return bytes(raw), truncated, pos


def decode_uleb128(data: bytes, pos: int, end: int | None = None,
                   bits: int = 32) -> LEBResult:
    end = len(data) if end is None else end
    start = pos
    raw, truncated, pos = _read_bytes(data, pos, end)
    value = 0
    shift = 0
    overflow = truncated
    for byte in raw:
        chunk = byte & 0x7F
        if shift < bits:
            kept = min(7, bits - shift)
            if chunk >> kept:
                overflow = True
            value |= (chunk & ((1 << kept) - 1)) << shift
        elif chunk != 0:
            overflow = True
        shift += 7
    non_canonical = False
    if not overflow and len(raw) > minimal_unsigned_len(value):
        non_canonical = True
    candidates = () if (overflow or non_canonical) else (value,)
    return LEBResult(value, False, bits, start, pos, raw, truncated,
                     non_canonical, overflow, candidates)


def decode_sleb128(data: bytes, pos: int, end: int | None = None,
                   bits: int = 32) -> LEBResult:
    end = len(data) if end is None else end
    start = pos
    raw, truncated, pos = _read_bytes(data, pos, end)
    value = 0
    shift = 0
    for byte in raw:
        value |= (byte & 0x7F) << shift
        shift += 7
    last = raw[-1] if raw else 0
    if raw and (last & 0x40):
        value |= -(1 << shift)
    lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    overflow = truncated or not (lo <= value <= hi)
    non_canonical = False
    if not overflow and len(raw) > minimal_signed_len(value):
        non_canonical = True
    candidates = () if (overflow or non_canonical) else (value,)
    return LEBResult(value, True, bits, start, pos, raw, truncated,
                     non_canonical, overflow, candidates)
