"""Unsigned LEB128 decoding.

Non-canonical encodings and out-of-range values are kept as *separate*
diagnostics: noncanonical means the integer is in bounds but its
representation had redundant leading bytes/bits; out_of_range means the
represented integer exceeds the declared bit width.  They can co-occur and
must never be collapsed into one finding.

All values keep their original byte coordinates and an explicit unknown state
is exposed for truncated input, so callers never invent a value.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class LebU32:
    """Result of decoding a u32 LEB128, with every judgment as first-class data."""

    start: int
    end: int
    value: int | None
    truncated: bool
    noncanonical: bool
    out_of_range: bool
    raw: bytes
    candidates: tuple[int, ...] = field(default_factory=tuple)

    @property
    def unknown(self) -> bool:
        """True when the value cannot be uniquely determined."""
        return self.value is None

    def diagnostics(self) -> tuple[str, ...]:
        out: list[str] = []
        if self.truncated:
            out.append("truncated")
        if self.noncanonical:
            out.append("noncanonical")
        if self.out_of_range:
            out.append("out_of_range")
        return tuple(out)


def decode_u32(buf: bytes, start: int, hard_end: int | None = None) -> LebU32:
    """Decode one unsigned LEB128 as a u32 starting at ``start``.

    ``hard_end`` bounds the scan (e.g. section end).  A missing terminator
    yields an unknown value plus truncated; the value is never guessed.
    """
    end_bound = len(buf) if hard_end is None else min(hard_end, len(buf))
    raw = bytearray()
    result = 0
    shift = 0
    pos = start
    terminated = False
    while pos < end_bound:
        b = buf[pos]
        raw.append(b)
        pos += 1
        chunk = b & 0x7F
        result |= chunk << shift
        shift += 7
        if (b & 0x80) == 0:
            terminated = True
            break
        if len(raw) >= 5:
            break
    raw_b = bytes(raw)
    if not terminated:
        overlong = len(raw_b) == 5 and (raw_b[4] & 0x80) != 0
        return LebU32(start, pos, None, truncated=True,
                      noncanonical=overlong, out_of_range=overlong, raw=raw_b)
    n = len(raw_b)
    last = raw_b[-1]
    noncanonical = False
    if n < 5:
        if n > 1 and last == 0:
            noncanonical = True
    else:
        if last & 0x70:
            return LebU32(start, pos, None, truncated=False,
                          noncanonical=True, out_of_range=True, raw=raw_b)
        if last == 0:
            noncanonical = True
    return LebU32(start, pos, result, truncated=False,
                  noncanonical=noncanonical, out_of_range=False, raw=raw_b,
                  candidates=(result,))


def encode_u32(value: int) -> bytes:
    """Canonical LEB128 encoder (sample builder use only)."""
    if value < 0:
        raise ValueError("unsigned only")
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def encode_s32(value: int) -> bytes:
    """Canonical signed LEB128 (i32) encoder for the sample builder."""
    out = bytearray()
    more = True
    while more:
        b = value & 0x7F
        value >>= 7
        sign = b & 0x40
        if (value == 0 and not sign) or (value == -1 and sign):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)


def decode_s32(buf: bytes, start: int, hard_end: int | None = None) -> LebU32:
    """Decode signed LEB128 as i32; sign-extension uses the same LebU32 shape."""
    end_bound = len(buf) if hard_end is None else min(hard_end, len(buf))
    raw = bytearray()
    result = 0
    shift = 0
    pos = start
    terminated = False
    while pos < end_bound:
        b = buf[pos]
        raw.append(b)
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            terminated = True
            break
        if len(raw) >= 5:
            break
    raw_b = bytes(raw)
    if not terminated:
        overlong = len(raw_b) == 5 and (raw_b[4] & 0x80) != 0
        return LebU32(start, pos, None, truncated=True,
                      noncanonical=overlong, out_of_range=overlong, raw=raw_b)
    last = raw_b[-1]
    if shift < 32 and (last & 0x40):
        result |= -(1 << shift)
    n = len(raw_b)
    noncanonical = False
    if n > 1:
        prev_bits = (n - 1) * 7
        low = -(1 << (prev_bits - 1))
        high = 1 << (prev_bits - 1)
        noncanonical = low <= result < high
    return LebU32(start, pos, result, truncated=False,
                  noncanonical=noncanonical, out_of_range=False, raw=raw_b,
                  candidates=(result,))
