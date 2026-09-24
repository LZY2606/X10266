"""Unsigned / signed LEB128 decoding with strict canonicality accounting.

Three distinct deviation classes are kept separate on purpose:

* ``LEB_NONCANONICAL`` -- the value fits the declared width and is fully
  recoverable, but more bytes are used than the canonical encoding needs
  (redundant zero/sign-extension bytes).
* ``LEB_RANGE`` -- the recovered integer does not fit the declared bit
  width (for example a 32-bit count decoding to 2**32).
* ``LEB_TRUNCATED`` -- the byte stream ends while the continuation bit
  is still set, so no complete value exists.

Non-canonical encoding and numeric overflow are never conflated.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

LEB_OK = "LEB_OK"
LEB_TRUNCATED = "LEB_TRUNCATED"
LEB_NONCANONICAL = "LEB_NONCANONICAL"
LEB_RANGE = "LEB_RANGE"


@dataclass(frozen=True)
class LEBToken:
    """One decoded LEB128 value with its byte provenance."""

    start: int
    end: int  # exclusive
    value: Optional[int]
    kind: str  # "u" or "s"
    width: int  # declared bit width (7/16/32/64)
    deviations: Tuple[str, ...] = field(default_factory=tuple)

    def is_ok(self) -> bool:
        return not self.deviations and self.value is not None


def encode_u(value: int) -> bytes:
    """Canonical unsigned LEB128 (builder/test helper)."""
    if value < 0:
        raise ValueError("unsigned LEB cannot encode negative value")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def encode_s(value: int) -> bytes:
    """Canonical signed LEB128 (builder/test helper)."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        sign_bit = byte & 0x40
        if (value == 0 and not sign_bit) or (value == -1 and sign_bit):
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


def _read_groups(data: bytes, pos: int) -> Tuple[Optional[int], int, int, bool]:
    """Read continuation groups; return (raw payload, new_pos, count, truncated)."""
    raw = 0
    shift = 0
    count = 0
    while True:
        if pos >= len(data):
            return None, pos, count, True
        byte = data[pos]
        raw |= (byte & 0x7F) << shift
        pos += 1
        count += 1
        if byte & 0x80 == 0:
            return raw, pos, count, False
        shift += 7


def decode_u(data: bytes, pos: int, width: int = 32) -> LEBToken:
    start = pos
    raw, new_pos, count, truncated = _read_groups(data, pos)
    devs: List[str] = []
    if truncated:
        devs.append(LEB_TRUNCATED)
        return LEBToken(start, new_pos, raw, "u", width, tuple(devs))
    max_value = (1 << width) - 1
    if raw > max_value:
        devs.append(LEB_RANGE)
    else:
        canonical_len = len(encode_u(raw))
        if count > canonical_len:
            devs.append(LEB_NONCANONICAL)
    return LEBToken(start, new_pos, raw, "u", width, tuple(devs))


def decode_s(data: bytes, pos: int, width: int = 32) -> LEBToken:
    start = pos
    raw, new_pos, count, truncated = _read_groups(data, pos)
    devs: List[str] = []
    if truncated:
        devs.append(LEB_TRUNCATED)
        return LEBToken(start, new_pos, None, "s", width, tuple(devs))
    total_bits = count * 7
    sign_at = total_bits - 7 + 6  # bit index of terminal sign bit
    if raw & (1 << sign_at):
        value = raw - (1 << total_bits)
    else:
        value = raw
    min_v = -(1 << (width - 1))
    max_v = (1 << (width - 1)) - 1
    if value < min_v or value > max_v:
        devs.append(LEB_RANGE)
    elif count > len(encode_s(value)):
        devs.append(LEB_NONCANONICAL)
    return LEBToken(start, new_pos, value, "s", width, tuple(devs))
