"""LEB128 decoding with *canonical* vs *overflow* diagnostics kept separate.

The validator distinguishes two distinct failure kinds that are easy to
conflate in a hand-written decoder:

* ``leb_noncanonical`` - the value fits in the declared bit width, but it
  could have been encoded in fewer bytes (trailing continuation / padding
  bits carry no information).
* ``leb_overflow`` - the decoded magnitude does not fit the declared width.

Both can occur at once (an over-long encoding that also overflows); in that
case the primary code is ``leb_overflow`` and ``noncanonical`` stays true so
the distinction survives in the event archive.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class LebResult:
    value: int
    end: int                 # exclusive offset of the last consumed byte
    noncanonical: bool = False
    overflow: bool = False

    @property
    def ok(self) -> bool:
        return not self.overflow

    def codes(self) -> list[str]:
        out: list[str] = []
        if self.overflow:
            out.append("leb_overflow")
        if self.noncanonical:
            out.append("leb_noncanonical")
        return out


def _gather(data: bytes, start: int, max_bytes: int) -> tuple[int, int, bool]:
    """Return (raw_value, end, truncated)."""
    value = 0
    shift = 0
    pos = start
    truncated = False
    while True:
        if pos - start >= max_bytes:
            # The next byte (if any) would exceed the legal byte count.
            return value, pos, True
        if pos >= len(data):
            truncated = True
            return value, pos, True
        b = data[pos]
        value |= (b & 0x7F) << shift
        pos += 1
        if (b & 0x80) == 0:
            return value, pos, False
        shift += 7


def decode_u(data: bytes, start: int, bits: int = 32) -> LebResult:
    """Decode an unsigned LEB128 of the given bit width."""
    max_bytes = (bits + 6) // 7
    value, end, truncated = _gather(data, start, max_bytes)
    if truncated:
        return LebResult(value=value, end=min(end, len(data)), noncanonical=True, overflow=False)
    n = end - start
    last = data[end - 1] & 0x7F
    overflow = False
    if bits % 7:
        overflow = bool(last & (0x7F & ~((1 << (bits % 7)) - 1)))
    noncanonical = False
    if n > 1:
        if last == 0:
            noncanonical = True
        elif bits % 7 == 0 and last & 0x40:
            noncanonical = True
    return LebResult(value=value, end=end, noncanonical=noncanonical, overflow=overflow)


def decode_s(data: bytes, start: int, bits: int = 32) -> LebResult:
    """Decode a signed LEB128 of the given bit width (32, 33, 64)."""
    max_bytes = (bits + 6) // 7
    value, end, truncated = _gather(data, start, max_bytes)
    if truncated:
        return LebResult(value=value, end=min(end, len(data)), noncanonical=True, overflow=False)
    n = end - start
    shift = 7 * (n - 1)
    signed = value
    if shift < bits and (data[end - 1] & 0x40):
        signed |= -(1 << (shift + 7))
    last = data[end - 1] & 0x7F
    overflow = False
    if shift < bits:
        sign = 1 if (last & 0x40) else 0
        # Bits above `bits` in the last group must all equal the sign bit.
        for bit in range(bits - shift, 7):
            if bool((last >> bit) & 1) != bool(sign):
                overflow = True
                break
    else:
        # shift == bits only when bits % 7 == 0: sign bit must be bit 6.
        if not (last & 0x40):
            overflow = True
    noncanonical = False
    if n > 1:
        if not (last & 0x40):
            if last == 0:
                noncanonical = True
        else:
            if last == 0x7F:
                noncanonical = True
    return LebResult(value=signed, end=end, noncanonical=noncanonical, overflow=overflow)


def enc_u(value: int) -> bytes:
    """Canonical unsigned LEB128 (used by the sample builder)."""
    if value < 0:
        raise ValueError("unsigned value must be non-negative")
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def enc_s(value: int) -> bytes:
    """Canonical signed LEB128."""
    out = bytearray()
    more = True
    while more:
        b = value & 0x7F
        value >>= 7
        sign = b & 0x40
        if (value == 0 and not sign) or (value == -1 and sign):
            more = False
            out.append(b)
        else:
            out.append(b | 0x80)
    return bytes(out)
