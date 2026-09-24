"""LEB128 decoding with non-canonical and overflow kept as separate facts.

The audit distinguishes three independent observations:

* truncation  -> the byte stream ended before the terminating byte;
* noncanonical -> the encoding uses unnecessary continuation bytes/padding;
* overflow    -> the decoded integer does not fit the declared bit width.

On truncation we cannot uniquely decide the value, so every legal completion
is enumerated (bounded by the index/value space limit).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class LebRecord:
    offset: int
    raw: bytes
    signed: bool
    bit_width: int
    value: Optional[int]
    status: str  # "ok" | "noncanonical" | "overflow" | "noncanonical+overflow" | "truncated"
    truncated: bool = False
    noncanonical: bool = False
    overflow: bool = False
    candidates: List[int] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "end": self.offset + len(self.raw),
            "raw_hex": self.raw.hex(),
            "signed": self.signed,
            "bit_width": self.bit_width,
            "value": self.value,
            "status": self.status,
            "truncated": self.truncated,
            "noncanonical": self.noncanonical,
            "overflow": self.overflow,
            "candidates": list(self.candidates),
            "note": self.note,
            "unit": "byte/uint",
        }


def _u7(payloads: List[int]) -> int:
    value = 0
    for i, p in enumerate(payloads):
        value |= p << (7 * i)
    return value


def decode_u(buf: bytes, offset: int, bit_width: int = 32) -> LebRecord:
    """Decode an unsigned LEB128 starting at ``offset``."""
    start = offset
    payloads: List[int] = []
    i = offset
    truncated = False
    while True:
        if i >= len(buf):
            truncated = True
            break
        b = buf[i]
        i += 1
        payloads.append(b & 0x7F)
        if not (b & 0x80):
            break
        if len(payloads) >= 8:
            # 8 bytes is the maximum for a 64-bit LEB128.
            pass
    raw = buf[start:i]
    n = len(payloads)
    max_bytes = (bit_width + 6) // 7
    if truncated:
        return LebRecord(
            start, raw, False, bit_width, None, "truncated",
            truncated=True,
            candidates=_truncated_unsigned_candidates(payloads, bit_width),
            note="continuation bit set but stream ended",
        )
    value = _u7(payloads)
    noncanonical = n > 1 and payloads[-1] == 0x00
    overflow = n > max_bytes or value >= (1 << bit_width)
    if n == max_bytes and not overflow:
        # Top byte may not exceed the width's remaining bits.
        used = bit_width - 7 * (n - 1)
        if payloads[-1] >> used:
            overflow = True
    status = "ok"
    if noncanonical and overflow:
        status = "noncanonical+overflow"
    elif noncanonical:
        status = "noncanonical"
    elif overflow:
        status = "overflow"
    return LebRecord(start, raw, False, bit_width, value, status,
                     noncanonical=noncanonical, overflow=overflow,
                     candidates=[value])


def _truncated_unsigned_candidates(payloads: List[int], bit_width: int) -> List[int]:
    """Enumerate the finite legal completions within the value space."""
    base = _u7(payloads)
    shift = 7 * len(payloads)
    limit = min(1 << bit_width, 1 << 20)
    candidates: List[int] = []
    for tail in range(0, 1 << 28):
        v = base | (tail << shift)
        if v >= limit:
            break
        candidates.append(v)
        if len(candidates) >= 256:
            break
    return candidates


def decode_s(buf: bytes, offset: int, bit_width: int = 32) -> LebRecord:
    """Decode a signed LEB128 (used for signed immediates / s33 limits)."""
    start = offset
    payloads: List[int] = []
    i = offset
    truncated = False
    while True:
        if i >= len(buf):
            truncated = True
            break
        b = buf[i]
        i += 1
        payloads.append(b & 0x7F)
        if not (b & 0x80):
            break
    raw = buf[start:i]
    n = len(payloads)
    max_bytes = (bit_width + 6) // 7
    if truncated:
        return LebRecord(start, raw, True, bit_width, None, "truncated",
                         truncated=True, candidates=[],
                         note="signed LEB128 truncated")
    value = _u7(payloads)
    if payloads[-1] & 0x40:
        value |= -(1 << (7 * n))
    sign_set = bool(payloads[-1] & 0x40)
    noncanonical = False
    if n > 1:
        if sign_set and payloads[-1] == 0x7F:
            noncanonical = True
        if not sign_set and payloads[-1] == 0x00:
            noncanonical = True
    overflow = False
    if n > max_bytes:
        overflow = True
    elif n == max_bytes:
        used = bit_width - 7 * (n - 1)
        top = payloads[-1]
        valid_sign_bits = {0, 0x7F}
        if top >= (1 << used) and not (top == 0x7F and sign_set and used < 7):
            # Check the value fits after sign extension.
            if value < -(1 << (bit_width - 1)) or value >= (1 << (bit_width - 1)):
                overflow = True
    status = "ok"
    if noncanonical and overflow:
        status = "noncanonical+overflow"
    elif noncanonical:
        status = "noncanonical"
    elif overflow:
        status = "overflow"
    return LebRecord(start, raw, True, bit_width, value, status,
                     noncanonical=noncanonical, overflow=overflow,
                     candidates=[value])


def encode_u(value: int) -> bytes:
    """Canonical unsigned LEB128."""
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def encode_s(value: int, bit_width: int = 32) -> bytes:
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


def encode_u_padded(value: int, pad_bytes: int = 1) -> bytes:
    """Deliberately non-canonical unsigned LEB128 (extra 0x80/0x00 bytes)."""
    canonical = encode_u(value)
    padding = b"\x80" * pad_bytes
    return canonical[:-1] + padding + bytes([canonical[-1]])


def decode_index(buf: bytes, offset: int, space_limit: int) -> LebRecord:
    """Decode an index LEB within a specific index space; bounds candidates."""
    rec = decode_u(buf, offset, bit_width=32)
    if rec.truncated:
        rec.candidates = [c for c in rec.candidates if c < space_limit]
    elif rec.value is not None and rec.value >= space_limit:
        rec.overflow = True
        rec.status = "overflow" if rec.status == "ok" else rec.status + "+overflow"
        rec.note = f"index {rec.value} >= space size {space_limit}"
    return rec
