"""LEB128 decode with *separate* non-canonical vs out-of-range diagnostics.

Domain rule (kept distinct on purpose):
  * NONCANONICAL -> the integer is within bounds but encoded over-long or with
    forbidden continuation bytes; a value is still recovered.
  * OVERFLOW     -> the encoded integer exceeds the target bit width.
  * TRUNCATED    -> the input ends before a terminating byte.

Every decode records the exact raw byte range so the UI highlights the
smallest failing span and the case pack can prove the two errors never merge.
"""

from __future__ import annotations

from dataclasses import dataclass, field

TRUNCATED = "leb.truncated"
NONCANONICAL = "leb.noncanonical"
OVERFLOW = "leb.overflow"


@dataclass
class LebResult:
    kind: str
    start: int
    end: int
    raw: bytes
    value: int | None
    codes: list[str] = field(default_factory=list)
    detail: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.codes


def _decode(buf: bytes, start: int, kind: str) -> LebResult:
    signed = kind.startswith("s")
    bits = int(kind[1:])
    max_bytes = (bits + 6) // 7          # ceil(bits/7): 5 for 32, 10 for 64
    pos = start
    codes: list[str] = []
    detail: dict = {}
    groups: list[int] = []
    continuation = True
    overlong = False

    # 1. pull the LEB run off the wire
    while continuation:
        if pos >= len(buf):
            codes.append(TRUNCATED)
            detail["expected_terminator"] = True
            continuation = False
            break
        b = buf[pos]
        pos += 1
        groups.append(b & 0x7F)
        continuation = bool(b & 0x80)
        if len(groups) == max_bytes and continuation:
            overlong = True
            if pos < len(buf):
                extra = buf[pos]
                pos += 1
                groups.append(extra & 0x7F)
                continuation = False
                if extra & 0x80:
                    detail["unbounded_continuation"] = True
            else:
                codes.append(TRUNCATED)
                continuation = False
            break

    # 2. range check (value vs bit width), independent of length canonicity
    overflow = False
    valid_bits = bits - 7 * (max_bytes - 1)
    final_mask = (1 << valid_bits) - 1
    value = 0
    for i, group in enumerate(groups[:max_bytes]):
        payload = group
        if i == max_bytes - 1:
            if group & ~final_mask:
                overflow = True
                detail["final_group"] = group
                detail["valid_bits"] = valid_bits
            payload = group & final_mask
        value |= payload << (7 * i)

    if signed and not overflow:
        sign_bit = 1 << (bits - 1)
        if value & sign_bit:
            value -= 1 << bits

    if overlong:
        codes.append(NONCANONICAL)
        detail["length_exceeds"] = max_bytes
        if len(groups) > max_bytes and groups[max_bytes] != 0:
            overflow = True
            detail["overflow_group"] = groups[max_bytes]
    if overflow:
        codes.append(OVERFLOW)

    # 3. canonical shortest encoding (distinct from overflow)
    if not overflow and not overlong and TRUNCATED not in codes:
        canonical = enc_s(value, bits) if signed else enc_u(value, bits)
        if len(canonical) < len(groups):
            codes.append(NONCANONICAL)
            detail["canonical_length"] = len(canonical)
            detail["actual_length"] = len(groups)

    recovered = None if (overflow or TRUNCATED in codes) else value
    raw = buf[start:pos]
    return LebResult(kind, start, pos, raw, recovered, codes, detail)


def decode_u32(buf: bytes, start: int = 0) -> LebResult:
    return _decode(buf, start, "u32")


def decode_u64(buf: bytes, start: int = 0) -> LebResult:
    return _decode(buf, start, "u64")


def decode_s32(buf: bytes, start: int = 0) -> LebResult:
    return _decode(buf, start, "s32")


def decode_s64(buf: bytes, start: int = 0) -> LebResult:
    return _decode(buf, start, "s64")


DECODERS = {
    "u32": decode_u32,
    "u64": decode_u64,
    "s32": decode_s32,
    "s64": decode_s64,
}


def enc_u(n: int, bits: int = 32) -> bytes:
    """Canonical unsigned LEB128 encoder (case-pack assembler)."""
    assert 0 <= n < (1 << bits)
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def enc_s(n: int, bits: int = 32) -> bytes:
    """Canonical signed LEB128 encoder."""
    out = bytearray()
    more = True
    while more:
        b = n & 0x7F
        n >>= 7
        sign = b & 0x40
        if (n == 0 and not sign) or (n == -1 and sign):
            more = False
            out.append(b)
        else:
            out.append(b | 0x80)
    return bytes(out)
