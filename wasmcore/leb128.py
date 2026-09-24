"""LEB128 decoding that separates *non-canonical encoding* from *numeric overflow*.

Machine-readable error kinds:
  - noncanonical_leb128: value fits, but the encoding uses more bytes than
    necessary (overlong zero/sign padding). Recorded as a diagnostic.
  - integer_overflow: the encoded value does not fit the requested bit width.
  - truncated_leb128: input ended before the terminating byte.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LebError(Exception):
    kind: str
    offset: int
    byte_range: tuple[int, int]
    detail: str
    raw: bytes = b""

    def event(self) -> dict:
        return {
            "kind": self.kind,
            "offset": self.offset,
            "byte_range": list(self.byte_range),
            "detail": self.detail,
            "raw_hex": self.raw.hex(),
        }


@dataclass
class LebValue:
    value: int
    offset: int
    byte_range: tuple[int, int]
    raw: bytes
    signed: bool
    bits: int
    canonical: bool = True
    diagnostics: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "offset": self.offset,
            "byte_range": list(self.byte_range),
            "raw_hex": self.raw.hex(),
            "signed": self.signed,
            "bits": self.bits,
            "canonical": self.canonical,
            "diagnostics": self.diagnostics,
        }


def _min_bytes_unsigned(value: int) -> int:
    n = 1
    while value >= 0x80:
        value >>= 7
        n += 1
    return n


def _min_bytes_signed(value: int) -> int:
    n = 0
    while True:
        n += 1
        byte = value & 0x7F
        value >>= 7
        if (value == 0 and not (byte & 0x40)) or (value == -1 and (byte & 0x40)):
            return n


def _noncanonical_diag(kind_value: int, count: int, minimal: int, offset: int,
                       pos: int, raw: bytes, signed: bool) -> dict:
    pad = "sign" if signed else "zero"
    return {
        "kind": "noncanonical_leb128",
        "offset": offset,
        "byte_range": [offset, pos],
        "detail": f"value {kind_value} encoded in {count} bytes; minimal is "
                  f"{minimal} ({pad} padding)",
        "raw_hex": raw.hex(),
    }


def read_uleb(data: bytes, offset: int, bits: int) -> LebValue:
    """Read unsigned LEB128 constrained to `bits` bits."""
    max_bytes = (bits + 6) // 7
    result = 0
    shift = 0
    pos = offset
    count = 0
    while True:
        if pos >= len(data):
            raise LebError("truncated_leb128", offset, (offset, pos),
                           f"u{bits} LEB128 truncated at byte {pos}", data[offset:pos])
        byte = data[pos]
        pos += 1
        count += 1
        if count > max_bytes:
            raise LebError(
                "integer_overflow", offset, (offset, pos),
                f"u{bits} LEB128 uses {count} bytes, more than the {max_bytes} allowed",
                data[offset:pos])
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            break
    raw = data[offset:pos]
    if result >= (1 << bits):
        raise LebError(
            "integer_overflow", offset, (offset, pos),
            f"u{bits} LEB128 value {result} does not fit in {bits} bits", raw)
    diagnostics: list[dict] = []
    canonical = True
    minimal = _min_bytes_unsigned(result)
    if count > minimal:
        canonical = False
        diagnostics.append(_noncanonical_diag(result, count, minimal, offset, pos, raw, False))
    return LebValue(result, offset, (offset, pos), raw, False, bits, canonical, diagnostics)


def read_sleb(data: bytes, offset: int, bits: int) -> LebValue:
    """Read signed LEB128 constrained to `bits` bits."""
    max_bytes = (bits + 6) // 7
    result = 0
    shift = 0
    pos = offset
    count = 0
    byte = 0
    while True:
        if pos >= len(data):
            raise LebError("truncated_leb128", offset, (offset, pos),
                           f"i{bits} LEB128 truncated at byte {pos}", data[offset:pos])
        byte = data[pos]
        pos += 1
        count += 1
        if count > max_bytes:
            raise LebError(
                "integer_overflow", offset, (offset, pos),
                f"i{bits} LEB128 uses {count} bytes, more than the {max_bytes} allowed",
                data[offset:pos])
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            break
    if byte & 0x40:
        result -= 1 << shift
    raw = data[offset:pos]
    lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    if not (lo <= result <= hi):
        raise LebError(
            "integer_overflow", offset, (offset, pos),
            f"i{bits} LEB128 value {result} outside [{lo}, {hi}]", raw)
    diagnostics: list[dict] = []
    canonical = True
    minimal = _min_bytes_signed(result)
    if count > minimal:
        canonical = False
        diagnostics.append(_noncanonical_diag(result, count, minimal, offset, pos, raw, True))
    return LebValue(result, offset, (offset, pos), raw, True, bits, canonical, diagnostics)
