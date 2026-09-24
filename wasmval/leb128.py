"""LEB128 decoding with canonical-form and range diagnostics.

Three distinct defect classes are produced, never merged:
  - leb128_noncanonical : value decodes fine but encoding is not minimal (diagnostic)
  - leb128_too_long     : more bytes than the bit-width allows (error)
  - value_overflow      : payload bits exceed the target bit width (error)
  - leb128_truncated    : input ended before the terminating byte (error)
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LebIssue:
    code: str
    message: str
    byte_start: int
    byte_end: int  # exclusive

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "byte_start": self.byte_start,
            "byte_end": self.byte_end,
        }


@dataclass
class LebResult:
    value: int | None
    byte_start: int
    byte_end: int  # exclusive; == byte_start when truncated at offset 0
    byte_length: int
    canonical: bool
    minimal_length: int
    signed: bool
    max_bits: int
    errors: list[LebIssue] = field(default_factory=list)
    diagnostics: list[LebIssue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "byte_start": self.byte_start,
            "byte_end": self.byte_end,
            "byte_length": self.byte_length,
            "canonical": self.canonical,
            "minimal_length": self.minimal_length,
            "signed": self.signed,
            "max_bits": self.max_bits,
            "errors": [e.to_dict() for e in self.errors],
            "diagnostics": [d.to_dict() for d in self.diagnostics],
        }


def _minimal_unsigned_length(value: int) -> int:
    if value == 0:
        return 1
    length = 0
    while value:
        length += 1
        value >>= 7
    return length


def _minimal_signed_length(value: int) -> int:
    length = 0
    while True:
        byte = value & 0x7F
        value >>= 7
        length += 1
        done = (value == 0 and not (byte & 0x40)) or (value == -1 and (byte & 0x40))
        if done:
            return length


def decode_unsigned(data: bytes, offset: int, max_bits: int = 32) -> LebResult:
    max_bytes = (max_bits + 6) // 7
    result = 0
    shift = 0
    pos = offset
    errors: list[LebIssue] = []
    while True:
        if pos >= len(data):
            errors.append(LebIssue(
                "leb128_truncated",
                f"unsigned LEB128 at {offset} ended after {pos - offset} byte(s) without terminator",
                offset, pos,
            ))
            return LebResult(None, offset, pos, pos - offset, False, 0, False, max_bits, errors=errors)
        byte = data[pos]
        pos += 1
        count = pos - offset
        if count > max_bytes:
            errors.append(LebIssue(
                "leb128_too_long",
                f"unsigned LEB128 at {offset} exceeds {max_bytes} bytes for u{max_bits}",
                offset, pos,
            ))
            return LebResult(None, offset, pos, count, False, 0, False, max_bits, errors=errors)
        payload = byte & 0x7F
        if count == max_bytes:
            used_bits = max_bits - 7 * (max_bytes - 1)
            if payload >> used_bits:
                errors.append(LebIssue(
                    "value_overflow",
                    f"unsigned LEB128 at {offset} carries bits beyond u{max_bits}",
                    offset, pos,
                ))
        result |= payload << shift
        shift += 7
        if not (byte & 0x80):
            break
    length = pos - offset
    minimal = _minimal_unsigned_length(result)
    diagnostics: list[LebIssue] = []
    canonical = length == minimal
    if not canonical:
        diagnostics.append(LebIssue(
            "leb128_noncanonical",
            f"unsigned LEB128 at {offset} uses {length} bytes, minimal is {minimal}",
            offset, pos,
        ))
    return LebResult(result, offset, pos, length, canonical, minimal, False, max_bits,
                     errors=errors, diagnostics=diagnostics)


def decode_signed(data: bytes, offset: int, max_bits: int = 32) -> LebResult:
    max_bytes = (max_bits + 6) // 7
    result = 0
    shift = 0
    pos = offset
    errors: list[LebIssue] = []
    byte = 0
    while True:
        if pos >= len(data):
            errors.append(LebIssue(
                "leb128_truncated",
                f"signed LEB128 at {offset} ended after {pos - offset} byte(s) without terminator",
                offset, pos,
            ))
            return LebResult(None, offset, pos, pos - offset, False, 0, True, max_bits, errors=errors)
        byte = data[pos]
        pos += 1
        count = pos - offset
        if count > max_bytes:
            errors.append(LebIssue(
                "leb128_too_long",
                f"signed LEB128 at {offset} exceeds {max_bytes} bytes for i{max_bits}",
                offset, pos,
            ))
            return LebResult(None, offset, pos, count, False, 0, True, max_bits, errors=errors)
        payload = byte & 0x7F
        if count == max_bytes:
            used_bits = max_bits - 7 * (max_bytes - 1)
            sign_bit = (payload >> (used_bits - 1)) & 1
            high = payload >> used_bits
            expected = (1 << (7 - used_bits)) - 1 if sign_bit else 0
            if high != expected:
                errors.append(LebIssue(
                    "value_overflow",
                    f"signed LEB128 at {offset} carries bits beyond i{max_bits}",
                    offset, pos,
                ))
        result |= payload << shift
        shift += 7
        if not (byte & 0x80):
            break
    if shift < max_bits and (byte & 0x40):
        result |= -(1 << shift)
    length = pos - offset
    minimal = _minimal_signed_length(result)
    diagnostics: list[LebIssue] = []
    canonical = length == minimal
    if not canonical:
        diagnostics.append(LebIssue(
            "leb128_noncanonical",
            f"signed LEB128 at {offset} uses {length} bytes, minimal is {minimal}",
            offset, pos,
        ))
    return LebResult(result, offset, pos, length, canonical, minimal, True, max_bits,
                     errors=errors, diagnostics=diagnostics)
