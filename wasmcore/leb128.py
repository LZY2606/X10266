"""LEB128 decoding that preserves the raw encoding and separates
non-canonical encodings from numeric overflow.

Error classes (kept strictly separate, per domain rule):
  * ``non_canonical`` -- value decodes fine and fits the target width,
    but the encoding is not the minimal one (e.g. 0x85 0x00 for 5).
  * ``overflow`` -- the encoded value does not fit the target width
    (e.g. a u32 whose 5th byte carries payload bits above bit 31).
  * ``truncated`` -- the byte stream ends in the middle of a sequence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

ERR_NON_CANONICAL = "non_canonical"
ERR_OVERFLOW = "overflow"
ERR_TRUNCATED = "truncated"

UNIT_BYTE = "byte"
BASIS_MODULE_OFFSET = "module_file_offset"


@dataclass
class LebValue:
    value: Optional[int]
    raw: bytes
    start: int
    signed: bool
    bits: int
    error: Optional[str] = None
    diagnostic: Optional[str] = None

    @property
    def end(self) -> int:
        return self.start + len(self.raw)

    @property
    def canonical(self) -> bool:
        return self.error is None

    def quantity(self, unit: str = UNIT_BYTE, basis: str = BASIS_MODULE_OFFSET) -> dict:
        """Domain quantity: raw representation is always preserved; the
        normalized value is only attached when conversion succeeded.
        Unconvertible values stay at their original position and carry a
        diagnostic instead of being silently coerced."""
        qty = {
            "unit": unit,
            "basis": basis,
            "raw_hex": self.raw.hex(),
            "range": {"start": self.start, "end": self.end},
        }
        if self.error is None:
            qty["value"] = self.value
        else:
            qty["value"] = None
            qty["error"] = self.error
            qty["diagnostic"] = self.diagnostic
        return qty


def _min_u_bytes(value: int) -> int:
    n = 1
    while value >= (1 << (7 * n)):
        n += 1
    return n


def _min_s_bytes(value: int) -> int:
    n = 1
    while not (-(1 << (7 * n - 1)) <= value < (1 << (7 * n - 1))):
        n += 1
    return n


def decode_unsigned(data: bytes, pos: int, bits: int = 32) -> LebValue:
    max_bytes = (bits + 6) // 7
    result = 0
    shift = 0
    raw = bytearray()
    i = pos
    while True:
        if i >= len(data):
            return LebValue(None, bytes(raw), pos, False, bits, ERR_TRUNCATED,
                            f"LEB128 sequence truncated at offset {i}")
        b = data[i]
        raw.append(b)
        i += 1
        if len(raw) == max_bytes:
            payload_bits = bits - 7 * (max_bytes - 1)
            mask = (1 << payload_bits) - 1
            if b & 0x80:
                return LebValue(None, bytes(raw), pos, False, bits, ERR_OVERFLOW,
                                f"u{bits} LEB128 continues past {max_bytes} bytes")
            if (b & 0x7F) & ~mask:
                return LebValue(None, bytes(raw), pos, False, bits, ERR_OVERFLOW,
                                f"u{bits} value does not fit in {bits} bits")
            result |= (b & 0x7F) << shift
            break
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    if len(raw) > _min_u_bytes(result):
        return LebValue(result, bytes(raw), pos, False, bits, ERR_NON_CANONICAL,
                        f"value {result} encoded in {len(raw)} bytes; "
                        f"minimal encoding is {_min_u_bytes(result)}")
    return LebValue(result, bytes(raw), pos, False, bits)


def decode_signed(data: bytes, pos: int, bits: int = 32) -> LebValue:
    max_bytes = (bits + 6) // 7
    result = 0
    shift = 0
    raw = bytearray()
    i = pos
    natural = False
    last_b = 0
    while True:
        if i >= len(data):
            return LebValue(None, bytes(raw), pos, True, bits, ERR_TRUNCATED,
                            f"LEB128 sequence truncated at offset {i}")
        b = data[i]
        last_b = b
        raw.append(b)
        i += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if len(raw) == max_bytes:
            if b & 0x80:
                return LebValue(None, bytes(raw), pos, True, bits, ERR_OVERFLOW,
                                f"s{bits} LEB128 continues past {max_bytes} bytes")
            payload_bits = bits - 7 * (max_bytes - 1)
            payload = b & 0x7F
            sign = (payload >> (payload_bits - 1)) & 1
            extension = payload >> payload_bits
            full = 0x7F >> payload_bits
            if (sign == 0 and extension != 0) or (sign == 1 and extension != full):
                return LebValue(None, bytes(raw), pos, True, bits, ERR_OVERFLOW,
                                f"s{bits} value does not fit in {bits} bits")
            break
        if not (b & 0x80):
            natural = True
            break
    if natural:
        if (last_b & 0x40) and shift < bits:
            result -= (1 << shift)
    elif result >= (1 << (bits - 1)):
        result -= (1 << bits)
    if len(raw) > _min_s_bytes(result):
        return LebValue(result, bytes(raw), pos, True, bits, ERR_NON_CANONICAL,
                        f"value {result} encoded in {len(raw)} bytes; "
                        f"minimal encoding is {_min_s_bytes(result)}")
    return LebValue(result, bytes(raw), pos, True, bits)
