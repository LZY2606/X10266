"""LEB128 decoding with explicit distinction between encoding and value faults.

The distinction required by the case package is enforced here, in one place:

* ``noncanonical`` - the numeric value fits, but the byte sequence is longer
  than necessary (redundant bytes / redundant sign bits).
* ``overflow``     - the decoded value does not fit the declared bit width.
* ``truncated``    - the continuation bit promises another byte that is absent.

Every result keeps the exact ``source`` byte range and the canonical
re-encoding, so the UI can display both representations with stable identity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

LebStatus = Literal["ok", "noncanonical", "overflow", "truncated"]


@dataclass(frozen=True)
class LebValue:
    value: int | None
    status: LebStatus
    signed: bool
    bits: int
    start: int
    end: int
    raw: bytes
    canonical: bytes
    reason: str | None = None

    def as_dict(self) -> dict:
        return {
            "value": self.value,
            "status": self.status,
            "signed": self.signed,
            "bits": self.bits,
            "start": self.start,
            "end": self.end,
            "raw_hex": self.raw.hex(),
            "canonical_hex": self.canonical.hex(),
            "reason": self.reason,
        }


def encode_u(value: int, bits: int = 32) -> bytes:
    if value < 0 or value >= (1 << bits):
        raise ValueError(f"unsigned value {value} out of range for u{bits}")
    out = bytearray()
    more = True
    while more:
        byte = value & 0x7F
        value >>= 7
        more = value != 0
        out.append(byte | (0x80 if more else 0))
    return bytes(out)


def encode_s(value: int, bits: int = 32) -> bytes:
    out = bytearray()
    more = True
    while more:
        byte = value & 0x7F
        value >>= 7
        sign_bit = byte & 0x40
        if (value == 0 and sign_bit == 0) or (value == -1 and sign_bit != 0):
            more = False
        else:
            byte |= 0x80
        out.append(byte)
    return bytes(out)


def _read_group(data: bytes, start: int, max_bytes: int) -> tuple[list[int], bool, bool]:
    """Return (payload bytes, terminated, truncated)."""
    payloads: list[int] = []
    pos = start
    while True:
        if pos >= len(data):
            return payloads, False, True
        byte = data[pos]
        payloads.append(byte & 0x7F)
        pos += 1
        if not (byte & 0x80):
            return payloads, True, False
        if len(payloads) >= max_bytes:
            return payloads, False, False


def decode_u(data: bytes, start: int = 0, bits: int = 32) -> LebValue:
    max_bytes = (bits + 6) // 7
    payloads, terminated, truncated = _read_group(data, start, max_bytes)
    end = start + len(payloads)
    raw = data[start:end]

    if truncated:
        return LebValue(None, "truncated", False, bits, start, end, raw, b"",
                        "continuation bit set but no following byte")

    value = 0
    for i, payload in enumerate(payloads):
        value |= payload << (7 * i)

    if not terminated:
        # Consumed max_bytes and the last still continues: per WebAssembly
        # conventions this integer is too long, always an overflow-class fault
        # (the value cannot be represented in the target width).
        return LebValue(value & ((1 << bits) - 1), "overflow", False, bits,
                        start, end, raw, b"",
                        f"u{bits} LEB128 exceeds {max_bytes} bytes")

    canonical = encode_u(value, bits) if 0 <= value < (1 << bits) else b""
    if value >= (1 << bits):
        return LebValue(value, "overflow", False, bits, start, end, raw, b"",
                        f"decoded value {value} exceeds u{bits} maximum {(1 << bits) - 1}")
    if len(raw) > len(canonical):
        return LebValue(value, "noncanonical", False, bits, start, end, raw, canonical,
                        f"u{bits} value {value} needs {len(canonical)} byte(s), "
                        f"encoded with {len(raw)}")
    return LebValue(value, "ok", False, bits, start, end, raw, canonical)


def decode_s(data: bytes, start: int = 0, bits: int = 32) -> LebValue:
    max_bytes = (bits + 6) // 7
    payloads, terminated, truncated = _read_group(data, start, max_bytes)
    end = start + len(payloads)
    raw = data[start:end]

    if truncated:
        return LebValue(None, "truncated", True, bits, start, end, raw, b"",
                        "continuation bit set but no following byte")

    result = 0
    shift = 0
    for payload in payloads:
        result |= payload << shift
        shift += 7

    if not terminated:
        sign = bool(payloads[-1] & 0x40)
        if sign:
            result -= 1 << shift
        return LebValue(None, "overflow", True, bits, start, end, raw, b"",
                        f"s{bits} LEB128 exceeds {max_bytes} bytes")

    # Sign extend from the final payload.
    if payloads[-1] & 0x40:
        result |= -(1 << shift)

    minimum = -(1 << (bits - 1))
    maximum = (1 << (bits - 1)) - 1
    if result < minimum or result > maximum:
        return LebValue(result, "overflow", True, bits, start, end, raw, b"",
                        f"decoded value {result} outside s{bits} range "
                        f"[{minimum}, {maximum}]")

    canonical = encode_s(result, bits)
    if len(raw) > len(canonical):
        return LebValue(result, "noncanonical", True, bits, start, end, raw, canonical,
                        f"s{bits} value {result} needs {len(canonical)} byte(s), "
                        f"encoded with {len(raw)} (redundant sign bits)")
    return LebValue(result, "ok", True, bits, start, end, raw, canonical)


def is_fault(status: LebStatus) -> bool:
    return status != "ok"
