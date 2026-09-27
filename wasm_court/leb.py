from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Leb128:
    coordinate: str
    offset: int
    end: int
    bits: int
    signed: bool
    raw_hex: str
    value: int | None
    canonical: bool
    status: str
    error_code: str | None = None
    message: str | None = None

    def as_dict(self) -> dict:
        return {
            "id": self.coordinate,
            "stable_coordinate": self.coordinate.split(":", 2)[-1],
            "kind": "leb128",
            "byte_range": byte_range(self.offset, self.end, "LEB128 encoded integer"),
            "bits": self.bits,
            "signed": self.signed,
            "raw_hex": self.raw_hex,
            "value": self.value,
            "canonical": self.canonical,
            "status": self.status,
            "error_code": self.error_code,
            "message": self.message,
            "unit": "byte/unsigned-or-signed-integer",
            "direct_sources": [
                source(
                    f"byte-range:{self.offset}:{self.end}",
                    self.raw_hex,
                    f"bytes:{self.offset}:{self.end}",
                )
            ],
        }


def source(coordinate: str, raw_hex: str, source_id: str) -> dict:
    import hashlib

    raw = bytes.fromhex(raw_hex)
    return {
        "id": source_id,
        "coordinate": coordinate,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "raw_hex": raw_hex,
        "kind": "byte-range",
    }


def byte_range(offset: int, end: int, meaning: str) -> dict:
    return {
        "offset": offset,
        "length": max(0, end - offset),
        "end": end,
        "unit": "byte",
        "coordinate_basis": "zero-based WebAssembly module byte offset",
        "meaning": meaning,
    }


def read_leb(
    buf: bytes | bytearray | memoryview,
    offset: int,
    *,
    bits: int = 32,
    signed: bool = False,
    coordinate: str,
) -> tuple[Leb128, int]:
    start = offset
    max_bytes = (bits + 6) // 7
    payloads: list[int] = []
    value = 0
    status = "ok"
    error_code = None
    message = None

    while len(payloads) < max_bytes:
        if offset >= len(buf):
            raw = bytes(buf[start:offset])
            return (
                Leb128(
                    coordinate,
                    start,
                    offset,
                    bits,
                    signed,
                    raw.hex(),
                    None,
                    False,
                    "error",
                    "leb_truncated",
                    "LEB128 continuation bit was set beyond module end",
                ),
                offset,
            )
        byte = buf[offset]
        offset += 1
        payload = byte & 0x7F
        shift = 7 * len(payloads)
        payloads.append(payload)
        value |= payload << shift

        if len(payloads) == max_bytes:
            available = bits - 7 * (max_bytes - 1)
            if byte & 0x80:
                status, error_code = "error", "leb_out_of_range"
                message = f"LEB128 continuation continues past {bits} bits"
            elif signed:
                sign_bit = 1 << (available - 1)
                sign = (payload >> (available - 1)) & 1
                expected_high = (1 << (7 - available)) - 1 if sign else 0
                if payload >> available != expected_high:
                    status, error_code = "error", "leb_out_of_range"
                    message = f"signed LEB{bits} contains bits outside int{bits}"
            elif payload >> available:
                status, error_code = "error", "leb_out_of_range"
                message = f"unsigned LEB{bits} contains bits above {bits}"
            break
        if not byte & 0x80:
            break

    raw = bytes(buf[start:offset])
    if error_code is None:
        if signed:
            value &= (1 << bits) - 1
            if value >= 1 << (bits - 1):
                value -= 1 << bits
            if len(payloads) > 1:
                previous_width = 7 * (len(payloads) - 1)
                minimum = -(1 << (previous_width - 1))
                maximum = 1 << (previous_width - 1)
                if minimum <= value < maximum:
                    status, error_code = "error", "leb_noncanonical"
                    message = "signed LEB128 has unnecessary sign-extension byte"
        elif len(payloads) > 1:
            previous_capacity = 1 << (7 * (len(payloads) - 1))
            if value < previous_capacity:
                status, error_code = "error", "leb_noncanonical"
                message = "unsigned LEB128 has an unnecessary continuation byte"

    canonical = error_code is None
    if error_code == "leb_out_of_range":
        decoded = None
    else:
        decoded = value
    return (
        Leb128(
            coordinate,
            start,
            offset,
            bits,
            signed,
            raw.hex(),
            decoded,
            canonical,
            status,
            error_code,
            message,
        ),
        offset,
    )
