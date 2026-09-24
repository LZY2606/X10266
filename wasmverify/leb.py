from __future__ import annotations

from dataclasses import dataclass


class LEBError(Exception):
    def __init__(self, code: str, start: int, end: int, message: str, value=None):
        super().__init__(message)
        self.code = code
        self.start = start
        self.end = end
        self.message = message
        self.value = value


@dataclass(frozen=True)
class LEBValue:
    value: int
    start: int
    end: int
    bits: int
    signed: bool
    canonical: bool
    bytes: bytes

    def as_dict(self) -> dict:
        return {
            "value": self.value,
            "range": [self.start, self.end],
            "bits": self.bits,
            "signed": self.signed,
            "canonical": self.canonical,
            "encoding_hex": self.bytes.hex(),
        }


def read_uleb(data: bytes, pos: int, limit: int | None = None, bits: int = 32) -> LEBValue:
    start = pos
    limit = len(data) if limit is None else limit
    result = 0
    shift = 0
    max_bytes = (bits + 6) // 7
    raw = bytearray()

    for byte_index in range(max_bytes):
        if pos >= limit:
            raise LEBError("LEB_TRUNCATED", start, max(start + 1, pos), "unsigned LEB128 ended before its terminator")
        byte = data[pos]
        raw.append(byte)
        pos += 1
        payload = byte & 0x7F
        result |= payload << shift
        shift += 7
        if not (byte & 0x80):
            canonical = True
            if byte_index > 0 and result < (1 << (7 * byte_index)):
                canonical = False
            if result > (1 << bits) - 1:
                raise LEBError(
                    "NUMERIC_OUT_OF_RANGE",
                    start,
                    pos,
                    f"unsigned LEB128 value {result} does not fit in u{bits}",
                    result,
                )
            return LEBValue(result, start, pos, bits, False, canonical, bytes(raw))
        if byte_index == max_bytes - 1:
            raise LEBError(
                "NUMERIC_OUT_OF_RANGE",
                start,
                pos,
                f"unsigned LEB128 continues past the u{bits} limit",
                result,
            )
    raise LEBError("LEB_TRUNCATED", start, pos, "unsigned LEB128 ended before its terminator")


def read_sleb(data: bytes, pos: int, limit: int | None = None, bits: int = 64) -> LEBValue:
    start = pos
    limit = len(data) if limit is None else limit
    result = 0
    shift = 0
    max_bytes = (bits + 6) // 7
    raw = bytearray()

    for byte_index in range(max_bytes):
        if pos >= limit:
            raise LEBError("LEB_TRUNCATED", start, max(start + 1, pos), "signed LEB128 ended before its terminator")
        byte = data[pos]
        raw.append(byte)
        pos += 1
        payload = byte & 0x7F
        result |= payload << shift
        shift += 7
        if not (byte & 0x80):
            if shift < bits and payload & 0x40:
                result |= -(1 << shift)
            if result < -(1 << (bits - 1)) or result > (1 << (bits - 1)) - 1:
                raise LEBError(
                    "NUMERIC_OUT_OF_RANGE",
                    start,
                    pos,
                    f"signed LEB128 value {result} does not fit in s{bits}",
                    result,
                )
            canonical = True
            if byte_index > 0:
                prior_bits = 7 * byte_index
                if -(1 << (prior_bits - 1)) <= result <= (1 << (prior_bits - 1)) - 1:
                    canonical = False
            return LEBValue(result, start, pos, bits, True, canonical, bytes(raw))
        if byte_index == max_bytes - 1:
            raise LEBError(
                "NUMERIC_OUT_OF_RANGE",
                start,
                pos,
                f"signed LEB128 continues past the s{bits} limit",
                result,
            )
    raise LEBError("LEB_TRUNCATED", start, pos, "signed LEB128 ended before its terminator")


def uleb_bytes(value: int) -> bytes:
    if value < 0:
        raise ValueError("unsigned LEB requires a non-negative value")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def sleb_bytes(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        done = (value == 0 and not (byte & 0x40)) or (value == -1 and (byte & 0x40))
        if done:
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)
