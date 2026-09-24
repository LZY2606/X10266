from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class LebResult:
    path: str
    start: int
    end: int
    raw: bytes
    value: Optional[int]
    canonical: bool
    error_code: Optional[str]

    def as_dict(self) -> dict:
        return {
            "stable_id": self.path,
            "byte_offset": self.start,
            "end_offset": self.end,
            "raw_hex": self.raw.hex(),
            "value": self.value,
            "canonical": self.canonical,
            "error_code": self.error_code,
            "coordinate_basis": "byte-offset-half-open",
            "unit": "bytes",
        }


def read_u32(data: bytes, start: int, limit: int, path: str) -> LebResult:
    value = 0
    shift = 0
    count = 0
    pos = start
    canonical = True
    error_code = None

    while True:
        if pos >= limit:
            return LebResult(path, start, limit, data[start:limit], None, False, "TRUNCATED_LEB128")
        byte = data[pos]
        pos += 1
        count += 1
        payload = byte & 0x7F

        if count == 5:
            if payload & 0x70:
                return LebResult(path, start, pos, data[start:pos], None, False, "NUMERIC_OUT_OF_RANGE")
            if payload == 0:
                canonical = False
                error_code = "NONCANONICAL_LEB128"
            value |= payload << shift
            if byte & 0x80:
                return LebResult(path, start, pos, data[start:pos], None, False, "NUMERIC_OUT_OF_RANGE")
            break

        value |= payload << shift
        if not (byte & 0x80):
            if count > 1 and payload == 0:
                canonical = False
                error_code = "NONCANONICAL_LEB128"
            break
        if payload == 0:
            # A zero continuation chunk may still be necessary in the first
            # four chunks of a 5-byte u32, so padding is judged at the end.
            pass
        shift += 7

    return LebResult(path, start, pos, data[start:pos], value, canonical, error_code)

