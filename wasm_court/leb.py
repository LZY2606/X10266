from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class LEBResult:
    value: int | None
    start: int
    end: int
    raw: bytes
    status: str
    code: str
    canonical: bool

    def to_event(self) -> dict[str, Any]:
        return {
            "kind": "leb128",
            "value": self.value,
            "unit": "uleb128:unsigned32",
            "coordinate_base": f"byte[{self.start}..{self.end - 1}]",
            "start": self.start,
            "end": self.end,
            "raw_hex": self.raw.hex(),
            "status": self.status,
            "code": self.code,
            "canonical": self.canonical,
        }


def decode_uleb128(data: bytes, start: int, *, max_value: int = 0xFFFFFFFF) -> LEBResult:
    value = 0
    shift = 0
    pos = start
    groups: list[tuple[int, int]] = []
    canonical_groups = 0
    overflow = False

    while pos < len(data):
        byte = data[pos]
        payload = byte & 0x7F
        groups.append((byte, payload))
        pos += 1
        if shift < 32:
            usable = min(7, 32 - shift)
            piece = payload & ((1 << usable) - 1)
            value |= piece << shift
            if payload or not canonical_groups:
                canonical_groups = len(groups)
            if payload >> usable:
                overflow = True
        else:
            overflow = True
        shift += 7
        if byte < 0x80:
            if len(groups) > 1 and payload == 0:
                canonical_groups = max(1, canonical_groups)
            raw = data[start:pos]
            noncanonical = len(groups) > canonical_groups
            if overflow or value > max_value:
                return LEBResult(None, start, pos, raw, "rejected", "numeric_value_out_of_range", False)
            if noncanonical:
                return LEBResult(value, start, pos, raw, "rejected", "noncanonical_leb128", False)
            return LEBResult(value, start, pos, raw, "accepted", "canonical_uleb128", True)

    raw = data[start:]
    return LEBResult(None, start, len(data), raw, "unknown", "leb128_truncated", False)
