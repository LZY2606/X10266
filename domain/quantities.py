"""Domain quantities.

Every numeric domain value carries a unit or a coordinate basis so that a
reviewer can tell byte offsets from section ids or stack depths. The original
lexical representation is retained on parsing (``raw``); normalisation only
happens in the derived layer.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


BYTE = "byte"
INDEX = "index"
LIMIT = "limit"
UNIT = "unit"


@dataclass(frozen=True)
class Basis:
    """A coordinate system for a quantity."""

    unit: str
    origin: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"unit": self.unit, "origin": self.origin}


BYTE_OFFSET = Basis(BYTE, origin=0)
SECTION_ID = Basis("section-id", origin=0)
INDEX_SPACE = Basis(INDEX, origin=0)
STACK_SLOT = Basis("stack-slot", origin=0)
LIMIT_BASIS = Basis(LIMIT, origin=0)


@dataclass(frozen=True)
class Quantity:
    """A numeric value with a unit/coordinate basis and original spelling."""

    value: int | None
    unit: str = UNIT
    origin: int = 0
    raw: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "basis": {"unit": self.unit, "origin": self.origin},
            "raw": self.raw,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Quantity":
        basis = data.get("basis", {})
        return cls(
            value=data.get("value"),
            unit=basis.get("unit", UNIT),
            origin=basis.get("origin", 0),
            raw=data.get("raw"),
        )


@dataclass(frozen=True)
class ByteRange:
    """Half-open byte range ``[start, end)`` in the original binary."""

    start: int
    end: int

    @property
    def length(self) -> int:
        return self.end - self.start

    def contains(self, offset: int) -> bool:
        return self.start <= offset < self.end

    def to_dict(self) -> dict[str, Any]:
        return {"start": self.start, "end": self.end, "length": self.length}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ByteRange":
        return cls(start=int(data["start"]), end=int(data["end"]))

    def __str__(self) -> str:
        return f"bytes[{self.start}..{self.end})"


def q_bytes(value: int, raw: str | None = None) -> Quantity:
    return Quantity(value=value, unit=BYTE, origin=0, raw=raw)


def q_index(value: int, raw: str | None = None) -> Quantity:
    return Quantity(value=value, unit=INDEX, origin=0, raw=raw)
