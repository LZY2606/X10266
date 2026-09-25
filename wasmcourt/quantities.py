"""领域量：携带单位/坐标基准，保留导入层原始表示。"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class Quantity:
    value: Optional[Any]
    unit: str
    basis: str
    raw: Optional[str] = None
    diagnostic: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "unit": self.unit,
            "basis": self.basis,
            "raw": self.raw,
            "diagnostic": self.diagnostic,
        }


def byte_offset(value: Optional[int], raw: Optional[str] = None,
                diagnostic: Optional[str] = None) -> Quantity:
    return Quantity(value=value, unit="byte", basis="module-file-offset",
                    raw=raw, diagnostic=diagnostic)


def byte_extent(value: Optional[int], raw: Optional[str] = None,
                diagnostic: Optional[str] = None) -> Quantity:
    return Quantity(value=value, unit="byte", basis="section-content-extent",
                    raw=raw, diagnostic=diagnostic)


def index_value(value: int, space: str) -> Quantity:
    return Quantity(value=value, unit="index", basis=f"{space}-index-space")


def q_bytes_range(start: Optional[int], end: Optional[int]) -> dict:
    return {
        "start": byte_offset(start).to_dict() if start is not None else None,
        "end": byte_offset(end).to_dict() if end is not None else None,
    }
