"""Quantity convention: every domain quantity carries a unit and a coordinate basis.

Raw representations are preserved at import; normalization happens only in the
derived layer. Values that cannot be converted stay in place with diagnostics.
"""
from __future__ import annotations


def qty(value, unit: str, basis: str) -> dict:
    return {"value": value, "unit": unit, "basis": basis}


def byte_offset(value: int) -> dict:
    return qty(value, "byte", "module-file-offset")


def byte_span(start: int, end: int) -> dict:
    return {"start": byte_offset(start), "end": byte_offset(end)}


def byte_len(value: int) -> dict:
    return qty(value, "byte", "module-file-offset")


def index_qty(value: int, space: str) -> dict:
    """Index-space coordinate, e.g. func index 3 in the module func index space."""
    return qty(value, "index", space)
