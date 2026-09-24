"""Shared shapes: byte ranges, findings and candidates."""

from __future__ import annotations

SEVERITY = {
    "error": "error",
    "capability-missing": "error",
    "unknown-opcode": "error",
    "warning": "warning",
    "info": "info",
}


def byte_range(start: int, end: int) -> dict:
    """A half-open byte interval; every coordinate carries its unit."""
    return {"start": start, "end": end, "unit": "byte", "basis": "module[0]"}


def finding(code: str, message: str, range_: dict, severity: str = "error",
            **extra) -> dict:
    out = {
        "code": code,
        "message": message,
        "range": range_,
        "severity": SEVERITY.get(severity, severity),
    }
    out.update(extra)
    return out


def candidate(candidate_id: str, label: str, rationale: str,
              range_: dict | None = None, **extra) -> dict:
    out = {"id": candidate_id, "label": label, "rationale": rationale}
    if range_ is not None:
        out["range"] = range_
    out.update(extra)
    return out
