"""Core domain model.

Every domain value carries a coordinate basis (byte span, index space, stack
slot) and keeps its raw representation. Derived values additionally carry an
algorithm version, parameter fingerprint and direct provenance.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

# ---------------------------------------------------------------------------
# Coordinate bases / provenance
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Span:
    """Half-open byte range ``[start, end)`` inside a specific source blob."""

    start: int
    end: int
    source_id: str = "v1"

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start:
            raise ValueError(f"invalid span {self}")

    @property
    def length(self) -> int:
        return self.end - self.start

    def intersects(self, other: "Span") -> bool:
        return self.source_id == other.source_id and self.start < other.end and other.start < self.end

    def to_dict(self) -> dict[str, Any]:
        return {"start": self.start, "end": self.end, "source_id": self.source_id}

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Span":
        return Span(start=int(d["start"]), end=int(d["end"]), source_id=d.get("source_id", "v1"))


def stable_hash(payload: Any) -> str:
    """Deterministic content hash used as a stable identity basis."""
    material = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def short_id(kind: str, payload: Any) -> str:
    return f"{kind}_{stable_hash(payload)[:16]}"


# ---------------------------------------------------------------------------
# Findings / candidates: rejected reasons, errors and unknowns are first class
# ---------------------------------------------------------------------------

Severity = Literal["error", "reject", "warning", "info", "accepted"]
Status = Literal["current", "stale", "superseded"]


@dataclass
class Candidate:
    """A legal alternative when a value cannot be uniquely decided."""

    value: str
    basis: str
    spans: list[Span] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "basis": self.basis,
            "spans": [s.to_dict() for s in self.spans],
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Candidate":
        return Candidate(
            value=d["value"],
            basis=d["basis"],
            spans=[Span.from_dict(s) for s in d.get("spans", [])],
        )


@dataclass
class Finding:
    """A single judgement produced by the validator.

    ``code`` values are stable machine-readable contracts; ``category`` keeps
    distinct families separate (non-canonical LEB128 vs numeric overflow,
    capability-missing vs unknown-byte, ...).
    """

    finding_id: str
    code: str
    category: str
    severity: Severity
    title: str
    detail: str
    spans: list[Span] = field(default_factory=list)
    index_space: str | None = None
    index: int | None = None
    candidates: list[Candidate] = field(default_factory=list)
    proposal: str | None = None
    expected: str | None = None
    actual: str | None = None
    accepted: bool | None = None  # human adjudication, None = undecided
    decision_event_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["spans"] = [s.to_dict() for s in self.spans]
        data["candidates"] = [c.to_dict() for c in self.candidates]
        return data

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Finding":
        d = dict(d)
        d["spans"] = [Span.from_dict(s) for s in d.get("spans", [])]
        d["candidates"] = [Candidate.from_dict(c) for c in d.get("candidates", [])]
        return Finding(**d)


@dataclass
class DerivedItem:
    """Anything shown in the review UI: section map row, index-table row,
    control-stack frame, type transition, minimal failing byte range, ..."""

    item_id: str
    kind: str  # section | index_entry | frame | transition | fail_range | leb | ...
    label: str
    value: dict[str, Any]
    spans: list[Span]
    depends_on: list[str] = field(default_factory=list)  # direct source item/event ids
    status: Status = "current"
    algorithm_version: str = ""
    param_fingerprint: str = ""
    candidates: list[Candidate] = field(default_factory=list)
    unknown: bool = False
    produced_by_run: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "kind": self.kind,
            "label": self.label,
            "value": self.value,
            "spans": [s.to_dict() for s in self.spans],
            "depends_on": list(self.depends_on),
            "status": self.status,
            "algorithm_version": self.algorithm_version,
            "param_fingerprint": self.param_fingerprint,
            "candidates": [c.to_dict() for c in self.candidates],
            "unknown": self.unknown,
            "produced_by_run": self.produced_by_run,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "DerivedItem":
        return DerivedItem(
            item_id=d["item_id"],
            kind=d["kind"],
            label=d["label"],
            value=d.get("value", {}),
            spans=[Span.from_dict(s) for s in d.get("spans", [])],
            depends_on=list(d.get("depends_on", [])),
            status=d.get("status", "current"),
            algorithm_version=d.get("algorithm_version", ""),
            param_fingerprint=d.get("param_fingerprint", ""),
            candidates=[Candidate.from_dict(c) for c in d.get("candidates", [])],
            unknown=d.get("unknown", False),
            produced_by_run=d.get("produced_by_run", ""),
        )


# ---------------------------------------------------------------------------
# Immutable events
# ---------------------------------------------------------------------------

@dataclass
class Event:
    event_id: str
    seq: int
    ts_ms: int
    kind: str  # source_submitted | params_revised | derived | decision | conflict | note
    payload: dict[str, Any]
    parent_event_id: str | None = None
    run_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Event":
        return Event(**d)
