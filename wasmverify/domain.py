from __future__ import annotations

from dataclasses import dataclass, field

KNOWN_SECTIONS = {
    1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start",
    9: "element", 10: "code", 11: "data", 12: "datacount",
}

VALTYPE_NAMES = {
    0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64",
    0x7B: "v128", 0x70: "funcref", 0x6F: "externref",
}

FEATURES = ("multi_value", "reference_types", "tail_call", "simd")


def qty(value: int | float, unit: str, coordinate: str | None = None) -> dict:
    out = {"value": value, "unit": unit}
    if coordinate is not None:
        out["coordinate_base"] = coordinate
    return out


@dataclass
class Finding:
    finding_id: str
    code: str
    severity: str
    title: str
    rationale: str
    byte_range: list[int]
    source_ids: list[str]
    accepted: bool | None = None
    candidates: list[dict] = field(default_factory=list)
    rejected_reasons: list[dict] = field(default_factory=list)
    unknown: bool = False

    def as_dict(self) -> dict:
        return {
            "stable_id": self.finding_id,
            "code": self.code,
            "severity": self.severity,
            "title": self.title,
            "rationale": self.rationale,
            "minimal_failure_byte_range": self.byte_range,
            "sources": self.source_ids,
            "accepted": self.accepted,
            "candidates": self.candidates,
            "rejected_reasons": self.rejected_reasons,
            "unknown": self.unknown,
        }


def module_id(project_id: str, sequence: int) -> str:
    return f"p:{project_id};module@e{sequence}"


def config_id(project_id: str, sequence: int) -> str:
    return f"p:{project_id};config@e{sequence}"


def decision_id(project_id: str, sequence: int) -> str:
    return f"p:{project_id};decision@e{sequence}"


def cell_id(module: str, kind: str, local: str) -> str:
    return f"{module};{kind}:{local}"


def result_id(algorithm: str, source_hash: str, kind: str) -> str:
    return f"result:{algorithm};{kind};sha256:{source_hash[:32]}"
