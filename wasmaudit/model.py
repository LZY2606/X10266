"""Domain data model.

Every entity the UI shows carries a stable identity and a byte coordinate
(offset..end in the *original* submission). Identities are content/coordinate
derived, so an export -> delete -> import round-trip restores them exactly.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict

# ---------- value types -----------------------------------------------------

I32 = "i32"
I64 = "i64"
F32 = "f32"
F64 = "f64"
V128 = "v128"
FUNCREF = "funcref"
EXTERNREF = "externref"


def type_name(code: int) -> str | None:
    return {
        0x7F: I32, 0x7E: I64, 0x7D: F32, 0x7C: F64,
        0x7B: V128, 0x70: FUNCREF, 0x6F: EXTERNREF,
    }.get(code)


def type_code(name: str) -> int:
    return {
        I32: 0x7F, I64: 0x7E, F32: 0x7D, F64: 0x7C,
        V128: 0x7B, FUNCREF: 0x70, EXTERNREF: 0x6F,
    }[name]


def stable_id(*parts: object) -> str:
    payload = "|".join(str(p) for p in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


# ---------- parsed entities -------------------------------------------------

@dataclass
class ByteSpan:
    start: int
    end: int

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass
class LebRef:
    id: str
    role: str               # e.g. "section.size", "type_count"
    kind: str
    start: int
    end: int
    raw_hex: str
    value: int | None
    codes: list[str]
    detail: dict


@dataclass
class Section:
    id: str
    ordinal: int             # physical position (0-based)
    section_id: int
    start: int               # first byte of section id
    end: int
    payload_start: int
    payload_end: int
    name: str
    custom_name: str | None = None
    custom_name_start: int | None = None
    custom_name_end: int | None = None
    custom_data_start: int | None = None
    custom_data_end: int | None = None
    codes: list[str] = field(default_factory=list)


@dataclass
class IndexEntry:
    id: str
    space: str               # type|func|table|memory|global|element|data
    index: int
    origin: str              # "import" | "defined"
    name: str | None
    section_ordinal: int
    detail: dict = field(default_factory=dict)
    byte_start: int | None = None
    byte_end: int | None = None


@dataclass
class ImportRecord:
    id: str
    index: int
    module: str
    field: str
    kind: str                # func|table|memory|global
    desc: dict               # typeidx / limits / valtype ...
    start: int
    end: int


@dataclass
class ExportRecord:
    id: str
    name: str
    kind: str
    index: int
    start: int
    end: int


@dataclass
class FuncType:
    id: str
    index: int
    params: list[str]
    results: list[str]
    start: int
    end: int


@dataclass
class ParseDiagnostic:
    code: str
    message: str
    start: int
    end: int
    severity: str = "error"
    detail: dict = field(default_factory=dict)


@dataclass
class ParsedModule:
    sha256: str
    size: int
    header_ok: bool
    version: int | None
    header_diag: list[ParseDiagnostic]
    sections: list[Section]
    lebs: list[LebRef]
    types: list[FuncType]
    imports: list[ImportRecord]
    exports: list[ExportRecord]
    indices: dict[str, list[IndexEntry]]
    functions: list[dict]      # {typeidx, body_start, body_end, local...}
    custom_sections: list[Section]
    diagnostics: list[ParseDiagnostic]

    def to_dict(self) -> dict:
        return asdict(self)


# ---------- validation ------------------------------------------------------

@dataclass
class Transition:
    seq: int
    offset: int
    end: int
    opcode: int
    mnemonic: str
    gate: str | None
    stack_before: list[str]
    stack_after: list[str]
    pop: list[str]
    push: list[str]
    polymorphic: bool
    note: str | None = None


@dataclass
class ControlEvent:
    seq: int
    offset: int
    opcode: int
    mnemonic: str
    action: str               # push|pop|branch|unreachable
    label: int
    kind: str | None
    polymorphic: bool
    stack_depth: int


@dataclass
class Candidate:
    id: str
    kind: str                 # interpretation/value candidate
    value: str
    evidence: dict
    accepted: bool
    reject_reason: str | None = None


@dataclass
class Finding:
    code: str
    severity: str             # error|capability|candidate|note
    message: str
    start: int
    end: int
    gate: str | None
    candidates: list[Candidate] = field(default_factory=list)
    detail: dict = field(default_factory=dict)


@dataclass
class FuncReport:
    func_index: int
    type_index: int
    start: int
    end: int
    status: str               # ok|error
    findings: list[Finding]
    transitions: list[Transition]
    control: list[ControlEvent]
    min_failure: tuple[int, int] | None
