"""Structural domain model for a parsed WebAssembly module.

Everything keeps original byte coordinates and the raw representation.
Normalisation happens only in the derived validation layer.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .leb import LebU32

VALUE_TYPES = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64"}

SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "datacount",
}


@dataclass(frozen=True)
class FuncType:
    params: tuple[str, ...]
    results: tuple[str, ...]
    start: int
    end: int
    raw: bytes


@dataclass(frozen=True)
class ImportEntry:
    index: int
    module: str
    module_raw: bytes
    field: str
    field_raw: bytes
    kind: int
    type_index: int | None
    start: int
    end: int

    @property
    def signature_key(self) -> str:
        return f"{self.module}::{self.field}"


@dataclass(frozen=True)
class LocalGroup:
    count: int
    type_name: str
    start: int
    end: int


@dataclass(frozen=True)
class FunctionBody:
    func_index: int
    type_index: int | None
    size: LebU32
    start: int          # offset of the body-size LEB
    end: int            # offset one past body payload
    code_start: int
    locals: tuple[LocalGroup, ...]
    local_types: tuple[str, ...]
    raw: bytes


@dataclass(frozen=True)
class Section:
    seq: int                    # zero-based physical order
    sid: int
    name: str | None            # custom-section name, None for known sections
    name_raw: bytes
    id_offset: int
    size: LebU32
    start: int                  # first byte (section id)
    payload_start: int
    payload_end: int
    end: int
    raw: bytes

    @property
    def kind(self) -> str:
        return SECTION_NAMES.get(self.sid, f"unknown({self.sid})")


@dataclass(frozen=True)
class IndexEntry:
    space: str                  # func / type / import / code
    index: int
    origin: str                 # import | defined | type
    section_seq: int
    type_index: int | None
    detail: str
    start: int
    end: int


@dataclass(frozen=True)
class Finding:
    """A judgment datum: errors, notes and their rejected reasons/candidates."""

    rule_id: str
    severity: str               # error | note
    message: str
    path: str
    start: int
    end: int
    candidates: tuple[str, ...] = ()
    rejected: tuple[dict, ...] = ()
    evidence: dict = field(default_factory=dict)
    proposal: str | None = None
    decision: str = "pending"   # accept | reject | pending (applied later)

    def stable_key(self) -> str:
        return f"{self.rule_id}|{self.path}|{self.start}:{self.end}"


@dataclass
class ParsedModule:
    raw: bytes
    sections: list[Section] = field(default_factory=list)
    types: list[FuncType] = field(default_factory=list)
    imports: list[ImportEntry] = field(default_factory=list)
    defined_type_indices: list[int] = field(default_factory=list)
    bodies: list[FunctionBody] = field(default_factory=list)
    index_spaces: list[IndexEntry] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    header_ok: bool = False

    def func_type_count(self) -> int:
        return len(self.imports) + len(self.defined_type_indices)

    def type_of_func(self, func_index: int) -> int | None:
        n_imp = len(self.imports)
        if func_index < n_imp:
            return self.imports[func_index].type_index
        k = func_index - n_imp
        if 0 <= k < len(self.defined_type_indices):
            return self.defined_type_indices[k]
        return None
