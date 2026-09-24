"""Structured parse model. Every object carries its source byte range."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..core.typesys import FuncType


@dataclass
class Span:
    start: int
    end: int
    unit: str = "byte_offset"

    def to_dict(self) -> dict:
        return {"start": self.start, "end": self.end, "unit": self.unit}


@dataclass
class Section:
    section_id: int
    name: str
    span: Span              # full section incl. id + size + payload
    payload_span: Span
    declared_size: int
    payload: bytes
    custom_name: Optional[str] = None
    order: int = 0

    def to_dict(self) -> dict:
        d = {
            "section_id": self.section_id,
            "name": self.name,
            "span": self.span.to_dict(),
            "payload_span": self.payload_span.to_dict(),
            "declared_size": self.declared_size,
            "size_unit": "byte",
            "order": self.order,
        }
        if self.custom_name is not None:
            d["custom_name"] = self.custom_name
        return d


@dataclass
class IndexEntry:
    """An entry in one of the module index spaces, with provenance."""
    space: str          # type | func | table | memory | global | elem | data
    index: int
    kind: str           # import | defined | local ...
    origin: str         # import-section | code-section ...
    span: Span
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "space": self.space,
            "index": self.index,
            "kind": self.kind,
            "origin": self.origin,
            "span": self.span.to_dict(),
            "detail": self.detail,
        }


@dataclass
class ImportEntry:
    module: str
    field: str
    kind: str           # function | table | memory | global
    span: Span
    typeidx: Optional[int] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    def key(self) -> str:
        return f"{self.module}::{self.field}::{self.kind}"

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "field": self.field,
            "kind": self.kind,
            "typeidx": self.typeidx,
            "span": self.span.to_dict(),
            "raw": self.raw,
            "contract_key": self.module + "." + self.field,
        }


@dataclass
class FunctionBody:
    funcidx: int
    span: Span
    locals: List[str]
    code: bytes
    code_offset: int

    def to_dict(self) -> dict:
        return {
            "funcidx": self.funcidx,
            "span": self.span.to_dict(),
            "locals": list(self.locals),
            "code_span": {"start": self.code_offset,
                          "end": self.code_offset + len(self.code),
                          "unit": "byte_offset"},
        }


@dataclass
class Limit:
    min: int
    max: Optional[int]
    has_max: bool
    shared: bool = False
    unit: str = "page"

    def to_dict(self) -> dict:
        return {"min": self.min, "max": self.max, "has_max": self.has_max,
                "shared": self.shared, "unit": self.unit}


@dataclass
class ModuleMap:
    magic_ok: bool
    version: Optional[int]
    version_bytes: bytes
    header_span: Span
    sections: List[Section]
    types: List[FuncType]
    type_spans: List[Span]
    imports: List[ImportEntry]
    functions: List[int]               # typeidx per defined function
    function_spans: List[Span]
    bodies: List[FunctionBody]
    tables: List[Dict[str, Any]]
    memories: List[Limit]
    globals_: List[Dict[str, Any]]
    exports: List[Dict[str, Any]]
    index_table: List[IndexEntry]
    leb_records: List[Dict[str, Any]]
    custom_sections: List[Section]
    raw: bytes
    parse_findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "magic_ok": self.magic_ok,
            "version": self.version,
            "version_bytes": self.version_bytes.hex(),
            "header_span": self.header_span.to_dict(),
            "sections": [s.to_dict() for s in self.sections],
            "types": [{"params": t.params, "results": t.results,
                       "span": self.type_spans[i].to_dict(),
                       "type_key": t.key()}
                      for i, t in enumerate(self.types)],
            "imports": [i.to_dict() for i in self.imports],
            "functions": self.functions,
            "function_spans": [s.to_dict() for s in self.function_spans],
            "bodies": [b.to_dict() for b in self.bodies],
            "tables": self.tables,
            "memories": [m.to_dict() for m in self.memories],
            "globals": self.globals_,
            "exports": self.exports,
            "index_table": [e.to_dict() for e in self.index_table],
            "leb_records": list(self.leb_records),
            "custom_sections": [s.to_dict() for s in self.custom_sections],
            "parse_findings": self.parse_findings,
            "byte_length": len(self.raw),
            "byte_length_unit": "byte",
        }
