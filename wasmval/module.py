"""WebAssembly binary module parser.

Parses the section structure, type/import/function/code sections, and keeps
every custom section byte-for-byte. All indices carry the byte range of the
LEB128 they were decoded from (index provenance). Parsing is lenient: order
and duplication defects are recorded as diagnostics, never thrown.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .leb128 import LebResult, decode_unsigned

SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "data_count",
}
# Known (non-custom) sections must appear at most once and in this order.
KNOWN_ORDER = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]

VALTYPES = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64"}
IMPORT_KINDS = {0x00: "func", 0x01: "table", 0x02: "memory", 0x03: "global"}


@dataclass
class Diagnostic:
    code: str
    message: str
    byte_start: int
    byte_end: int

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message,
                "byte_start": self.byte_start, "byte_end": self.byte_end}


@dataclass
class Section:
    identity: str
    order_index: int
    section_id: int
    name: str
    size: int | None
    header_start: int          # offset of the section id byte
    payload_start: int
    payload_end: int           # exclusive
    size_leb: LebResult
    raw: bytes                 # payload bytes, preserved verbatim

    def to_dict(self) -> dict:
        return {
            "identity": self.identity,
            "order_index": self.order_index,
            "section_id": self.section_id,
            "name": self.name,
            "size": self.size,
            "header_start": self.header_start,
            "payload_start": self.payload_start,
            "payload_end": self.payload_end,
            "size_leb": self.size_leb.to_dict(),
        }


@dataclass
class FuncType:
    index: int
    params: list[str]
    results: list[str]
    byte_start: int
    byte_end: int

    def to_dict(self) -> dict:
        return {"index": self.index, "params": self.params, "results": self.results,
                "byte_start": self.byte_start, "byte_end": self.byte_end}


@dataclass
class ImportEntry:
    index: int                 # index within the func/global import index space
    module: str
    name: str
    kind: str
    type_index: int | None     # for func imports
    type_index_leb: LebResult | None
    byte_start: int
    byte_end: int

    @property
    def qualified_name(self) -> str:
        return f"{self.module}.{self.name}"

    def to_dict(self) -> dict:
        return {"index": self.index, "module": self.module, "name": self.name,
                "kind": self.kind, "type_index": self.type_index,
                "type_index_leb": self.type_index_leb.to_dict() if self.type_index_leb else None,
                "byte_start": self.byte_start, "byte_end": self.byte_end}


@dataclass
class FunctionEntry:
    index: int                 # absolute index in the function index space
    type_index: int | None
    type_index_leb: LebResult

    def to_dict(self) -> dict:
        return {"index": self.index, "type_index": self.type_index,
                "type_index_leb": self.type_index_leb.to_dict()}


@dataclass
class CodeBody:
    func_index: int            # absolute function index space index
    locals: list[str]          # expanded local types (excluding params)
    expr_start: int            # absolute offset of the expression bytes
    expr_end: int              # exclusive
    expr: bytes
    byte_start: int
    byte_end: int

    def to_dict(self) -> dict:
        return {"func_index": self.func_index, "locals": self.locals,
                "expr_start": self.expr_start, "expr_end": self.expr_end,
                "byte_start": self.byte_start, "byte_end": self.byte_end}


@dataclass
class ParsedModule:
    data: bytes
    sections: list[Section] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    leb_issues: list[LebResult] = field(default_factory=list)
    types: list[FuncType] = field(default_factory=list)
    imports: list[ImportEntry] = field(default_factory=list)
    functions: list[FunctionEntry] = field(default_factory=list)
    bodies: list[CodeBody] = field(default_factory=list)
    header_ok: bool = True

    def custom_sections(self) -> list[Section]:
        return [s for s in self.sections if s.section_id == 0]

    def section_by_name(self, name: str) -> Section | None:
        for s in self.sections:
            if s.name == name:
                return s
        return None


class _Reader:
    def __init__(self, data: bytes, base: int = 0):
        self.data = data
        self.pos = 0
        self.base = base  # absolute offset of data[0] in the module

    def u8(self) -> int:
        b = self.data[self.pos]
        self.pos += 1
        return b

    def u32(self) -> LebResult:
        r = decode_unsigned(self.data, self.pos, 32)
        r.byte_start += self.base
        r.byte_end += self.base
        self.pos += r.byte_length
        return r

    def take(self, n: int) -> bytes:
        b = self.data[self.pos:self.pos + n]
        self.pos += n
        return b

    def done(self) -> bool:
        return self.pos >= len(self.data)


def _read_name(reader: _Reader) -> tuple[str, LebResult]:
    length = reader.u32()
    n = length.value or 0
    raw = reader.take(n)
    return raw.decode("utf-8", errors="replace"), length


def parse_module(data: bytes) -> ParsedModule:
    mod = ParsedModule(data=data)
    if len(data) < 8 or data[:4] != b"\x00asm":
        mod.header_ok = False
        mod.diagnostics.append(Diagnostic(
            "bad_magic", "module does not start with \\0asm magic", 0, min(4, len(data))))
        return mod
    if data[4:8] != b"\x01\x00\x00\x00":
        mod.diagnostics.append(Diagnostic(
            "bad_version", f"unsupported version bytes {data[4:8].hex()}", 4, 8))

    pos = 8
    last_known_rank = 0
    seen_known: dict[int, Section] = {}
    order = 0
    while pos < len(data):
        header_start = pos
        section_id = data[pos]
        pos += 1
        size_leb = decode_unsigned(data, pos, 32)
        mod.leb_issues.append(size_leb)
        pos += size_leb.byte_length
        size = size_leb.value or 0
        payload_start = pos
        payload_end = min(pos + size, len(data))
        raw = data[payload_start:payload_end]
        pos = payload_end
        name = SECTION_NAMES.get(section_id, f"unknown_{section_id}")
        sec = Section(
            identity=f"sec:{order}", order_index=order, section_id=section_id,
            name=name, size=size_leb.value, header_start=header_start,
            payload_start=payload_start, payload_end=payload_end,
            size_leb=size_leb, raw=raw,
        )
        mod.sections.append(sec)
        order += 1

        if section_id == 0:
            pass  # custom sections may appear anywhere, any number of times
        elif section_id not in SECTION_NAMES:
            mod.diagnostics.append(Diagnostic(
                "unknown_section_id", f"section id {section_id} is not defined",
                header_start, header_start + 1))
        else:
            rank = KNOWN_ORDER.index(section_id) + 1
            if section_id in seen_known:
                first = seen_known[section_id]
                mod.diagnostics.append(Diagnostic(
                    "section_duplicate",
                    f"section '{name}' appears again (first: {first.identity} at byte "
                    f"{first.header_start}, duplicate: {sec.identity})",
                    header_start, payload_start))
            else:
                seen_known[section_id] = sec
            if rank < last_known_rank:
                mod.diagnostics.append(Diagnostic(
                    "section_out_of_order",
                    f"section '{name}' (rank {rank}) appears after a rank-{last_known_rank} section",
                    header_start, payload_start))
            last_known_rank = max(last_known_rank, rank)

        if section_id == 1:
            _parse_type_section(mod, sec)
        elif section_id == 2:
            _parse_import_section(mod, sec)
        elif section_id == 3:
            _parse_function_section(mod, sec)
        elif section_id == 10:
            _parse_code_section(mod, sec)

    # function/code count agreement
    if mod.functions and mod.bodies and len(mod.functions) != len(mod.bodies):
        mod.diagnostics.append(Diagnostic(
            "function_code_count_mismatch",
            f"function section declares {len(mod.functions)} but code section has {len(mod.bodies)}",
            0, 0))
    return mod


def _parse_type_section(mod: ParsedModule, sec: Section) -> None:
    r = _Reader(sec.raw, base=sec.payload_start)
    count = r.u32()
    mod.leb_issues.append(count)
    for _ in range(count.value or 0):
        if r.done():
            break
        start = r.base + r.pos
        form = r.u8()
        if form != 0x60:
            mod.diagnostics.append(Diagnostic(
                "bad_functype_form", f"expected 0x60, got 0x{form:02x}", start, start + 1))
            return
        params = _read_valtype_vec(mod, r)
        results = _read_valtype_vec(mod, r)
        mod.types.append(FuncType(len(mod.types), params, results, start, r.base + r.pos))


def _read_valtype_vec(mod: ParsedModule, r: _Reader) -> list[str]:
    count = r.u32()
    mod.leb_issues.append(count)
    out = []
    for _ in range(count.value or 0):
        if r.done():
            break
        b = r.u8()
        out.append(VALTYPES.get(b, f"unknown_0x{b:02x}"))
    return out


def _parse_import_section(mod: ParsedModule, sec: Section) -> None:
    r = _Reader(sec.raw, base=sec.payload_start)
    count = r.u32()
    mod.leb_issues.append(count)
    func_index = 0
    for _ in range(count.value or 0):
        if r.done():
            break
        start = r.base + r.pos
        module, _ = _read_name(r)
        name, _ = _read_name(r)
        kind_byte = r.u8()
        kind = IMPORT_KINDS.get(kind_byte, f"unknown_{kind_byte}")
        type_index = None
        type_leb = None
        if kind == "func":
            type_leb = r.u32()
            mod.leb_issues.append(type_leb)
            type_index = type_leb.value
        elif kind == "global":
            r.u8()  # valtype
            r.u8()  # mutability
        elif kind == "memory":
            _skip_limits(r)
        elif kind == "table":
            r.u8()
            _skip_limits(r)
        mod.imports.append(ImportEntry(
            index=func_index if kind == "func" else -1,
            module=module, name=name, kind=kind,
            type_index=type_index, type_index_leb=type_leb,
            byte_start=start, byte_end=r.base + r.pos))
        if kind == "func":
            func_index += 1


def _skip_limits(r: _Reader) -> None:
    flags = r.u8()
    r.u32()
    if flags & 1:
        r.u32()


def _parse_function_section(mod: ParsedModule, sec: Section) -> None:
    r = _Reader(sec.raw, base=sec.payload_start)
    count = r.u32()
    mod.leb_issues.append(count)
    imported_funcs = sum(1 for i in mod.imports if i.kind == "func")
    for n in range(count.value or 0):
        if r.done():
            break
        leb = r.u32()
        mod.leb_issues.append(leb)
        mod.functions.append(FunctionEntry(imported_funcs + n, leb.value, leb))


def _parse_code_section(mod: ParsedModule, sec: Section) -> None:
    r = _Reader(sec.raw, base=sec.payload_start)
    count = r.u32()
    mod.leb_issues.append(count)
    imported_funcs = sum(1 for i in mod.imports if i.kind == "func")
    for n in range(count.value or 0):
        if r.done():
            break
        body_start = r.base + r.pos
        size = r.u32()
        mod.leb_issues.append(size)
        body_end_pos = r.pos + (size.value or 0)
        local_count = r.u32()
        mod.leb_issues.append(local_count)
        locals_: list[str] = []
        for _ in range(local_count.value or 0):
            run = r.u32()
            mod.leb_issues.append(run)
            vt = r.u8()
            locals_.extend([VALTYPES.get(vt, f"unknown_0x{vt:02x}")] * (run.value or 0))
        expr_start = r.base + r.pos
        expr_end = r.base + body_end_pos
        expr = r.data[r.pos:body_end_pos]
        r.pos = body_end_pos
        mod.bodies.append(CodeBody(
            func_index=imported_funcs + n, locals=locals_,
            expr_start=expr_start, expr_end=expr_end, expr=expr,
            byte_start=body_start, byte_end=expr_end))
