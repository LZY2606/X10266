"""段内容分析：类型/导入/函数/全局/代码索引空间与字节范围。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .leb128 import decode_s, decode_u
from .parser import Diagnostic, ModuleMap
from .quantities import index_value

VALTYPES = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64",
            0x7B: "v128", 0x70: "funcref", 0x6F: "externref"}
REF_TYPES = {0x70: "funcref", 0x6F: "externref"}


class Cursor:
    def __init__(self, data: bytes, start: int, end: int, leb_log: Optional[list],
                 ctx: str):
        self.data = data
        self.pos = start
        self.end = end
        self.leb_log = leb_log
        self.ctx = ctx

    def u32(self, label: str):
        r = decode_u(self.data, self.pos, 32, f"{self.ctx}.{label}")
        if self.leb_log is not None:
            self.leb_log.append(r)
        self.pos = r.end
        return r

    def s32(self, label: str):
        r = decode_s(self.data, self.pos, 32, f"{self.ctx}.{label}")
        if self.leb_log is not None:
            self.leb_log.append(r)
        self.pos = r.end
        return r

    def s33(self, label: str):
        r = decode_s(self.data, self.pos, 33, f"{self.ctx}.{label}")
        if self.leb_log is not None:
            self.leb_log.append(r)
        self.pos = r.end
        return r

    def byte(self, label: str):
        b = self.data[self.pos]
        self.pos += 1
        return b

    def take(self, n: int, label: str):
        raw = self.data[self.pos:self.pos + n]
        self.pos += n
        return raw

    @property
    def exhausted(self) -> bool:
        return self.pos >= self.end


@dataclass
class FuncType:
    index: int
    params: list
    results: list
    offset: int
    end: int

    def to_dict(self) -> dict:
        return {
            "index": index_value(self.index, "type").to_dict(),
            "params": self.params,
            "results": self.results,
            "byte_range": {"start": self.offset, "end": self.end},
        }


@dataclass
class ImportEntry:
    index: int
    module: str
    name: str
    kind: str
    descriptor: dict
    offset: int
    end: int

    def to_dict(self) -> dict:
        return {
            "index": index_value(self.index, "import").to_dict(),
            "module": self.module, "name": self.name,
            "kind": self.kind, "descriptor": self.descriptor,
            "byte_range": {"start": self.offset, "end": self.end},
        }


@dataclass
class CodeBody:
    func_index: int
    body_offset: int
    body_end: int
    expr_offset: int
    locals: list

    def to_dict(self) -> dict:
        return {
            "func_index": index_value(self.func_index, "func").to_dict(),
            "body_byte_range": {"start": self.body_offset, "end": self.body_end},
            "expr_offset": self.expr_offset,
            "locals": self.locals,
        }


@dataclass
class ModuleAnalysis:
    types: list = field(default_factory=list)
    imports: list = field(default_factory=list)
    function_type_indices: list = field(default_factory=list)
    globals_: list = field(default_factory=list)
    code_bodies: list = field(default_factory=list)
    diagnostics: list = field(default_factory=list)
    index_spaces: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "types": [t.to_dict() for t in self.types],
            "imports": [i.to_dict() for i in self.imports],
            "function_type_indices": [
                {"func_index": index_value(k, "func").to_dict(),
                 "type_index": index_value(v, "type").to_dict()}
                for k, v in self.function_type_indices],
            "globals": self.globals_,
            "code_bodies": [b.to_dict() for b in self.code_bodies],
            "index_spaces": self.index_spaces,
            "diagnostics": [d.to_dict() for d in self.diagnostics],
        }


def _read_name(cur: Cursor, label: str):
    length = cur.u32(f"{label}-length")
    if not length.decodable:
        return None
    raw = cur.take(length.value, label)
    return raw.decode("utf-8")


def _read_result_types(cur: Cursor, label: str):
    count = cur.u32(f"{label}-count")
    types = []
    if not count.decodable:
        return types, count
    for _ in range(count.value):
        b = cur.byte(f"{label}-type")
        types.append(VALTYPES.get(b, f"unknown-valtype-0x{b:02x}"))
    return types, count


def _read_limits(cur: Cursor, label: str):
    flags = cur.byte(f"{label}-flags")
    lim = {"flags": flags}
    minimum = cur.u32(f"{label}-min")
    lim["min"] = minimum.value
    if flags & 1:
        maximum = cur.u32(f"{label}-max")
        lim["max"] = maximum.value
    return lim


def _parse_type_section(cur: Cursor, out: ModuleAnalysis):
    count = cur.u32("type-count")
    if not count.decodable:
        out.diagnostics.append(Diagnostic(
            f"leb-{count.status}", f"type count: {count.diagnostic}",
            count.offset, count.end, "type"))
        return
    for i in range(count.value):
        start = cur.pos
        tag = cur.byte("functype-tag")
        if tag != 0x60:
            out.diagnostics.append(Diagnostic(
                "bad-functype-tag", f"expected 0x60, got 0x{tag:02x}",
                cur.pos - 1, cur.pos, f"type[{i}]"))
        params, _ = _read_result_types(cur, f"type[{i}].params")
        results, _ = _read_result_types(cur, f"type[{i}].results")
        out.types.append(FuncType(i, params, results, start, cur.pos))


def _parse_import_section(cur: Cursor, out: ModuleAnalysis):
    count = cur.u32("import-count")
    if not count.decodable:
        out.diagnostics.append(Diagnostic(
            f"leb-{count.status}", f"import count: {count.diagnostic}",
            count.offset, count.end, "import"))
        return
    for i in range(count.value):
        start = cur.pos
        module = _read_name(cur, f"import[{i}].module")
        name = _read_name(cur, f"import[{i}].name")
        kind = cur.byte(f"import[{i}].kind")
        if kind == 0x00:
            tidx = cur.u32(f"import[{i}].typeidx")
            descriptor = {"type_index": tidx.value}
            kind_name = "func"
        elif kind == 0x01:
            elem = cur.byte(f"import[{i}].table-elemtype")
            lim = _read_limits(cur, f"import[{i}].table")
            descriptor = {"element_type": REF_TYPES.get(elem, f"0x{elem:02x}"),
                          "limits": lim}
            kind_name = "table"
        elif kind == 0x02:
            descriptor = {"limits": _read_limits(cur, f"import[{i}].memory")}
            kind_name = "memory"
        elif kind == 0x03:
            vt = cur.byte(f"import[{i}].global-valtype")
            mut = cur.byte(f"import[{i}].global-mut")
            descriptor = {"valtype": VALTYPES.get(vt, f"0x{vt:02x}"),
                          "mutable": bool(mut)}
            kind_name = "global"
        else:
            descriptor = {"raw_kind": kind}
            kind_name = f"unknown-0x{kind:02x}"
            out.diagnostics.append(Diagnostic(
                "unknown-import-kind", f"import kind 0x{kind:02x}",
                cur.pos - 1, cur.pos, f"import[{i}]"))
        out.imports.append(ImportEntry(
            i, module, name, kind_name, descriptor, start, cur.pos))


def _parse_function_section(cur: Cursor, out: ModuleAnalysis):
    count = cur.u32("function-count")
    if not count.decodable:
        out.diagnostics.append(Diagnostic(
            f"leb-{count.status}", f"function count: {count.diagnostic}",
            count.offset, count.end, "function"))
        return
    imported_funcs = sum(1 for imp in out.imports if imp.kind == "func")
    for i in range(count.value):
        tidx = cur.u32(f"function[{i}].typeidx")
        out.function_type_indices.append((imported_funcs + i, tidx.value))


def _parse_global_section(cur: Cursor, out: ModuleAnalysis):
    count = cur.u32("global-count")
    if not count.decodable:
        return
    imported_globals = sum(1 for imp in out.imports if imp.kind == "global")
    for i in range(count.value):
        vt = cur.byte(f"global[{i}].valtype")
        mut = cur.byte(f"global[{i}].mut")
        out.globals_.append({
            "index": imported_globals + i,
            "valtype": VALTYPES.get(vt, f"0x{vt:02x}"),
            "mutable": bool(mut),
            "offset": cur.pos - 2,
        })
        _skip_init_expr(cur, f"global[{i}].init")


def _skip_init_expr(cur: Cursor, label: str):
    depth = 0
    start = cur.pos
    while cur.pos < cur.end:
        b = cur.byte(f"{label}.opcode")
        if b == 0x41:
            r = cur.s32(f"{label}.i32-imm")
        elif b == 0x42:
            r = decode_s(cur.data, cur.pos, 64, f"{label}.i64-imm")
            if cur.leb_log is not None:
                cur.leb_log.append(r)
            cur.pos = r.end
        elif b == 0x43:
            cur.take(4, f"{label}.f32-imm")
        elif b == 0x44:
            cur.take(8, f"{label}.f64-imm")
        elif b in (0x23,):
            cur.u32(f"{label}.global-imm")
        elif b == 0x0B:
            break
        elif b in (0x02, 0x03, 0x04):
            cur.pos += 1
            depth += 1
            continue
        elif b == 0x00:
            continue
        if depth > 0 and b == 0x0B:
            depth -= 1
    return start, cur.pos


def _parse_code_section(cur: Cursor, out: ModuleAnalysis):
    count = cur.u32("code-count")
    if not count.decodable:
        out.diagnostics.append(Diagnostic(
            f"leb-{count.status}", f"code count: {count.diagnostic}",
            count.offset, count.end, "code"))
        return
    imported_funcs = sum(1 for imp in out.imports if imp.kind == "func")
    for i in range(count.value):
        size = cur.u32(f"body[{i}].size")
        body_start = cur.pos
        if not size.decodable:
            out.diagnostics.append(Diagnostic(
                f"leb-{size.status}", f"body size: {size.diagnostic}",
                size.offset, size.end, f"code.body[{i}]"))
            break
        body_end = min(body_start + size.value, cur.end)
        body_cur = Cursor(cur.data, body_start, body_end, cur.leb_log,
                          f"code.body[{i}]")
        local_groups = body_cur.u32("local-decl-groups")
        locals_ = []
        if local_groups.decodable:
            for g in range(local_groups.value):
                n = body_cur.u32(f"local-group[{g}].count")
                vt = body_cur.byte(f"local-group[{g}].valtype")
                if n.decodable:
                    locals_.extend([VALTYPES.get(vt, f"0x{vt:02x}")] * n.value)
        expr_offset = body_cur.pos
        out.code_bodies.append(CodeBody(
            imported_funcs + i, body_start, body_end, expr_offset, locals_))
        cur.pos = body_end


def analyze(data: bytes, module_map: ModuleMap,
            leb_log: Optional[list] = None) -> ModuleAnalysis:
    out = ModuleAnalysis()
    parsers = {1: _parse_type_section, 2: _parse_import_section,
               3: _parse_function_section, 6: _parse_global_section,
               10: _parse_code_section}
    for sec in module_map.sections:
        parser_fn = parsers.get(sec.section_id)
        if parser_fn is None:
            continue
        cur = Cursor(data, sec.content_offset, sec.end_offset, leb_log,
                     f"section#{sec.ordinal}.{sec.name}")
        parser_fn(cur, out)
        if cur.pos != cur.end:
            out.diagnostics.append(Diagnostic(
                "section-trailing-bytes",
                f"{sec.name} section has {cur.end - cur.pos} unconsumed byte(s)",
                cur.pos, cur.end, sec.name))

    imported = {
        "func": sum(1 for i in out.imports if i.kind == "func"),
        "table": sum(1 for i in out.imports if i.kind == "table"),
        "memory": sum(1 for i in out.imports if i.kind == "memory"),
        "global": sum(1 for i in out.imports if i.kind == "global"),
    }
    defined = {
        "func": len(out.code_bodies),
        "global": len(out.globals_),
        "type": len(out.types),
    }
    out.index_spaces = {
        "type": {"imported": 0, "defined": len(out.types),
                 "total": len(out.types)},
        "func": {"imported": imported["func"],
                 "defined": len(out.code_bodies),
                 "total": imported["func"] + len(out.code_bodies)},
        "global": {"imported": imported["global"],
                   "defined": len(out.globals_),
                   "total": imported["global"] + len(out.globals_)},
    }
    return out
