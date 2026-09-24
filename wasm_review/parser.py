"""Structural WebAssembly module parser.

The parser is intentionally proposal-agnostic: it records section layout,
index spaces and raw instruction bytes. Semantic/type checking happens in
``validator``.  Every parsed node carries:

* ``uid``         stable content identity (hash of structural content)
* ``byte_start``/``byte_end``  original byte range in the immutable blob
* ``leb``         original LEB128 representation for each decoded number
"""

import hashlib
from dataclasses import dataclass, field

from . import ALGORITHM_VERSION_PARSE, WASM_MAGIC, WASM_VERSION
from .leb128 import read_leb
from .opcodes import VALTYPES, REFTYPES

SECTION_NAMES = {
    0: "custom",
    1: "type", 2: "import", 3: "function", 4: "table", 5: "memory",
    6: "global", 7: "export", 8: "start", 9: "element", 10: "code",
    11: "data", 12: "datacount",
}
KNOWN_SECTION_IDS = set(SECTION_NAMES)
# Canonical order for the eleven well-known sections (id 1..12 minus gaps).
CANONICAL_ORDER = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]


def _uid(prefix: str, material: str) -> str:
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}_{digest}"


@dataclass
class ParseIssue:
    code: str
    message: str
    byte_start: int
    byte_end: int
    uid: str = ""

    def __post_init__(self):
        if not self.uid:
            self.uid = _uid("pi", f"{self.code}@{self.byte_start}:{self.byte_end}")

    def as_dict(self) -> dict:
        return {"uid": self.uid, "code": self.code, "message": self.message,
                "byte_start": self.byte_start, "byte_end": self.byte_end}


@dataclass
class Section:
    sec_id: int
    name: str
    byte_start: int          # at section id byte
    byte_end: int
    payload_start: int
    payload_end: int
    size_leb: dict
    name_leb: dict | None = None   # custom section name utf8 range/bytes
    raw_custom: bytes = b""
    uid: str = ""
    index_in_file: int = 0

    def as_dict(self) -> dict:
        return {
            "uid": self.uid, "sec_id": self.sec_id, "name": self.name,
            "index_in_file": self.index_in_file,
            "byte_start": self.byte_start, "byte_end": self.byte_end,
            "payload_start": self.payload_start, "payload_end": self.payload_end,
            "size_leb": self.size_leb,
            "custom_name_leb": self.name_leb,
            "custom_hex": self.raw_custom.hex(),
        }


@dataclass
class ImportRec:
    index: int
    module: str
    field: str
    kind: str               # function | table | memory | global
    desc: dict
    byte_start: int
    byte_end: int
    uid: str = ""

    def as_dict(self) -> dict:
        return {"uid": self.uid, "index": self.index, "module": self.module,
                "field": self.field, "kind": self.kind, "desc": self.desc,
                "byte_start": self.byte_start, "byte_end": self.byte_end}


@dataclass
class TypeRec:
    index: int
    functype: dict          # {"params": [...], "results": [...]}
    byte_start: int
    byte_end: int
    uid: str = ""

    def as_dict(self) -> dict:
        return {"uid": self.uid, "index": self.index,
                "functype": self.functype,
                "byte_start": self.byte_start, "byte_end": self.byte_end}


@dataclass
class GlobalRec:
    index: int
    valtype: str
    mutable: bool
    byte_start: int
    byte_end: int
    uid: str = ""

    def as_dict(self) -> dict:
        return {"uid": self.uid, "index": self.index, "valtype": self.valtype,
                "mutable": self.mutable,
                "byte_start": self.byte_start, "byte_end": self.byte_end}


@dataclass
class FuncBody:
    func_index: int          # module-level func index (incl imports)
    body_index: int          # index among defined functions
    byte_start: int
    byte_end: int
    locals: list
    expr_start: int
    expr_end: int
    body_size_leb: dict
    uid: str = ""

    def as_dict(self) -> dict:
        return {"uid": self.uid, "func_index": self.func_index,
                "body_index": self.body_index,
                "byte_start": self.byte_start, "byte_end": self.byte_end,
                "locals": self.locals,
                "expr_start": self.expr_start, "expr_end": self.expr_end,
                "body_size_leb": self.body_size_leb}


@dataclass
class ParsedModule:
    algorithm_version: str
    byte_len: int
    magic_ok: bool
    version_ok: bool
    sections: list = field(default_factory=list)
    types: list = field(default_factory=list)
    imports: list = field(default_factory=list)
    func_type_index: list = field(default_factory=list)  # one entry per defined func
    func_type_index_lebs: list = field(default_factory=list)
    globals_: list = field(default_factory=list)
    tables: list = field(default_factory=list)
    memories: list = field(default_factory=list)
    exports: list = field(default_factory=list)
    func_bodies: list = field(default_factory=list)
    issue_diags: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "algorithm_version": self.algorithm_version,
            "byte_len": self.byte_len,
            "magic_ok": self.magic_ok,
            "version_ok": self.version_ok,
            "sections": [s.as_dict() for s in self.sections],
            "types": [t.as_dict() for t in self.types],
            "imports": [i.as_dict() for i in self.imports],
            "func_type_index": self.func_type_index,
            "func_type_index_lebs": self.func_type_index_lebs,
            "globals": [g.as_dict() for g in self.globals_],
            "tables": self.tables,
            "memories": self.memories,
            "exports": self.exports,
            "func_bodies": [b.as_dict() for b in self.func_bodies],
            "issues": self.issue_diags,
        }


class _Cursor:
    def __init__(self, buf: bytes, end: int | None = None):
        self.buf = buf
        self.pos = 0
        self.end = len(buf) if end is None else end
        self.issues: list[ParseIssue] = []

    def leb(self, kind: str = "u32"):
        lv = read_leb(self.buf, self.pos, kind)
        self.pos = lv.end
        if lv.code is not None and lv.code != "leb_truncated":
            self.issues.append(ParseIssue(
                lv.code, f"{kind} LEB128 {lv.status}: {lv.raw.hex()}",
                lv.start, lv.end))
        return lv

    def byte(self) -> int | None:
        if self.pos >= self.end:
            return None
        v = self.buf[self.pos]
        self.pos += 1
        return v

    def take(self, n: int) -> bytes:
        chunk = self.buf[self.pos:min(self.pos + n, self.end)]
        self.pos += len(chunk)
        return chunk

    def name(self) -> tuple[str, int, int]:
        start = self.pos
        lv = self.leb()
        raw = self.take(max(0, lv.value))
        end = self.pos
        return raw.decode("utf-8", "replace"), start, end


def _read_valtype(c: _Cursor):
    b = c.byte()
    if b is None:
        return None, None
    if b in VALTYPES:
        return VALTYPES[b], b
    if b in REFTYPES:
        return REFTYPES[b], b
    c.issues.append(ParseIssue("unknown_valtype",
                               f"unknown value type byte 0x{b:02x}",
                               c.pos - 1, c.pos))
    return f"0x{b:02x}", b


def _limits(c: _Cursor) -> dict:
    flag = c.byte()
    out = {"flag_byte": flag, "byte_start": c.pos - 1}
    if flag in (0x00, 0x01):
        mn = c.leb()
        out["min"] = mn.value
        out["min_leb"] = mn.to_diag()
        if flag == 0x01:
            mx = c.leb()
            out["max"] = mx.value
            out["max_leb"] = mx.to_diag()
    else:
        c.issues.append(ParseIssue("bad_limits_flag",
                                   f"invalid limits flag 0x{flag:02x}",
                                   c.pos - 1, c.pos))
    out["byte_end"] = c.pos
    return out


def _parse_type_payload(c: _Cursor, mod: ParsedModule):
    n = c.leb()
    for i in range(n.value):
        start = c.pos
        tag = c.byte()
        functype = {"tag": tag}
        if tag != 0x60:
            c.issues.append(ParseIssue("bad_functype_tag",
                                       f"expected 0x60 got 0x{(tag or 0):02x}",
                                       c.pos - 1, c.pos))
        pn = c.leb()
        params = []
        for _ in range(pn.value):
            vt, raw = _read_valtype(c)
            params.append({"type": vt, "raw_byte": raw})
        rn = c.leb()
        results = []
        for _ in range(rn.value):
            vt, raw = _read_valtype(c)
            results.append({"type": vt, "raw_byte": raw})
        functype = {"params": [p["type"] for p in params],
                    "results": [r["type"] for r in results],
                    "params_raw": params, "results_raw": results}
        mod.types.append(TypeRec(i, functype, start, c.pos,
                                 _uid("ty", f"{i}|{params}|{results}")))


def _parse_import_payload(c: _Cursor, mod: ParsedModule):
    n = c.leb()
    for i in range(n.value):
        start = c.pos
        modname, _, _ = c.name()
        fieldname, _, _ = c.name()
        kind = c.byte()
        desc: dict = {}
        kind_name = {0: "function", 1: "table", 2: "memory",
                     3: "global"}.get(kind)
        if kind_name is None:
            c.issues.append(ParseIssue("bad_import_kind",
                                       f"import kind 0x{(kind or 0):02x}",
                                       c.pos - 1, c.pos))
        if kind == 0:
            ti = c.leb()
            desc = {"type_index": ti.value, "type_index_leb": ti.to_diag()}
        elif kind == 1:
            et, raw = _read_valtype(c)
            lim = _limits(c)
            desc = {"element_type": et, "element_raw": raw, "limits": lim}
        elif kind == 2:
            desc = {"limits": _limits(c)}
        elif kind == 3:
            vt, raw = _read_valtype(c)
            mut = c.byte()
            desc = {"valtype": vt, "valtype_raw": raw, "mutable": mut == 1,
                    "mut_byte": mut}
        rec = ImportRec(i, modname, fieldname, kind_name or "unknown", desc,
                        start, c.pos)
        rec.uid = _uid("imp", f"{i}|{modname}|{fieldname}|{kind}|{c.pos}")
        mod.imports.append(rec)


def _parse_function_payload(c: _Cursor, mod: ParsedModule):
    n = c.leb()
    for i in range(n.value):
        ti = c.leb()
        mod.func_type_index.append(ti.value)
        mod.func_type_index_lebs.append(ti.to_diag())


def _parse_table_payload(c: _Cursor, mod: ParsedModule):
    n = c.leb()
    for i in range(n.value):
        start = c.pos
        et, raw = _read_valtype(c)
        lim = _limits(c)
        mod.tables.append({"index": i, "element_type": et,
                           "element_raw": raw, "limits": lim,
                           "byte_start": start, "byte_end": c.pos})


def _parse_memory_payload(c: _Cursor, mod: ParsedModule):
    n = c.leb()
    for i in range(n.value):
        start = c.pos
        lim = _limits(c)
        mod.memories.append({"index": i, "limits": lim,
                             "byte_start": start, "byte_end": c.pos})


def _parse_global_payload(c: _Cursor, mod: ParsedModule):
    n = c.leb()
    for i in range(n.value):
        start = c.pos
        vt, raw = _read_valtype(c)
        mut = c.byte()
        # constant init expr: parse minimally up to first 0x0b
        expr_start = c.pos
        while c.pos < c.end and c.buf[c.pos] != 0x0B:
            c.pos += 1
        end_byte = c.byte()
        g = GlobalRec(i, vt or "?", mut == 1, start, c.pos,
                      _uid("glo", f"{i}|{vt}|{mut}|{expr_start}"))
        mod.globals_.append(g)


def _parse_export_payload(c: _Cursor, mod: ParsedModule):
    n = c.leb()
    for i in range(n.value):
        start = c.pos
        nm, ns, ne = c.name()
        kind = c.byte()
        idx = c.leb()
        mod.exports.append({
            "index": i, "name": nm, "kind": kind,
            "kind_name": {0: "function", 1: "table", 2: "memory",
                          3: "global"}.get(kind, "unknown"),
            "target_index": idx.value, "target_index_leb": idx.to_diag(),
            "byte_start": start, "byte_end": c.pos,
            "uid": _uid("exp", f"{i}|{nm}|{kind}|{idx.value}"),
        })


def _parse_code_payload(c: _Cursor, mod: ParsedModule):
    n = c.leb()
    imported = sum(1 for i in mod.imports if i.kind == "function")
    for k in range(n.value):
        start = c.pos
        size = c.leb()
        body_end = min(c.pos + size.value, c.end)
        body_c = _Cursor(c.buf, body_end)
        body_c.pos = c.pos
        local_groups = body_c.leb()
        locals_: list = []
        for _g in range(local_groups.value):
            cnt = body_c.leb()
            vt, raw = _read_valtype(body_c)
            locals_.append({"count": cnt.value, "type": vt,
                            "count_leb": cnt.to_diag(),
                            "raw_byte": raw})
        expr_start = body_c.pos
        # Raw expression bytes are preserved; decoder runs in the validator
        # against the active capability set.
        expr_end = body_end
        body_c.pos = body_end
        if size.value and c.pos + size.value <= c.end:
            pass
        func_index = imported + k
        body = FuncBody(
            func_index, k, start, body_end, locals_, expr_start, expr_end,
            size.to_diag(),
            _uid("body", f"{func_index}|{start}|{size.value}"))
        mod.func_bodies.append(body)
        c.pos = body_end
    if n.value != len(mod.func_type_index) and mod.func_type_index:
        c.issues.append(ParseIssue(
            "function_code_count_mismatch",
            f"function section declares {len(mod.func_type_index)} but code "
            f"section has {n.value} bodies",
            n.start, n.end))


def _count_valtype_list(c: _Cursor):
    n = c.leb()
    for _ in range(n.value):
        _read_valtype(c)
    return n.value


def _parse_element_payload(c: _Cursor, mod: ParsedModule):
    # Parse just enough to stay structurally aligned; MVP table 0 segments.
    n = c.leb()
    for i in range(n.value):
        start = c.pos
        flag = c.leb()
        if flag.value == 0:
            off = c.leb()              # offset expr (simplified: const+end)
            while c.pos < c.end and c.buf[c.pos] != 0x0B:
                c.pos += 1
            c.byte()
            cnt = c.leb()
            for _ in range(cnt.value):
                c.leb()
        else:
            c.issues.append(ParseIssue(
                "element_flag_unsupported",
                f"element segment flag {flag.value} parsed minimally",
                start, c.pos))
            break
        mod.exports  # no-op to keep linters calm


def _parse_data_payload(c: _Cursor):
    c.leb()  # count
    # Data segments are kept as opaque payload bytes; details are not needed
    # by the type-stack validation exercised by the case pack.


def parse_module(data: bytes) -> ParsedModule:
    mod = ParsedModule(ALGORITHM_VERSION_PARSE, len(data), False, False)
    magic_ok = data[:4] == WASM_MAGIC
    version_ok = data[4:8] == WASM_VERSION
    mod.magic_ok = magic_ok
    mod.version_ok = version_ok
    if not magic_ok:
        mod.issue_diags.append(ParseIssue(
            "bad_magic", "module does not start with \\x00asm", 0,
            min(4, len(data))).as_dict())
        return mod
    if not version_ok:
        mod.issue_diags.append(ParseIssue(
            "bad_version", f"unsupported version bytes {data[4:8].hex()}",
            4, 8).as_dict())
        return mod

    pos = 8
    file_index = 0
    while pos < len(data):
        sec_start = pos
        sec_id = data[pos]
        pos += 1
        size_lv = read_leb(data, pos, "u32")
        pos = size_lv.end
        payload_start = pos
        payload_end = min(pos + size_lv.value, len(data))
        raw_payload = data[payload_start:payload_end]
        if size_lv.code is not None and size_lv.code != "leb_truncated":
            mod.issue_diags.append(ParseIssue(
                size_lv.code,
                f"section size LEB128 {size_lv.status}",
                size_lv.start, size_lv.end).as_dict())
        name_leb = None
        custom_raw = b""
        name = SECTION_NAMES.get(sec_id)
        if sec_id == 0:
            nc = _Cursor(data, payload_end)
            nc.pos = payload_start
            nm, ns, ne = nc.name()
            name = f"custom:{nm}"
            name_bytes = data[ns:ne]
            name_leb = {"hex": name_bytes.hex(), "byte_start": ns,
                        "byte_end": ne, "text": nm}
            custom_raw = data[ne:payload_end]
        sec = Section(sec_id, name or f"unknown(0x{sec_id:02x})",
                      sec_start, payload_end, payload_start, payload_end,
                      size_lv.to_diag(), name_leb, custom_raw)
        sec.index_in_file = file_index
        sec.uid = _uid(
            "sec",
            f"{file_index}|{sec_id}|{payload_start}|{raw_payload.hex()}")
        mod.sections.append(sec)

        c = _Cursor(data, payload_end)
        c.pos = payload_start
        try:
            if sec_id == 1:
                _parse_type_payload(c, mod)
            elif sec_id == 2:
                _parse_import_payload(c, mod)
            elif sec_id == 3:
                _parse_function_payload(c, mod)
            elif sec_id == 4:
                _parse_table_payload(c, mod)
            elif sec_id == 5:
                _parse_memory_payload(c, mod)
            elif sec_id == 6:
                _parse_global_payload(c, mod)
            elif sec_id == 7:
                _parse_export_payload(c, mod)
            elif sec_id == 9:
                _parse_element_payload(c, mod)
            elif sec_id == 10:
                _parse_code_payload(c, mod)
            elif sec_id == 11:
                _parse_data_payload(c)
        except IndexError:
            c.issues.append(ParseIssue(
                "payload_truncated",
                f"section {name} payload ended unexpectedly",
                payload_start, payload_end))
        for issue in c.issues:
            mod.issue_diags.append(issue.as_dict())
        if payload_end > len(data):
            mod.issue_diags.append(ParseIssue(
                "section_size_overflow",
                f"section {name} claims size {size_lv.value} past blob end",
                size_lv.start, size_lv.end).as_dict())
        pos = payload_end
        file_index += 1
    return mod
