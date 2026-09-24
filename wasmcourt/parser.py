"""字节级 WebAssembly 模块解析器。

保留（基线保真）：
  原字节范围、section id/size、LEB128 编码细节、索引来源、
  import 契约与自定义段（含名字与原始 payload 字节）。

解析只做“能安全读取”的结构化工作；类型栈 / 能力 / 契约判定在 validate。
解析层发现的问题（header、段顺序、重复段、LEB、截断）记为 finding，
其 range 是精确到字节的半开区间，供“最小失败字节范围”展示。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import leb128
from .ident import cid
from .units import byte_range

WASM_MAGIC = b"\x00asm"
WASM_VERSION = b"\x01\x00\x00\x00"

SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "datacount",
}
# 标准段必须按 id 升序出现（custom 段 id=0 可出现在任意位置）。
ORDERED_STANDARD_IDS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]

VALTYPE_NAMES = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64",
                 0x7B: "v128", 0x70: "funcref", 0x6F: "externref"}

IMPORT_KIND = {0: "func", 1: "table", 2: "mem", 3: "global"}
EXPORT_KIND = {0: "func", 1: "table", 2: "mem", 3: "global"}
FUNC_TYPE_REF = 0x00
LIMITS_HAS_MAX = 0x01


@dataclass
class Finding:
    code: str
    message: str
    range: dict
    severity: str = "error"
    category: str = "parse"
    candidates: list[dict] = field(default_factory=list)
    provenance: dict = field(default_factory=dict)

    def ident(self) -> str:
        return cid({"code": self.code, "range": self.range,
                    "message": self.message, "category": self.category})

    def as_dict(self) -> dict:
        return {"id": self.ident(), "code": self.code, "message": self.message,
                "range": self.range, "severity": self.severity,
                "category": self.category, "candidates": self.candidates,
                "provenance": self.provenance}


def _finding(code, message, start, end, severity="error", category="parse",
             candidates=None, provenance=None) -> Finding:
    return Finding(code, message, byte_range(start, end), severity, category,
                   candidates or [], provenance or {})


class ParseError(Exception):
    def __init__(self, message, start=None, end=None, code="parse_error"):
        super().__init__(message)
        self.code = code
        self.start = start
        self.end = end


class Cursor:
    """带边界检查的字节游标；越界抛 ParseError（带字节坐标）。"""

    def __init__(self, data: bytes, base: int = 0, end: int | None = None):
        self.data = data
        self.pos = base
        self.end = len(data) if end is None else end

    def remaining(self) -> int:
        return self.end - self.pos

    def take(self, n: int, what: str) -> bytes:
        if n < 0 or self.pos + n > self.end:
            raise ParseError(f"unexpected end of section reading {what}",
                             self.pos, min(self.pos + max(n, 1), len(self.data)),
                             code="truncated")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u8(self, what: str) -> tuple[int, int, int]:
        start = self.pos
        return self.take(1, what)[0], start, self.pos

    def leb_u32(self, what: str) -> tuple[int | None, dict]:
        start = self.pos
        result = leb128.decode_u32(self.data, start)
        if start + result.width > self.end:
            raise ParseError(f"unexpected end of section reading {what} LEB128",
                             start, self.end, code="truncated")
        self.pos += result.width
        info = {"what": what, "range": byte_range(start, self.pos),
                **result.as_dict()}
        return result.value, info

    def name(self, what: str) -> tuple[str, int, int, dict | None, int | None]:
        start = self.pos
        n, leb = self.leb_u32(f"{what}.name_len")
        raw = self.take(n, f"{what}.name") if n is not None else b""
        try:
            text = raw.decode("utf-8")
            bad = None
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
            bad = "name is not valid UTF-8"
        return text, start, self.pos, bad, leb["range"]["start"]



def parse_module(data: bytes) -> dict:
    """解析完整模块，返回结构化字典 + findings + LEB 记录。

    解析永不抛异常（格式错误也返回结构化结果），致命错误记录后停止深入，
    但已安全读取的信息全部保留。
    """
    findings: list[dict] = []
    lebs: list[dict] = []
    sections: list[dict] = []
    fatal: dict | None = None

    def add(f: Finding):
        findings.append(f.as_dict())

    if len(data) < 8 or data[0:4] != WASM_MAGIC:
        add(_finding("bad_magic", "module must begin with \\x00asm", 0,
                     min(4, len(data))))
        return _result(data, sections, findings, lebs,
                       {"code": "bad_magic", "at": 0})
    if data[4:8] != WASM_VERSION:
        add(_finding("unsupported_version",
                     "only wasm binary version 1 is understood", 4, 8,
                     candidates=[{"version_byte": list(data[4:8]),
                                  "decided": False}]))
        return _result(data, sections, findings, lebs,
                       {"code": "unsupported_version", "at": 4})

    pos = 8
    last_standard_id = 0
    seen_standard: set[int] = set()
    custom_ordinal = 0
    while pos < len(data):
        sec_start = pos
        sid = data[pos]
        id_end = pos + 1
        size_result = leb128.decode_u32(data, id_end)
        size_end = id_end + size_result.width
        if size_end > len(data):
            add(_finding("truncated",
                         "section size LEB128 runs past end of module",
                         id_end, min(size_end, len(data))))
            break
        lebs.append({"what": "section.size",
                     "range": byte_range(id_end, size_end),
                     **size_result.as_dict(),
                     "section_ordinal": len(sections)})
        size = size_result.value
        body_end = size_end + (size or 0)
        if size is None or body_end > len(data):
            add(_finding("section_size_overflow",
                         "declared section size runs past end of module",
                         id_end, size_end))
            break
        name = SECTION_NAMES.get(sid, f"unknown({sid})")
        section = {
            "ordinal": len(sections),
            "id": sid,
            "name": name,
            "id_range": byte_range(sec_start, id_end),
            "size_range": byte_range(id_end, size_end),
            "body_range": byte_range(size_end, body_end),
            "range": byte_range(sec_start, body_end),
            "size": size,
            "custom": sid == 0,
            "payload_preserved": True,
        }

        if sid == 0:
            custom_ordinal += 1
            section["custom_ordinal"] = custom_ordinal
            _parse_custom(data, size_end, body_end, section, add)
        elif sid not in SECTION_NAMES:
            add(_finding("unknown_section_id",
                         f"unknown standard section id {sid}", sec_start, id_end))
        else:
            if sid in seen_standard:
                add(_finding("duplicate_section",
                             f"section {name} (id={sid}) appears more than once",
                             sec_start, id_end,
                             candidates=[{"kept": "both-preserved",
                                          "decision": "invalid per spec"}]))
            if sid < last_standard_id:
                add(_finding("section_out_of_order",
                             f"section {name} (id={sid}) follows section id "
                             f"{last_standard_id}; standard sections must be "
                             "strictly ascending",
                             sec_start, id_end))
            seen_standard.add(sid)
            last_standard_id = max(last_standard_id, sid)
            try:
                _parse_section_body(sid, data, size_end, body_end, section,
                                    add, lebs, len(sections))
            except ParseError as exc:
                end = exc.end if exc.end is not None else exc.start
                add(_finding(exc.code, str(exc), exc.start or size_end,
                             end or size_end))
                section["fatal"] = {"code": exc.code, "message": str(exc)}
        sections.append(section)
        pos = body_end

    summary = _index_summary(sections)
    return _result(data, sections, findings, lebs, fatal, summary)


def _result(data, sections, findings, lebs, fatal, summary=None):
    standard = [s for s in sections if not s["custom"]]
    custom = [s for s in sections if s["custom"]]
    return {
        "byte_len": len(data),
        "sections": sections,
        "findings": findings,
        "leb_records": lebs,
        "fatal": fatal,
        "index_summary": summary or _index_summary(sections),
        "fidelity": {
            "custom_sections_preserved": len(custom),
            "standard_sections_preserved": len(standard),
            "raw_bytes_preserved": True,
        },
    }


def _parse_custom(data, body_start, body_end, section, add):
    cur = Cursor(data, body_start, body_end)
    try:
        cname, ns, ne, bad, _ = cur.name("custom")
    except ParseError as exc:
        add(_finding(exc.code, str(exc), exc.start or body_start,
                     exc.end or body_start, category="custom"))
        section["custom_name"] = ""
        section["name_range"] = byte_range(body_start, body_start)
    else:
        section["custom_name"] = cname
        section["name_range"] = byte_range(ns, ne)
        if bad:
            add(_finding("custom_name_utf8", bad, ns, ne, severity="warning",
                         category="custom"))
    # 自定义段原始 payload（含名字）逐字节保留：派生层不做规范化丢弃
    section["raw_payload_hex"] = data[body_start:body_end].hex()
    section["content_range"] = byte_range(cur.pos, body_end)


def _track_leb(lebs, section_ordinal, cur_start_ref, info):
    info["section_ordinal"] = section_ordinal
    lebs.append(info)


def _parse_section_body(sid, data, start, end, section, add, lebs, ordinal):
    cur = Cursor(data, start, end)

    def vec_count(what):
        value, info = cur.leb_u32(what)
        _track_leb(lebs, ordinal, start, info)
        if value is None:
            if info["out_of_range"]:
                add(_finding("leb_out_of_range",
                             f"{what}: integer too large for u32",
                             info["range"]["start"], info["range"]["end"],
                             category="leb"))
            if info["truncated"]:
                add(_finding("truncated", f"{what}: truncated LEB128",
                             info["range"]["start"], info["range"]["end"],
                             category="leb"))
            raise ParseError(f"unreadable {what} vector count",
                             info["range"]["start"], info["range"]["end"],
                             code="unrecoverable_leb")
        if info["noncanonical"]:
            add(_finding("leb_noncanonical",
                         f"{what}: non-canonical LEB128 (value {value} is "
                         "uniquely decodable; encoding defect, not overflow)",
                         info["range"]["start"], info["range"]["end"],
                         severity="warning", category="leb",
                         candidates=[{"interpreted_as": value,
                                      "rejected": "overflow-not-applicable"}]))
        return value, info

    if sid == 1:
        count, _ = vec_count("type.count")
        types = []
        for i in range(count):
            tstart = cur.pos
            form, fs, fe = cur.u8("type.form")
            if form != 0x60:
                raise ParseError(f"type {i}: expected functype 0x60", fs, fe,
                                 code="bad_type_form")
            np, _ = vec_count(f"type[{i}].param_count")
            params = []
            for j in range(np):
                b, bs, be = cur.u8(f"type[{i}].param[{j}]")
                params.append(_valtype(b, bs, be, add, f"type[{i}].param[{j}]"))
            nr, _ = vec_count(f"type[{i}].result_count")
            results = []
            for j in range(nr):
                b, bs, be = cur.u8(f"type[{i}].result[{j}]")
                results.append(_valtype(b, bs, be, add,
                                        f"type[{i}].result[{j}]"))
            types.append({"index": i, "range": byte_range(tstart, cur.pos),
                          "params": params, "results": results})
        section["types"] = types

    elif sid == 2:
        count, _ = vec_count("import.count")
        imports = []
        for i in range(count):
            istart = cur.pos
            mod, ms, me, mbad, _ = _cur_name(cur, add, f"import[{i}].module")
            nm, ns2, ne2, nbad, _ = _cur_name(cur, add, f"import[{i}].field")
            kind, ks, ke = cur.u8(f"import[{i}].kind")
            entry = {"index": i, "range": byte_range(istart, 0),
                     "module": mod, "field": nm,
                     "module_range": byte_range(ms, me),
                     "field_range": byte_range(ns2, ne2),
                     "kind_range": byte_range(ks, ke),
                     "kind": IMPORT_KIND.get(kind, f"unknown({kind})")}
            if kind == FUNC_TYPE_REF:
                ti, info = cur.leb_u32(f"import[{i}].typeidx")
                _track_leb(lebs, ordinal, start, info)
                entry["typeidx"] = ti
                entry["desc_range"] = info["range"]
                _leb_findings(ti, info, f"import[{i}].typeidx", add)
            else:
                _skip_import_desc(cur, kind, i, add, lebs, ordinal)
            entry["range"] = byte_range(istart, cur.pos)
            imports.append(entry)
        section["imports"] = imports

    elif sid == 3:
        count, _ = vec_count("function.count")
        funcs = []
        for i in range(count):
            vstart = cur.pos
            ti, info = cur.leb_u32(f"function[{i}].typeidx")
            _track_leb(lebs, ordinal, start, info)
            _leb_findings(ti, info, f"function[{i}].typeidx", add)
            funcs.append({"decl_index": i, "typeidx": ti,
                          "range": byte_range(vstart, cur.pos)})
        section["functions"] = funcs

    elif sid == 7:
        count, _ = vec_count("export.count")
        exports = []
        for i in range(count):
            estart = cur.pos
            nm, ns2, ne2, _, _ = _cur_name(cur, add, f"export[{i}].name")
            kind, ks, ke = cur.u8(f"export[{i}].kind")
            idx, info = cur.leb_u32(f"export[{i}].idx")
            _track_leb(lebs, ordinal, start, info)
            exports.append({"index": i, "range": byte_range(estart, cur.pos),
                            "name": nm, "kind": EXPORT_KIND.get(kind, "?"),
                            "ref_index": idx})
        section["exports"] = exports

    elif sid == 10:
        count, _ = vec_count("code.count")
        bodies = []
        for i in range(count):
            bstart = cur.pos
            bsize, info = cur.leb_u32(f"code[{i}].body_size")
            _track_leb(lebs, ordinal, start, info)
            _leb_findings(bsize, info, f"code[{i}].body_size", add)
            bend = cur.pos + (bsize or 0)
            if bend > end:
                raise ParseError(f"code body {i} overruns code section",
                                 cur.pos, end, code="truncated")
            bodies.append({"body_index": i,
                           "size_range": byte_range(bstart, cur.pos),
                           "range": byte_range(cur.pos, bend),
                           "body_size": bsize})
            cur.pos = bend
        section["bodies"] = bodies
    else:
        # table/memory/global/start/element/data/datacount：保留原始范围，
        # 本案例不逐字段展开，但字节不丢弃。
        section["raw_payload_hex"] = data[start:end].hex()


def _valtype(byte, start, end, add, where) -> dict:
    name = VALTYPE_NAMES.get(byte)
    if name is None:
        add(_finding("bad_valtype", f"{where}: unknown valtype 0x{byte:02x}",
                     start, end, category="type"))
        return {"byte": byte, "name": f"unknown(0x{byte:02x})",
                "range": byte_range(start, end)}
    valtype = {"byte": byte, "name": name, "range": byte_range(start, end)}
    if name in ("v128", "funcref", "externref"):
        valtype["requires"] = {"v128": "simd", "funcref": "reference_types",
                               "externref": "reference_types"}[name]
    return valtype


def _cur_name(cur, add, what):
    try:
        return cur.name(what)
    except ParseError as exc:
        add(_finding(exc.code, str(exc), exc.start or cur.pos,
                     exc.end or cur.pos, category="name"))
        return "", cur.pos, cur.pos, str(exc), None


def _leb_findings(value, info, what, add):
    r = info["range"]
    if info["out_of_range"]:
        add(_finding("leb_out_of_range",
                     f"{what}: integer too large for u32",
                     r["start"], r["end"], category="leb",
                     candidates=[{"rejected": "value-not-in-u32"}]))
    if info["truncated"]:
        add(_finding("truncated", f"{what}: truncated LEB128",
                     r["start"], r["end"], category="leb"))
    if info["noncanonical"]:
        add(_finding("leb_noncanonical",
                     f"{what}: non-canonical LEB128 encoding (value "
                     f"{value} uniquely decodable; encoding defect only)",
                     r["start"], r["end"], severity="warning", category="leb",
                     candidates=[{"interpreted_as": value,
                                  "note": "overflow must not be inferred"}]))


def _skip_import_desc(cur, kind, i, add, lebs, ordinal):
    """非函数 import（table/mem/global）：读掉描述符并保真记录。"""
    label = f"import[{i}]"
    if kind == 2:  # mem limits
        flags, fs, fe = cur.u8(f"{label}.limits.flags")
        cur.leb_u32(f"{label}.limits.min")
        if flags & LIMITS_HAS_MAX:
            cur.leb_u32(f"{label}.limits.max")
    elif kind == 1:  # table
        cur.u8(f"{label}.table.elemtype")
        cur.u8(f"{label}.table.limits.flags")
        cur.leb_u32(f"{label}.table.limits.min")
    elif kind == 3:  # global
        cur.u8(f"{label}.global.valtype")
        cur.u8(f"{label}.global.mut")
    else:
        raise ParseError(f"{label}: unknown import kind {kind}",
                         cur.pos - 1, cur.pos, code="bad_import_kind")


def _index_summary(sections: list[dict]) -> dict:
    """合并 import/function/code 得到统一函数索引空间及其来源。"""
    type_count = 0
    func_rows = []
    imported_funcs = 0
    code_count = 0
    function_decl_count = 0
    for s in sections:
        if s.get("id") == 1 and "types" in s:
            type_count = len(s["types"])
        elif s.get("id") == 2:
            for imp in s.get("imports", []):
                if imp["kind"] == "func":
                    func_rows.append({
                        "funcidx": len(func_rows),
                        "origin": "import",
                        "origin_ref": f"{imp['module']}.{imp['field']}",
                        "typeidx": imp.get("typeidx"),
                        "range": imp["range"],
                        "desc_range": imp.get("desc_range"),
                    })
            imported_funcs = len(func_rows)
        elif s.get("id") == 3:
            for fn in s.get("functions", []):
                func_rows.append({
                    "funcidx": imported_funcs + fn["decl_index"],
                    "origin": "defined",
                    "decl_index": fn["decl_index"],
                    "typeidx": fn.get("typeidx"),
                    "range": fn["range"],
                })
            function_decl_count = len(s.get("functions", []))
        elif s.get("id") == 10:
            code_count = len(s.get("bodies", []))
    return {
        "type_count": type_count,
        "imported_func_count": imported_funcs,
        "defined_func_count": function_decl_count,
        "code_body_count": code_count,
        "func_rows": func_rows,
        "decl_code_match": function_decl_count == code_count,
    }
