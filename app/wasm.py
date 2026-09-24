from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
import numpy as np

MAGIC = b"\x00asm"
VERSION = b"\x01\x00\x00\x00"
ALGORITHM_VERSION = "wasm-boundary-court/v1"

SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "data_count",
}

KNOWN_SECTIONS = set(SECTION_NAMES)
ORDERED_SECTIONS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
DEFAULT_PROPOSALS = {"multi_value": False, "reference_types": False, "sign_extension": False, "bulk_memory": False}

FEATURES_BY_OPCODE = {
    0xC0: "reference_types", 0xD0: "reference_types", 0xD1: "reference_types",
    0xD2: "bulk_memory", 0xFC0A: "bulk_memory", 0xFC0B: "bulk_memory",
    0xFC08: "bulk_memory", 0xFC09: "bulk_memory",
    0x20: None, 0x21: None, 0x22: None, 0x23: None, 0x24: None,
}
SIGN_EXTEND = {0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5A, 0x5C, 0x5E, 0x60, 0x62, 0x64, 0x66, 0x68, 0x6C, 0x6E, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7A, 0x7C}
SIMPLE_OPCODES = {
    0x00: ("unreachable", [], []), 0x01: ("nop", [], []), 0x0F: ("return", [], []),
    0x1A: ("drop", ["t"], []), 0x1B: ("select", ["t", "i32", "t"], ["t"]),
    0x41: ("i32.const", [], ["i32"]), 0x42: ("i64.const", [], ["i64"]),
    0x45: ("i32.eqz", ["i32"], ["i32"]), 0x6A: ("i32.add", ["i32", "i32"], ["i32"]),
    0x28: ("i32.load", ["i32"], ["i32"]), 0x36: ("i32.store", ["i32", "i32"], []),
}
CONTROL = {0x02: "block", 0x03: "loop", 0x04: "if", 0x05: "else", 0x0B: "end"}
CONST_OPCODES = {0x41: "i32", 0x42: "i64", 0x23: "global.get"}
VALUE_TYPES = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64", 0x70: "funcref", 0x6F: "externref"}
FUNC_TYPE = 0x60
REF_NULL = 0xD0
REF_FUNC = 0xD2
REF_IS_NULL = 0xD1
TABLE_GET = 0x25
TABLE_SET = 0x26

class Status(str, Enum):
    accepted = "accepted"
    rejected = "rejected"
    candidate = "candidate"
    unknown = "unknown"

@dataclass
class Span:
    start: int
    end: int
    label: str = ""
    def as_dict(self): return asdict(self)

@dataclass
class Finding:
    code: str
    status: str
    message: str
    span: Span
    source_id: str
    candidates: list[dict] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    def as_dict(self):
        d = asdict(self)
        d["span"] = self.span.as_dict()
        return d

@dataclass
class LebValue:
    kind: str
    value: int | None
    start: int
    end: int
    raw: list[int]
    canonical: bool
    overflow: bool
    error: str | None = None
    def as_dict(self):
        return asdict(self)

class Reader:
    def __init__(self, data: bytes, source_id: str, base: int = 0):
        self.data = data
        self.source_id = source_id
        self.pos = base
        self.base = base
        self.findings: list[Finding] = []
        self.leb_records: list[LebValue] = []

    def remaining(self): return len(self.data) + self.base - self.pos
    def span(self, start: int, label: str): return Span(start, self.pos, label)
    def byte(self, label: str) -> int | None:
        if self.pos >= self.base + len(self.data):
            self.findings.append(Finding("truncated_byte", Status.rejected.value, f"truncated while reading {label}", Span(self.pos, self.pos + 1, label), self.source_id))
            return None
        b = self.data[self.pos - self.base]
        self.pos += 1
        return b

    def bytes_value(self, n: int, label: str) -> bytes | None:
        if self.remaining() < n:
            start = self.pos
            self.findings.append(Finding("truncated_bytes", Status.rejected.value, f"truncated while reading {label}", Span(start, start + n, label), self.source_id))
            return None
        v = self.data[self.pos - self.base:self.pos - self.base + n]
        self.pos += n
        return v

    def u32leb(self, label: str, limit: int | None = None) -> tuple[int | None, LebValue]:
        start = self.pos
        result = 0; shift = 0; raw = []; canonical = True; overflow = False
        for idx in range(5):
            b = self.byte(f"{label} LEB byte {idx}")
            if b is None: break
            raw.append(b); chunk = b & 0x7F
            if idx < 4 and chunk == 0 and idx > 0:
                canonical = False
            if idx == 4:
                if chunk & 0xF0:
                    overflow = True
                if chunk in (0, 0x7F) and raw[-2] & 0x40 == (0 if chunk == 0 else 1):
                    pass
                elif b & 0x80:
                    canonical = False
            result |= chunk << shift
            shift += 7
            if not b & 0x80:
                if idx < 4:
                    # Unsigned LEB is non-minimal when a non-final byte adds no bits.
                    if idx > 0 and chunk == 0:
                        canonical = False
                break
        else:
            b = self.byte(f"{label} excess LEB byte")
            if b is not None:
                raw.append(b); canonical = False
        if raw and raw[-1] & 0x80:
            self.findings.append(Finding("leb_unterminated", Status.rejected.value, f"{label} LEB128 has no terminating byte", Span(start, self.pos, label), self.source_id))
        if not canonical:
            self.findings.append(Finding("noncanonical_leb", Status.candidate.value, f"{label} uses a non-canonical LEB128 encoding", Span(start, self.pos, label), self.source_id, evidence={"raw": raw}))
        if overflow:
            self.findings.append(Finding("value_out_of_bounds", Status.rejected.value, f"{label} LEB128 value exceeds u32", Span(start, self.pos, label), self.source_id, evidence={"raw": raw}))
        rec = LebValue("u32", None if overflow else result & 0xFFFFFFFF, start, self.pos, raw, canonical, overflow)
        self.leb_records.append(rec)
        return rec.value, rec

    def s32leb(self, label: str):
        return self.u32leb(label)[0]

    def name(self, label: str) -> tuple[str | None, Span]:
        start = self.pos
        n, _ = self.u32leb(f"{label} byte length")
        if n is None: return None, self.span(start, label)
        raw = self.bytes_value(n, label)
        if raw is None: return None, self.span(start, label)
        try: return raw.decode("utf-8"), self.span(start, label)
        except UnicodeDecodeError:
            self.findings.append(Finding("invalid_utf8", Status.rejected.value, f"{label} is not UTF-8", Span(start, self.pos, label), self.source_id, evidence={"raw_hex": raw.hex()}))
            return raw.decode("utf-8", "replace"), self.span(start, label)

    def types(self, count_label: str):
        count, _ = self.u32leb(count_label)
        out = []
        for i in range(count or 0):
            b = self.byte(f"value type {i}")
            if b is None: break
            if b == FUNC_TYPE:
                out.append([])
            elif b in VALUE_TYPES:
                out.append(VALUE_TYPES[b])
            else:
                self.findings.append(Finding("unknown_value_type", Status.rejected.value, f"unknown value type 0x{b:02x}", Span(self.pos - 1, self.pos, "value type"), self.source_id))
                out.append(f"unknown:0x{b:02x}")
        return out

@dataclass
class Section:
    stable_id: str
    section_id: int
    name: str
    start: int
    end: int
    payload_start: int
    payload_end: int
    size_value: int | None
    size_leb: dict
    order: int
    custom_name: str | None = None
    retained: bool = True
    def as_dict(self): return asdict(self)


def _rec(kind, index, name, span, source_id, **extra):
    d = {"stable_id": f"{kind}:{index}", "kind": kind, "index": index, "name": name,
         "span": span.as_dict(), "source_id": source_id}
    d.update(extra)
    return d


def parse_module(data: bytes, source_id="source.binary", proposals=None) -> dict:
    proposals = {**DEFAULT_PROPOSALS, **(proposals or {})}
    r = Reader(data, source_id)
    header_span = Span(0, min(8, len(data)), "wasm header")
    header_ok = data.startswith(MAGIC + VERSION)
    if data[:4] != MAGIC:
        r.findings.append(Finding("bad_magic", Status.rejected.value, "WebAssembly magic is not 00 61 73 6d", Span(0, min(4, len(data)), "magic"), source_id))
    if len(data) >= 8 and data[4:8] != VERSION:
        r.findings.append(Finding("unsupported_version", Status.rejected.value, "unsupported binary version", Span(4, 8, "version"), source_id, candidates=[{"version": 1, "status": "accepted"}]))
    r.pos = 8
    sections: list[Section] = []
    order_seen: dict[int, int] = {}
    last_standard = 0
    order = 0
    while r.remaining() > 0 and header_ok:
        start = r.pos
        sid_b = r.byte("section id")
        if sid_b is None: break
        sid = sid_b
        size, size_leb = r.u32leb("section size")
        payload_start = r.pos
        payload_end = payload_start + (size or 0)
        if size is None or payload_end > r.base + len(data):
            r.findings.append(Finding("section_payload_out_of_bounds", Status.rejected.value, "section size exceeds byte range", Span(start, max(payload_start, min(payload_end, r.base + len(data))), "section"), source_id))
            break
        custom_name = None
        if sid == 0:
            nr = Reader(data[payload_start - r.base:payload_end - r.base], source_id, payload_start)
            custom_name, _ = nr.name("custom section name")
            r.findings.extend(nr.findings)
        sec = Section(f"section:ord{order}:id{sid}", sid, SECTION_NAMES.get(sid, "unknown"), start, payload_end,
                      payload_start, payload_end, size, size_leb.as_dict(), order, custom_name, True)
        if sid not in KNOWN_SECTIONS:
            r.findings.append(Finding("unknown_section", Status.rejected.value, f"unknown section id {sid}", Span(start, start + 1, "section id"), source_id))
        if sid != 0:
            if sid in order_seen:
                r.findings.append(Finding("duplicate_section", Status.rejected.value, f"section {sec.name} appears more than once", Span(start, payload_end, sec.name), source_id, evidence={"first_order": order_seen[sid]}))
            if sid < last_standard:
                r.findings.append(Finding("section_out_of_order", Status.rejected.value, f"section {sec.name} is out of order", Span(start, payload_end, sec.name), source_id, evidence={"previous_standard_id": last_standard}))
            order_seen.setdefault(sid, order)
            last_standard = max(last_standard, sid)
        sections.append(sec)
        r.pos = payload_end
        order += 1
    parsed = _parse_sections(data, source_id, sections, proposals)
    all_findings = [f.as_dict() if isinstance(f, Finding) else f for f in r.findings]
    all_findings.extend(f.as_dict() if isinstance(f, Finding) else f for f in parsed["findings"])
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "source_id": source_id,
        "header": {"span": header_span.as_dict(), "magic_hex": data[:4].hex(), "version_bytes": list(data[4:8]), "accepted": header_ok},
        "byte_length": len(data),
        "sections": [s.as_dict() for s in sections],
        "leb128": [x.as_dict() for x in r.leb_records] + parsed.pop("section_leb", []),
        "records": parsed["records"],
        "index_spaces": parsed["index_spaces"],
        "import_contract": parsed["import_contract"],
        "functions": parsed["functions"],
        "findings": all_findings,
        "proposals": proposals,
    }


def _section_reader(data, source_id, sec):
    return Reader(data[sec["payload_start"]:sec["payload_end"]], source_id, sec["payload_start"])


def _parse_sections(data, source_id, sections: list[Section], proposals):
    section_dicts = [s.as_dict() for s in sections]
    records = []
    findings = []
    section_leb = []
    types = []
    imports = []
    funcs = []
    funcs_by_idx = {"import": [], "defined": []}
    exports = []
    code_by_func = {}
    for sec in section_dicts:
        if sec["section_id"] not in (1, 2, 3, 7, 10):
            continue
        r = _section_reader(data, source_id, sec)
        section_leb.extend(x.as_dict() for x in r.leb_records)
        count, _ = r.u32leb(f"{sec['name']} count")
        if sec["section_id"] == 1:
            for i in range(count or 0):
                start = r.pos
                tag = r.byte("func type tag")
                params, results = [], []
                if tag == FUNC_TYPE:
                    params = r.types("type parameter count")
                    results = r.types("type result count")
                    if len(results) > 1 and not proposals.get("multi_value"):
                        findings.append(Finding("capability_missing", Status.rejected.value, "multi-value result requires enabled multi_value proposal", Span(start, r.pos, "func type"), source_id, evidence={"proposal": "multi_value", "opcode": "func_type"}))
                    types.append({"params": params, "results": results})
                    records.append(_rec("type", i, f"type {i}: ({','.join(map(str, params))}) -> ({','.join(map(str, results))})", Span(start, r.pos, "type entry"), source_id, params=params, results=results, section_order=sec["order"]))
                else:
                    findings.append(Finding("invalid_type_form", Status.rejected.value, "type entry does not use func form 0x60", Span(start, r.pos, "type form"), source_id))
        elif sec["section_id"] == 2:
            for i in range(count or 0):
                start = r.pos
                module, _ = r.name("import module")
                name, _ = r.name("import name")
                kind = r.byte("import kind")
                desc = None; type_index = None
                if kind == 0:
                    type_index, _ = r.u32leb("import function type index")
                    if type_index is not None and type_index >= len(types):
                        findings.append(Finding("index_out_of_bounds", Status.rejected.value, "import function type index is out of bounds", Span(start, r.pos, "import"), source_id, evidence={"index": type_index, "space_size": len(types), "index_space": "type"}))
                    desc = {"kind": "function", "type_index": type_index}
                    funcs_by_idx["import"].append({"module": module, "name": name, "type_index": type_index})
                elif kind == 1:
                    et = r.byte("table element type"); flags = r.byte("table limits flag")
                    minimum, _ = r.u32leb("table minimum"); maximum = None
                    if flags and flags & 1: maximum, _ = r.u32leb("table maximum")
                    desc = {"kind": "table", "element_type": VALUE_TYPES.get(et, f"0x{et:02x}"), "min": minimum, "max": maximum}
                    if et in (0x70, 0x6F) and not proposals.get("reference_types"):
                        findings.append(Finding("capability_missing", Status.rejected.value, "reference types require enabled reference_types proposal", Span(start, r.pos, "table import"), source_id, evidence={"proposal": "reference_types"}))
                elif kind == 2:
                    flags = r.byte("memory limits flag"); minimum, _ = r.u32leb("memory minimum"); maximum = None
                    if flags and flags & 1: maximum, _ = r.u32leb("memory maximum")
                    desc = {"kind": "memory", "min": minimum, "max": maximum}
                elif kind == 3:
                    vt = r.byte("global value type"); mut = r.byte("global mutability")
                    desc = {"kind": "global", "value_type": VALUE_TYPES.get(vt, f"0x{vt:02x}"), "mutable": bool(mut)}
                else:
                    findings.append(Finding("unknown_import_kind", Status.rejected.value, f"unknown import kind {kind}", Span(start, r.pos, "import kind"), source_id))
                imports.append({"module": module, "name": name, "desc": desc})
                records.append(_rec("import", i, f"{module}.{name}", Span(start, r.pos, "import entry"), source_id, desc=desc, section_order=sec["order"]))
        elif sec["section_id"] == 3:
            for i in range(count or 0):
                start = r.pos
                type_index, _ = r.u32leb("defined function type index")
                if type_index is not None and type_index >= len(types):
                    findings.append(Finding("index_out_of_bounds", Status.rejected.value, "defined function type index is out of bounds", Span(start, r.pos, "function"), source_id, evidence={"index": type_index, "space_size": len(types), "index_space": "type"}))
                funcs.append(type_index)
                funcs_by_idx["defined"].append({"type_index": type_index})
                records.append(_rec("function", len(funcs_by_idx["import"]) + i, f"function {len(funcs_by_idx['import']) + i}", Span(start, r.pos, "function entry"), source_id, type_index=type_index, section_order=sec["order"]))
        elif sec["section_id"] == 7:
            for i in range(count or 0):
                start = r.pos; name, _ = r.name("export name"); kind = r.byte("export kind"); idx, _ = r.u32leb("export index")
                exports.append({"name": name, "kind": kind, "index": idx})
                records.append(_rec("export", i, name, Span(start, r.pos, "export entry"), source_id, kind=kind, index=idx, section_order=sec["order"]))
        elif sec["section_id"] == 10:
            for i in range(count or 0):
                fidx = len(funcs_by_idx["import"]) + i
                start = r.pos
                body_size, _ = r.u32leb("function body size")
                end = r.pos + (body_size or 0)
                code_by_func[fidx] = {"start": r.pos, "declared_end": end, "body_size": body_size}
                if body_size is None or end > sec["payload_end"]:
                    findings.append(Finding("function_body_out_of_bounds", Status.rejected.value, "function body exceeds code section", Span(start, min(end, sec["payload_end"]), "function body"), source_id))
                    break
                r.pos = end
        findings.extend(f.as_dict() if isinstance(f, Finding) else f for f in r.findings)
        section_leb.extend(x.as_dict() for x in r.leb_records)
    validations = _validate_functions(data, source_id, types, funcs_by_idx, code_by_func, proposals, [s.as_dict() for s in sections])
    return {"records": records + validations["records"], "index_spaces": _index_spaces(types, funcs_by_idx, imports, exports),
            "import_contract": {"required": imports}, "functions": validations["functions"], "findings": findings + validations["findings"], "section_leb": section_leb + validations["body_leb"]}

def _index_spaces(types, funcs_by_idx, imports, exports):
    imported_funcs = funcs_by_idx["import"]
    defined = funcs_by_idx["defined"]
    function_sources = []
    for i, detail in enumerate(imported_funcs):
        function_sources.append({"index": i, "origin": "import", "source_id": "source.binary", "detail": detail})
    for i, detail in enumerate(defined):
        function_sources.append({"index": len(imported_funcs) + i, "origin": "defined", "source_id": "source.binary", "detail": detail})
    return {
        "type": {"size": len(types), "sources": [{"index": i, "source_id": "source.binary", "space": "type"} for i in range(len(types))]},
        "function": {"size": len(function_sources), "sources": function_sources},
        "import": {"size": len(imports), "sources": [{"index": i, "source_id": "source.binary"} for i in range(len(imports))]},
        "export": {"size": len(exports), "sources": [{"index": i, "source_id": "source.binary"} for i in range(len(exports))]},
    }


def _read_locals(r: Reader):
    local_count, _ = r.u32leb("local declaration group count")
    locals_ = []
    for _ in range(local_count or 0):
        n, _ = r.u32leb("local count")
        vt = r.byte("local value type")
        typ = VALUE_TYPES.get(vt, f"unknown:0x{vt:02x}") if vt is not None else "unknown"
        locals_.extend([typ] * (n or 0))
    return locals_


def _validate_functions(data, source_id, types, funcs_by_idx, code_by_func, proposals, sections):
    findings = []
    records = []
    funcs_out = []
    imported = funcs_by_idx["import"]
    for fidx, loc in code_by_func.items():
        rel = fidx - len(imported)
        if rel < 0 or rel >= len(funcs_by_idx["defined"]):
            continue
        type_index = funcs_by_idx["defined"][rel].get("type_index")
        ftype = types[type_index] if isinstance(type_index, int) and type_index < len(types) else {"params": [], "results": []}
        r = Reader(data, source_id, 0); r.pos = loc["start"]
        locals_ = _read_locals(r)
        params = list(ftype.get("params", []))
        results = list(ftype.get("results", []))
        ctx = FunctionContext(fidx, type_index, params + locals_, results, source_id, proposals, types, funcs_by_idx)
        ctx.stack.extend(params)
        end = loc["declared_end"]
        while r.pos < end:
            start = r.pos
            opcode = r.byte("opcode")
            if opcode is None: break
            consumed_ok = _step_instruction(opcode, r, ctx, start, end)
            ctx.records.append({"function_index": fidx, "stable_id": f"instr:func{fidx}:offset{start}", "kind": "instruction",
                                "index": len(ctx.records), "name": ctx.last_name, "opcode": opcode,
                                "span": {"start": start, "end": r.pos, "label": ctx.last_name},
                                "source_id": source_id, "input": ctx.last_input,
                                "output": ctx.last_output, "polymorphic": ctx.last_poly,
                                "stack_after": list(ctx.stack), "control_depth": len(ctx.blocks),
                                "status": "accepted" if consumed_ok else "rejected"})
            if not consumed_ok and not ctx.blocks:
                break
        while ctx.blocks:
            blk = ctx.blocks.pop()
            ctx.records.append({"function_index": fidx, "stable_id": f"implicit-end:func{fidx}:offset{blk['start']}", "kind": "control",
                                "index": len(ctx.records), "name": "implicit end", "span": {"start": end, "end": end, "label": "implicit end"},
                                "source_id": source_id, "status": "rejected", "message": "block has no end opcode"})
            findings.append(Finding("unterminated_block", Status.rejected.value, "control block has no end", Span(blk["start"], end, "block"), source_id))
        got = [x for x in ctx.stack if x != "polymorphic"]
        had_unreachable = any((x.code if isinstance(x, Finding) else x.get("code")) == "unreachable_stack" for x in ctx.findings)
        if got != results and not had_unreachable:
            findings.append(Finding("type_stack_mismatch", Status.rejected.value, "function result stack does not match declared result types",
                                    Span(loc["start"], loc["declared_end"], "function stack"), source_id,
                                    candidates=[{"got": got, "expected": results, "status": "rejected"}]))
        findings.extend(r.findings)
        findings.extend(ctx.findings)
        records.extend(ctx.records)
        funcs_out.append({"function_index": fidx, "type_index": type_index, "params": params, "locals": locals_,
                          "results": results, "control_stack": ctx.block_history, "type_transfers": [x for x in ctx.records if x.get("kind") == "instruction"],
                          "final_stack": got, "span": {"start": loc["start"], "end": loc["declared_end"], "label": f"function {fidx} body"}})
    body_leb = []
    return {"findings": [f.as_dict() for f in findings], "records": records, "functions": funcs_out, "body_leb": body_leb}


@dataclass
class FunctionContext:
    function_index: int
    type_index: int | None
    locals: list[str]
    results: list[str]
    source_id: str
    proposals: dict
    types: list
    funcs_by_idx: dict
    stack: list[str] = field(default_factory=list)
    blocks: list[dict] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    records: list[dict] = field(default_factory=list)
    block_history: list[dict] = field(default_factory=list)
    last_name = ""
    last_input: list[str] = field(default_factory=list)
    last_output: list[str] = field(default_factory=list)
    last_poly = False


def _pop_expected(ctx: FunctionContext, expected, span: Span, opcode_name: str):
    if ctx.blocks and ctx.blocks[-1].get("unreachable") and not ctx.stack:
        ctx.last_poly = True
        return []
    reverse = list(expected)
    reverse.reverse()
    consumed = []
    for want in reverse:
        if ctx.blocks and ctx.blocks[-1].get("unreachable") and ctx.stack and ctx.stack[-1] == "polymorphic":
            ctx.last_poly = True
            continue
        if not ctx.stack:
            ctx.findings.append(Finding("unreachable_stack" if ctx.blocks and ctx.blocks[-1].get("unreachable") else "type_stack_underflow",
                                        Status.rejected.value if not (ctx.blocks and ctx.blocks[-1].get("unreachable")) else Status.candidate.value,
                                        f"{opcode_name} expected {want} on an unreachable/empty stack", span, ctx.source_id,
                                        candidates=[{"expected": want, "state": "polymorphic" if ctx.blocks and ctx.blocks[-1].get("unreachable") else "underflow"}]))
            return None
        got = ctx.stack.pop()
        if got == "polymorphic":
            ctx.last_poly = True
            continue
        if want != "t" and got != want:
            ctx.findings.append(Finding("type_mismatch", Status.rejected.value, f"{opcode_name} expected {want}, got {got}", span, ctx.source_id,
                                        candidates=[{"expected": want, "got": got, "status": "rejected"}]))
            return None
        consumed.append(got)
    consumed.reverse()
    return consumed


def _check_feature(ctx, opcode, span, subopcode=None):
    feature = FEATURES_BY_OPCODE.get(opcode)
    if opcode == 0xFC and subopcode in (8, 9, 10, 11):
        feature = "bulk_memory"
    if opcode in SIGN_EXTEND:
        feature = "sign_extension"
    if feature and not ctx.proposals.get(feature):
        ctx.findings.append(Finding("capability_missing", Status.rejected.value, f"opcode requires disabled proposal {feature}", span, ctx.source_id,
                                    evidence={"opcode": opcode, "subopcode": subopcode, "proposal": feature}))
        return False
    return True


def _known(opcode, subopcode=None):
    if opcode in SIMPLE_OPCODES or opcode in CONTROL or opcode in (0x10, 0x20, 0x21, 0x22, 0x23, 0x24, TABLE_GET, TABLE_SET, REF_NULL, REF_IS_NULL, 0x1A, 0x1B) or opcode in SIMPLE_OPCODES:
        return True
    if opcode == 0xFC:
        return subopcode in (8, 9, 10, 11)
    return opcode in FEATURES_BY_OPCODE

def _step_instruction(opcode, r: Reader, ctx: FunctionContext, start, end) -> bool:
    span = Span(start, r.pos, "opcode")
    ctx.last_name = f"unknown 0x{opcode:02x}"
    ctx.last_input = []
    ctx.last_output = []
    ctx.last_poly = False
    subopcode = None
    if opcode == 0xFC:
        subopcode, _ = r.u32leb("0xFC subopcode")
    known = _known(opcode, subopcode)
    if not known:
        ctx.findings.append(Finding("unknown_byte", Status.rejected.value, f"unknown opcode byte 0x{opcode:02x}", Span(start, start + 1, "unknown opcode"), ctx.source_id))
        return False
    if not _check_feature(ctx, opcode, Span(start, start + 1, "capability gate"), subopcode):
        ctx.last_name = f"disabled 0x{opcode:02x}"
        return False
    if opcode in (0x02, 0x03, 0x04):
        name = CONTROL[opcode]
        bt = r.byte("block type")
        inputs, outputs = [], []
        if bt == FUNC_TYPE:
            inputs, outputs = [], []
        elif bt in VALUE_TYPES:
            outputs = [VALUE_TYPES[bt]]
        elif bt is not None:
            type_index, _ = r.u32leb("block type index")
            if type_index is not None and type_index < len(ctx.types):
                inputs = list(ctx.types[type_index]["params"]); outputs = list(ctx.types[type_index]["results"])
        if len(outputs) > 1 and not ctx.proposals.get("multi_value"):
            ctx.findings.append(Finding("capability_missing", Status.rejected.value, "multi-value block output requires multi_value proposal", Span(start, r.pos, name), ctx.source_id, evidence={"proposal": "multi_value"}))
            return False
        consumed = _pop_expected(ctx, inputs, Span(start, r.pos, name), name)
        if consumed is None: return False
        blk = {"start": start, "kind": name, "inputs": inputs, "outputs": outputs, "stack_height": len(ctx.stack), "unreachable": False}
        ctx.blocks.append(blk); ctx.block_history.append(dict(blk, event="enter", span={"start": start, "end": r.pos}))
        ctx.stack.extend(outputs)
        ctx.last_name = name; ctx.last_input = consumed; ctx.last_output = outputs
        return True
    if opcode == 0x05:
        if not ctx.blocks:
            ctx.findings.append(Finding("else_without_block", Status.rejected.value, "else outside if", Span(start, start + 1, "else"), ctx.source_id)); return False
        blk = ctx.blocks[-1]
        ctx.stack = ctx.stack[:blk["stack_height"]]
        ctx.stack.extend(blk["outputs"])
        blk["unreachable"] = False
        ctx.last_name = "else"; ctx.block_history.append({"event": "else", "start": start, "kind": blk["kind"]})
        return True
    if opcode == 0x0B:
        if not ctx.blocks:
            ctx.last_name = "function_end"
            ctx.last_input = list(ctx.stack)
            ctx.last_output = list(ctx.results)
            ctx.block_history.append({"event": "function_exit", "start": start, "kind": "function"})
            return True
        blk = ctx.blocks.pop()
        expected = blk["outputs"]
        if blk.get("unreachable"):
            while ctx.stack and ctx.stack[-1] == "polymorphic": ctx.stack.pop()
        got = ctx.stack[blk["stack_height"]:]
        if got != expected:
            candidates = _stack_candidates(got, expected)
            ctx.findings.append(Finding("block_type_mismatch", Status.rejected.value, "block termination stack does not match block type", Span(blk["start"], start + 1, "block"), ctx.source_id, candidates=candidates))
            return False
        ctx.stack = ctx.stack[:blk["stack_height"]] + expected
        ctx.last_name = "end"; ctx.last_input = got; ctx.last_output = expected
        ctx.block_history.append({"event": "exit", "start": start, "block_start": blk["start"], "kind": blk["kind"]})
        return True
    if opcode == 0x00:
        ctx.last_name = "unreachable"
        ctx.stack = ctx.stack[:ctx.blocks[-1]["stack_height"]] if ctx.blocks else []
        ctx.stack.append("polymorphic")
        if ctx.blocks: ctx.blocks[-1]["unreachable"] = True
        ctx.findings.append(Finding("unreachable_stack", Status.candidate.value, "polymorphic stack begins at unreachable; later mismatches are bounded to this region", Span(start, start + 1, "unreachable"), ctx.source_id, candidates=[{"state": "polymorphic", "scope": "current block"}]))
        ctx.last_output = ["polymorphic"]
        return True
    if opcode == 0x10:
        type_index, _ = r.u32leb("call type index")
        if not isinstance(type_index, int) or type_index >= len(ctx.types):
            ctx.findings.append(Finding("index_out_of_bounds", Status.rejected.value, "call type index is out of bounds", Span(start, r.pos, "call"), ctx.source_id, evidence={"index": type_index, "space": "type"})); return False
        ftype = ctx.types[type_index]
        consumed = _pop_expected(ctx, ftype["params"], Span(start, r.pos, "call"), "call")
        if consumed is None: return False
        ctx.stack.extend(ftype["results"])
        ctx.last_name = "call"; ctx.last_input = consumed; ctx.last_output = list(ftype["results"])
        return True
    if opcode in (0x20, 0x21):
        idx, _ = r.u32leb("local index")
        if not isinstance(idx, int) or idx >= len(ctx.locals):
            ctx.findings.append(Finding("index_out_of_bounds", Status.rejected.value, "local index is out of bounds", Span(start, r.pos, "local"), ctx.source_id, evidence={"index": idx, "space_size": len(ctx.locals)})); return False
        name = "local.get" if opcode == 0x20 else "local.set"
        typ = ctx.locals[idx]
        if opcode == 0x20:
            ctx.stack.append(typ); ctx.last_output = [typ]
        else:
            consumed = _pop_expected(ctx, [typ], Span(start, r.pos, name), name)
            if consumed is None: return False
            ctx.last_input = consumed
        ctx.last_name = name
        return True
    if opcode in (0x22, 0x23, 0x24):
        idx, _ = r.u32leb("global index")
        name = {0x22: "global.get", 0x23: "global.set", 0x24: "global.tee"}[opcode]
        ctx.findings.append(Finding("global_type_unavailable", Status.unknown.value, "global type cannot be uniquely determined because global section is absent from this small sample", Span(start, r.pos, name), ctx.source_id, candidates=[{"type": "i32", "status": "candidate"}, {"type": "i64", "status": "candidate"}]))
        return True
    if opcode == REF_NULL:
        rb = r.byte("ref.null type"); ctx.stack.append("funcref" if rb == 0x70 else "externref"); ctx.last_name = "ref.null"; ctx.last_output = [ctx.stack[-1]]; return True
    if opcode == REF_IS_NULL:
        consumed = _pop_expected(ctx, ["t"], Span(start, start + 1, "ref.is_null"), "ref.is_null")
        if consumed is None: return False
        ctx.stack.append("i32"); ctx.last_name = "ref.is_null"; ctx.last_input = consumed; ctx.last_output = ["i32"]; return True
    if opcode == 0x0F:
        consumed = _pop_expected(ctx, ctx.results, Span(start, start + 1, "return"), "return")
        if consumed is None: return False
        if ctx.blocks: ctx.blocks[-1]["unreachable"] = True
        ctx.stack = ["polymorphic"]
        ctx.last_name = "return"; ctx.last_input = consumed; ctx.last_output = ["polymorphic"]
        return True
    if opcode in SIMPLE_OPCODES:
        name, inputs, output_template = SIMPLE_OPCODES[opcode]
        types_for_input = [_instantiate(x, ctx.stack) for x in inputs]
        consumed = _pop_expected(ctx, types_for_input, Span(start, start + 1, name), name)
        if consumed is None: return False
        outputs = [consumed[0] if x == "t" else x for x in output_template]
        ctx.stack.extend(outputs)
        ctx.last_name = name; ctx.last_input = consumed; ctx.last_output = outputs
        return True
    ctx.findings.append(Finding("unknown_byte", Status.rejected.value, f"unimplemented known opcode 0x{opcode:02x}", Span(start, start + 1, "opcode"), ctx.source_id))
    return False


def _instantiate(token, stack):
    if token != "t": return token
    for x in reversed(stack):
        if x != "polymorphic": return x
    return "t"


def _stack_candidates(got, expected):
    if len(got) == len(expected):
        return [{"got": got, "expected": expected, "status": "rejected", "reason": "type differs at first unequal position"}]
    return [{"got": got, "expected": expected, "status": "rejected", "reason": "stack arity differs"},
            {"repair": "pop_or_push_until_arity", "status": "candidate", "note": "legal alternatives retained because repair is not uniquely determined"}]


def compare_import_contract(parsed_contract: dict, host_contract: dict) -> list[dict]:
    required = {(x.get("module"), x.get("name")): x.get("desc") for x in parsed_contract.get("required", [])}
    provided = {(x.get("module"), x.get("name")): x.get("desc") for x in host_contract.get("imports", [])}
    findings = []
    for key, desc in required.items():
        if key not in provided:
            findings.append({"code": "import_missing", "status": "rejected", "message": f"host does not provide {key[0]}.{key[1]}", "evidence": {"required": desc, "host": None}})
        elif provided[key] != desc:
            findings.append({"code": "import_mismatch", "status": "rejected", "message": f"host signature for {key[0]}.{key[1]} differs",
                            "candidates": [{"required": desc, "status": "rejected"}, {"host": provided[key], "status": "accepted"}]})
    for key, desc in provided.items():
        if key not in required:
            findings.append({"code": "import_unused", "status": "candidate", "message": f"host provides unused import {key[0]}.{key[1]}", "evidence": {"host": desc}})
    return findings


def finding_minimum_span(finding: dict, sections: list[dict]) -> dict:
    span = finding.get("span") or {"start": 0, "end": 0}
    start, end = span.get("start", 0), span.get("end", span.get("start", 0))
    return {"start": int(start), "end": int(max(start, end)), "label": span.get("label", finding.get("code", "failure")),
            "byte_range_hex": None, "reason": finding.get("message", "")}
