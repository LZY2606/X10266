"""WebAssembly module validator with first-class findings, candidates and
stable identities.

Design rules implemented here (domain requirements):

* 不规范 LEB128 与数值越界分开 — NONCANONICAL vs VALUE_OUT_OF_RANGE findings.
* polymorphic stack 只在 unreachable 区域生效 — the value stack becomes
  polymorphic only after `unreachable`/`br`/`return` inside the current
  control frame; outside, underflow is a hard STACK_MISMATCH.
* 未启用 proposal 的 opcode 报能力缺失而非未知字节 — CAPABILITY_MISSING
  carries (feature, proposal); only genuinely unassigned bytes are
  UNKNOWN_BYTE.
* 候选、拒绝原因、未知状态都是一等数据 — Candidate records with options and
  rejection reasons, Unknown markers, all with stable ids.
* 最小失败字节范围 — every finding carries the smallest byte range that
  proves the failure.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict

from .capabilities import (
    PROPOSALS, VALTYPE, classify_single, classify_fc, classify_fd,
)
from .leb128 import decode_uleb, decode_sleb

ALGORITHM_VERSION = "wasmvc-validator/1.3.0"

SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "datacount",
}
# canonical order rank; custom sections may appear anywhere
ORDER_RANK = {1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8, 9: 9,
              12: 10, 10: 11, 11: 12}

OPCODE_NAMES = {
    0x00: "unreachable", 0x01: "nop", 0x02: "block", 0x03: "loop",
    0x04: "if", 0x05: "else", 0x0B: "end", 0x0C: "br", 0x0D: "br_if",
    0x0E: "br_table", 0x0F: "return", 0x10: "call", 0x11: "call_indirect",
    0x1A: "drop", 0x1B: "select", 0x1C: "select_t",
    0x20: "local.get", 0x21: "local.set", 0x22: "local.tee",
    0x23: "global.get", 0x24: "global.set",
    0x25: "table.get", 0x26: "table.set",
    0x41: "i32.const", 0x42: "i64.const", 0x43: "f32.const", 0x44: "f64.const",
    0xD0: "ref.null", 0xD1: "ref.is_null", 0xD2: "ref.func",
    0xFC: "prefix.fc", 0xFD: "prefix.fd",
}
for _op in range(0x28, 0x41):
    OPCODE_NAMES.setdefault(_op, f"mem.{_op:#04x}")
for _op in range(0x45, 0xC0):
    OPCODE_NAMES.setdefault(_op, f"num.{_op:#04x}")


def stable_id(kind: str, *parts: object) -> str:
    h = hashlib.sha1()
    h.update(kind.encode())
    for part in parts:
        h.update(b"\x1f")
        h.update(str(part).encode())
    return f"{kind}-{h.hexdigest()[:16]}"


def params_fingerprint(features: dict[str, bool], host_contract: dict) -> str:
    blob = json.dumps(
        {"features": features, "host": host_contract, "algo": ALGORITHM_VERSION},
        sort_keys=True, separators=(",", ":"),
    )
    return "fp-" + hashlib.sha1(blob.encode()).hexdigest()[:16]


@dataclass
class Finding:
    id: str
    kind: str
    severity: str  # error | warning | info
    message: str
    byte_start: int
    byte_end: int
    subject: str            # stable identity of what the finding is about
    source: str             # direct source identity (section/field path)
    status: str = "open"    # open | adopted | rejected
    rejection_reason: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Candidate:
    id: str
    subject: str
    question: str
    options: list[str]
    byte_start: int
    byte_end: int
    source: str
    status: str = "open"          # open | adopted | rejected
    adopted: str | None = None
    rejection_reason: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Unknown:
    id: str
    subject: str
    reason: str
    byte_start: int
    byte_end: int
    source: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class SectionRecord:
    ordinal: int
    id: str
    section_id: int
    name: str
    size: int
    start: int
    end: int
    size_leb_start: int
    size_leb_end: int
    order_ok: bool
    duplicate_of: int | None
    custom_name: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class IndexEntry:
    id: str
    space: str          # type | func | table | mem | global | local
    index: int
    origin: str         # import | defined | param | local
    desc: str
    byte_start: int
    byte_end: int

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class TypeTransition:
    id: str
    func_index: int
    pc: int
    opcode: str
    stack_before: list[str]
    stack_after: list[str]
    control_depth: int
    polymorphic: bool

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class ControlFrame:
    opcode: str
    start_types: list[str]
    end_types: list[str]
    height: int
    unreachable: bool
    pc: int


@dataclass
class ValidationResult:
    sections: list[SectionRecord] = field(default_factory=list)
    index_entries: list[IndexEntry] = field(default_factory=list)
    transitions: list[TypeTransition] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    unknowns: list[Unknown] = field(default_factory=list)
    custom_sections: list[dict] = field(default_factory=list)
    leb_records: list[dict] = field(default_factory=list)
    types: list[dict] = field(default_factory=list)
    imports: list[dict] = field(default_factory=list)
    exports: list[dict] = field(default_factory=list)
    func_bodies: list[dict] = field(default_factory=list)
    fingerprint: str = ""
    algo_version: str = ALGORITHM_VERSION

    def as_dict(self) -> dict:
        return {
            "sections": [s.as_dict() for s in self.sections],
            "index_entries": [e.as_dict() for e in self.index_entries],
            "transitions": [t.as_dict() for t in self.transitions],
            "findings": [f.as_dict() for f in self.findings],
            "candidates": [c.as_dict() for c in self.candidates],
            "unknowns": [u.as_dict() for u in self.unknowns],
            "custom_sections": self.custom_sections,
            "leb_records": self.leb_records,
            "types": self.types,
            "imports": self.imports,
            "exports": self.exports,
            "func_bodies": self.func_bodies,
            "fingerprint": self.fingerprint,
            "algo_version": self.algo_version,
        }


class Validator:
    def __init__(self, raw: bytes, features: dict[str, bool], host_contract: dict):
        self.raw = raw
        self.features = dict(features)
        self.host = host_contract or {"functions": [], "memories": []}
        self.res = ValidationResult()
        self.res.fingerprint = params_fingerprint(self.features, self.host)
        # index spaces
        self.types: list[tuple[list[str], list[str]]] = []
        self.func_types: list[int] = []          # funcidx -> typeidx
        self.func_imports = 0
        self.mem_count = 0
        self.mem_imports = 0
        self.global_types: list[tuple[str, bool]] = []
        self.table_count = 0
        self.datacount: int | None = None
        self.code_section: SectionRecord | None = None
        self.data_segments = 0

    # -- finding helpers -------------------------------------------------
    def _finding(self, kind, severity, message, start, end, subject, source):
        fid = stable_id("find", kind, subject, start, end)
        self.res.findings.append(Finding(fid, kind, severity, message,
                                         start, end, subject, source))
        return fid

    def _candidate(self, subject, question, options, start, end, source):
        cid = stable_id("cand", subject, question, start, end)
        self.res.candidates.append(Candidate(cid, subject, question,
                                             list(options), start, end, source))
        return cid

    def _unknown(self, subject, reason, start, end, source):
        uid = stable_id("unk", subject, reason, start, end)
        self.res.unknowns.append(Unknown(uid, subject, reason, start, end, source))
        return uid

    def _leb(self, res, context: str):
        rec = res.as_dict()
        rec["context"] = context
        rec["id"] = stable_id("leb", context, res.start, res.end, res.raw.hex())
        self.res.leb_records.append(rec)
        if res.truncated:
            self._finding("LEB_TRUNCATED", "error",
                          f"LEB128 truncated in {context}",
                          res.start, max(res.end, res.start + 1), context, context)
        if res.rep_too_long:
            self._finding("LEB_REP_TOO_LONG", "error",
                          f"LEB128 representation too long in {context}",
                          res.start, res.end, context, context)
        if res.noncanonical:
            # 不规范 LEB128 — kept separate from out-of-range
            self._finding("LEB_NONCANONICAL", "error",
                          f"non-canonical LEB128 in {context} "
                          f"(value {res.value} encoded in {len(res.raw)} bytes)",
                          res.start, res.end, context, context)
        if res.out_of_range:
            # 数值越界 — separate kind
            self._finding("LEB_VALUE_OUT_OF_RANGE", "error",
                          f"LEB128 value out of range for u{res.width}/s{res.width} "
                          f"in {context}",
                          res.start, res.end, context, context)
        return res

    # -- top level ---------------------------------------------------------
    def validate(self) -> ValidationResult:
        raw = self.raw
        if len(raw) < 8 or raw[:4] != b"\x00asm":
            self._finding("BAD_MAGIC", "error", "missing \\0asm magic",
                          0, min(4, len(raw)), "module", "module/header")
            return self.res
        if raw[4:8] != b"\x01\x00\x00\x00":
            self._finding("BAD_VERSION", "error",
                          f"unsupported version {raw[4:8].hex()}",
                          4, 8, "module", "module/header")
            return self.res
        self._parse_sections()
        self._check_import_contract()
        self._validate_code()
        return self.res

    # -- section map -------------------------------------------------------
    def _parse_sections(self):
        raw = self.raw
        pos = 8
        ordinal = -1
        seen_rank: dict[int, int] = {}
        while pos < len(raw):
            ordinal += 1
            sec_start = pos
            sid = raw[pos]
            src = f"section/{ordinal}"
            if sid > 12:
                self._finding("BAD_SECTION_ID", "error",
                              f"unknown section id {sid}",
                              sec_start, sec_start + 1, src, src)
                return
            size_res = self._leb(decode_uleb(raw, pos + 1), f"{src}/size")
            sec_end = size_res.end + size_res.value
            if sec_end > len(raw):
                self._finding("SECTION_TRUNCATED", "error",
                              f"section {SECTION_NAMES.get(sid, sid)} exceeds module",
                              size_res.end, len(raw), src, src)
                sec_end = len(raw)
            dup_of = None
            order_ok = True
            if sid != 0:
                rank = ORDER_RANK[sid]
                if sid in seen_rank:
                    dup_of = seen_rank[sid]
                    order_ok = False
                    self._finding("SECTION_DUPLICATE", "error",
                                  f"duplicate {SECTION_NAMES[sid]} section",
                                  sec_start, sec_end, src, src)
                for other_id, other_rank in seen_rank.items():
                    if other_id != sid and other_rank > rank:
                        order_ok = False
                        self._finding("SECTION_OUT_OF_ORDER", "error",
                                      f"{SECTION_NAMES[sid]} section appears after "
                                      f"{SECTION_NAMES[other_id]}",
                                      sec_start, sec_end, src, src)
                        break
                seen_rank.setdefault(sid, ordinal)
            cname = None
            if sid == 0:
                cname = self._parse_custom_name(size_res.end, sec_end, src)
            rec = SectionRecord(
                ordinal=ordinal,
                id=stable_id("sec", ordinal, sec_start, sid),
                section_id=sid,
                name=SECTION_NAMES.get(sid, f"id{sid}"),
                size=size_res.value,
                start=sec_start,
                end=sec_end,
                size_leb_start=pos + 1,
                size_leb_end=size_res.end,
                order_ok=order_ok and dup_of is None,
                duplicate_of=dup_of,
                custom_name=cname,
            )
            self.res.sections.append(rec)
            self._parse_section_body(rec)
            if not size_res.ok:
                # unsafe to trust the boundary; still recorded, then stop
                pos = sec_end
                if size_res.truncated or size_res.rep_too_long:
                    break
                pos = sec_end
                continue
            pos = sec_end

    def _parse_custom_name(self, start, end, src):
        raw = self.raw
        if start >= end:
            return ""
        nr = self._leb(decode_uleb(raw, start), f"{src}/name_len")
        name_end = nr.end + nr.value
        cname = raw[nr.end:name_end].decode("utf-8", errors="replace")
        # custom sections are preserved verbatim - including name and payload
        self.res.custom_sections.append({
            "id": stable_id("custom", cname, start),
            "section": src,
            "name": cname,
            "name_start": nr.end,
            "name_end": name_end,
            "payload_start": name_end,
            "payload_end": end,
            "payload_hex": raw[name_end:end].hex(),
            "raw_hex": raw[start:end].hex(),
        })
        return cname

    def _parse_section_body(self, rec: SectionRecord):
        dispatch = {
            1: self._parse_type, 2: self._parse_import, 3: self._parse_function,
            4: self._parse_table, 5: self._parse_memory, 6: self._parse_global,
            7: self._parse_export, 8: self._parse_start, 9: self._parse_element,
            10: self._parse_code_index, 11: self._parse_data_index,
            12: self._parse_datacount,
        }
        fn = dispatch.get(rec.section_id)
        if fn:
            fn(rec)

    def _cursor(self, rec):
        start = rec.start
        size_res = decode_uleb(self.raw, start + 1)
        return size_res.end

    def _parse_valtype(self, pos, src, allow_block_void=False):
        byte = self.raw[pos]
        if allow_block_void and byte == 0x40:
            return None, pos + 1
        name, feature = VALTYPE.get(byte, (None, None))
        if name is None:
            self._finding("UNKNOWN_VALTYPE", "error",
                          f"unknown value type byte {byte:#04x}",
                          pos, pos + 1, src, src)
            return "unknown", pos + 1
        if feature and not self.features.get(feature, False):
            self._finding("CAPABILITY_MISSING", "error",
                          f"value type {name} requires enabled proposal "
                          f"{PROPOSALS[feature]['name']}",
                          pos, pos + 1, src, src)
        return name, pos + 1

    def _parse_resulttype(self, pos, rec, label):
        cnt = self._leb(decode_uleb(self.raw, pos),
                        f"{label}#{len(self.types)}/count_{label}")
        pos = cnt.end
        types = []
        for i in range(cnt.value):
            t, pos = self._parse_valtype(pos, label)
            types.append(t)
        return types, pos

    def _parse_type(self, rec: SectionRecord):
        pos = self._cursor(rec)
        cnt = self._leb(decode_uleb(self.raw, pos), "section/type/count")
        pos = cnt.end
        for i in range(cnt.value):
            src = f"type/{i}"
            marker = self.raw[pos]
            if marker != 0x60:
                self._finding("BAD_FUNCTYPE", "error",
                              f"type {i} marker is {marker:#04x}, expected 0x60",
                              pos, pos + 1, src, src)
                break
            mstart = pos
            pos += 1
            params, pos = self._read_type_vec(pos, src, "params", i)
            results, pos = self._read_type_vec(pos, src, "results", i)
            if len(results) > 1 and not self.features.get("multivalue", False):
                self._finding("CAPABILITY_MISSING", "error",
                              f"function type {i} returns {len(results)} values; "
                              "multi-value proposal is disabled",
                              mstart, pos, src, src)
            self.types.append((params, results))
            self.res.types.append({
                "id": stable_id("type", i, tuple(params), tuple(results)),
                "index": i, "params": params, "results": results,
                "byte_start": mstart, "byte_end": pos,
            })
            self.res.index_entries.append(IndexEntry(
                id=stable_id("idx", "type", i), space="type", index=i,
                origin="defined",
                desc=f"({','.join(params)})->({','.join(results)})",
                byte_start=mstart, byte_end=pos))

    def _read_type_vec(self, pos, src, kind, type_i):
        cnt = self._leb(decode_uleb(self.raw, pos), f"type/{type_i}/{kind}")
        pos = cnt.end
        out = []
        for _ in range(cnt.value):
            t, pos = self._parse_valtype(pos, src)
            out.append(t)
        return out, pos

    def _read_name(self, pos, src):
        nr = self._leb(decode_uleb(self.raw, pos), f"{src}/name")
        end = nr.end + nr.value
        return self.raw[nr.end:end].decode("utf-8", errors="replace"), nr.end, end

    def _parse_import(self, rec: SectionRecord):
        pos = self._cursor(rec)
        cnt = self._leb(decode_uleb(self.raw, pos), "section/import/count")
        pos = cnt.end
        func_idx = 0
        for i in range(cnt.value):
            src = f"import/{i}"
            istart = pos
            mod, _, pos = self._read_name(pos, f"{src}/module")
            fld, _, pos = self._read_name(pos, f"{src}/field")
            kind = self.raw[pos]
            pos += 1
            entry = {"index": i, "module": mod, "name": fld, "kind": kind,
                     "byte_start": istart}
            if kind == 0x00:  # function
                tr = self._leb(decode_uleb(self.raw, pos), f"{src}/typeidx")
                pos = tr.end
                ti = tr.value
                entry["typeidx"] = ti
                resolved = self._resolve_type(ti, tr.start, tr.end, src)
                entry["type"] = resolved
                self.func_types.append(ti)
                self.res.index_entries.append(IndexEntry(
                    id=stable_id("idx", "func", func_idx), space="func",
                    index=func_idx, origin="import",
                    desc=f"{mod}.{fld}: {resolved}",
                    byte_start=istart, byte_end=pos))
                func_idx += 1
                self.func_imports += 1
            elif kind == 0x01:  # table
                tt, pos = self._parse_valtype(pos, src)
                lim, pos = self._read_limits(pos, src)
                entry["elem_type"] = tt
                entry["limits"] = lim
                self.res.index_entries.append(IndexEntry(
                    id=stable_id("idx", "table", self.table_count), space="table",
                    index=self.table_count, origin="import", desc=tt,
                    byte_start=istart, byte_end=pos))
                self.table_count += 1
            elif kind == 0x02:  # memory
                lim, pos = self._read_limits(pos, src)
                entry["limits"] = lim
                self._check_limits(lim, istart, pos, src)
                self.res.index_entries.append(IndexEntry(
                    id=stable_id("idx", "mem", self.mem_count), space="mem",
                    index=self.mem_count, origin="import", desc=f"memory {lim}",
                    byte_start=istart, byte_end=pos))
                self.mem_count += 1
                self.mem_imports += 1
            elif kind == 0x03:  # global
                gt, pos = self._parse_valtype(pos, src)
                mut = self.raw[pos]
                pos += 1
                entry["global_type"] = [gt, bool(mut)]
                self.res.index_entries.append(IndexEntry(
                    id=stable_id("idx", "global", len(self.global_types)),
                    space="global", index=len(self.global_types), origin="import",
                    desc=f"{gt}{' mut' if mut else ''}",
                    byte_start=istart, byte_end=pos))
                self.global_types.append((gt, bool(mut)))
            else:
                self._finding("BAD_IMPORT_KIND", "error",
                              f"import {i} unknown kind {kind:#04x}",
                              istart, pos, src, src)
            entry["byte_end"] = pos
            self.res.imports.append(entry)

    def _read_limits(self, pos, src):
        flags = self.raw[pos]
        fstart = pos
        pos += 1
        if flags not in (0x00, 0x01):
            self._finding("BAD_LIMITS_FLAGS", "error",
                          f"limits flags {flags:#04x}", fstart, pos, src, src)
            mn = self._leb(decode_uleb(self.raw, pos), f"{src}/min")
            return {"flags": flags, "min": mn.value, "max": None,
                    "start": fstart, "end": mn.end}, mn.end
        mn = self._leb(decode_uleb(self.raw, pos), f"{src}/min")
        pos = mn.end
        result = {"flags": flags, "min": mn.value, "max": None,
                  "start": fstart}
        if flags == 0x01:
            mx = self._leb(decode_uleb(self.raw, pos), f"{src}/max")
            pos = mx.end
            result["max"] = mx.value
            result["end"] = mx.end
            if not (mx.truncated or mx.out_of_range) and mx.value < mn.value:
                self._finding("LIMITS_REVERSED", "error",
                              f"max pages {mx.value} < min pages {mn.value}",
                              fstart, mx.end, src, src)
        else:
            result["end"] = mn.end
        if not mn.out_of_range and mn.value > 65536:
            self._finding("LIMITS_EXCEEDED", "error",
                          f"memory min {mn.value} > 65536 pages",
                          fstart, result["end"], src, src)
        return result, pos

    def _check_limits(self, lim, start, end, src):
        if lim.get("min", 0) > 65536 or (lim.get("max") or 0) > 65536:
            self._finding("LIMITS_EXCEEDED", "error",
                          "memory limits exceed 65536 pages",
                          start, end, src, src)

    def _resolve_type(self, ti, start, end, src):
        if ti >= len(self.types):
            self._finding("INDEX_OUT_OF_RANGE", "error",
                          f"type index {ti} but only {len(self.types)} types",
                          start, end, src, src)
            return "?"
        params, results = self.types[ti]
        return f"({','.join(params)})->({','.join(results)})"

    def _parse_function(self, rec: SectionRecord):
        pos = self._cursor(rec)
        cnt = self._leb(decode_uleb(self.raw, pos), "section/function/count")
        pos = cnt.end
        for i in range(cnt.value):
            src = f"function/decl/{i}"
            tr = self._leb(decode_uleb(self.raw, pos), f"{src}/typeidx")
            pos = tr.end
            self.func_types.append(tr.value)

    def _parse_table(self, rec: SectionRecord):
        pos = self._cursor(rec)
        cnt = self._leb(decode_uleb(self.raw, pos), "section/table/count")
        pos = cnt.end
        for i in range(cnt.value):
            src = f"table/{i}"
            tt, pos = self._parse_valtype(pos, src)
            lim, pos = self._read_limits(pos, src)
            self.res.index_entries.append(IndexEntry(
                id=stable_id("idx", "table", self.table_count), space="table",
                index=self.table_count, origin="defined", desc=tt,
                byte_start=rec.start, byte_end=pos))
            self.table_count += 1

    def _parse_memory(self, rec: SectionRecord):
        pos = self._cursor(rec)
        cnt = self._leb(decode_uleb(self.raw, pos), "section/memory/count")
        pos = cnt.end
        for i in range(cnt.value):
            src = f"memory/{i}"
            istart = pos
            lim, pos = self._read_limits(pos, src)
            self._check_limits(lim, istart, pos, src)
            self.res.index_entries.append(IndexEntry(
                id=stable_id("idx", "mem", self.mem_count), space="mem",
                index=self.mem_count, origin="defined", desc=f"memory {lim['min']}",
                byte_start=istart, byte_end=pos))
            self.mem_count += 1
        if self.mem_count - self.mem_imports > 1 and not self.features.get("multi_memory", False):
            self._finding("CAPABILITY_MISSING", "error",
                          "multiple memories defined but multi-memory proposal "
                          "is disabled", rec.start, rec.end,
                          "section/memory", "section/memory")

    def _parse_global(self, rec: SectionRecord):
        pos = self._cursor(rec)
        cnt = self._leb(decode_uleb(self.raw, pos), "section/global/count")
        pos = cnt.end
        for i in range(cnt.value):
            src = f"global/{i}"
            istart = pos
            gt, pos = self._parse_valtype(pos, src)
            mut = self.raw[pos]
            pos += 1
            self.global_types.append((gt, bool(mut)))
            self.res.index_entries.append(IndexEntry(
                id=stable_id("idx", "global", len(self.global_types) - 1),
                space="global", index=len(self.global_types) - 1, origin="defined",
                desc=f"{gt}{' mut' if mut else ''}",
                byte_start=istart, byte_end=pos))
            pos = self._skip_const_expr(pos, src)

    def _skip_const_expr(self, pos, src):
        depth = 0
        start = pos
        while pos < len(self.raw):
            op = self.raw[pos]
            if op == 0x0B and depth == 0:
                return pos + 1
            if op in (0x41, 0x42):
                r = decode_sleb(self.raw, pos + 1, 32 if op == 0x41 else 64)
                pos = r.end
            elif op == 0x43:
                pos += 5
            elif op == 0x44:
                pos += 9
            elif op == 0x23:
                r = decode_uleb(self.raw, pos + 1)
                pos = r.end
            elif op == 0xD0:
                r = decode_uleb(self.raw, pos + 1)
                pos = r.end
            elif op == 0x0B:
                depth -= 1
                pos += 1
            else:
                pos += 1
        self._finding("CONST_EXPR_UNTERMINATED", "error",
                      "constant expression has no terminating end",
                      start, len(self.raw), src, src)
        return pos

    def _parse_export(self, rec: SectionRecord):
        pos = self._cursor(rec)
        cnt = self._leb(decode_uleb(self.raw, pos), "section/export/count")
        pos = cnt.end
        seen = set()
        for i in range(cnt.value):
            src = f"export/{i}"
            nm, _, e = self._read_name(pos, f"{src}/name")
            pos = e
            kind = self.raw[pos]
            pos += 1
            ir = self._leb(decode_uleb(self.raw, pos), f"{src}/index")
            pos = ir.end
            if nm in seen:
                self._finding("EXPORT_DUPLICATE_NAME", "error",
                              f"duplicate export name {nm!r}",
                              rec.start, pos, src, src)
            seen.add(nm)
            self.res.exports.append({"name": nm, "kind": kind,
                                     "index": ir.value})

    def _parse_start(self, rec: SectionRecord):
        pos = self._cursor(rec)
        ir = self._leb(decode_uleb(self.raw, pos), "section/start/funcidx")
        if ir.value >= len(self.func_types):
            self._finding("INDEX_OUT_OF_RANGE", "error",
                          f"start function {ir.value} out of func index space",
                          ir.start, ir.end, "section/start", "section/start")

    def _parse_element(self, rec: SectionRecord):
        pos = self._cursor(rec)
        cnt = self._leb(decode_uleb(self.raw, pos), "section/element/count")

    def _parse_datacount(self, rec: SectionRecord):
        pos = self._cursor(rec)
        cnt = self._leb(decode_uleb(self.raw, pos), "section/datacount/count")
        self.datacount = cnt.value

    def _parse_data_index(self, rec: SectionRecord):
        pos = self._cursor(rec)
        cnt = self._leb(decode_uleb(self.raw, pos), "section/data/count")
        self.data_segments = cnt.value
        if self.datacount is not None and self.datacount != cnt.value:
            self._finding("DATACOUNT_MISMATCH", "error",
                          f"data count {cnt.value} != datacount {self.datacount}",
                          rec.start, rec.end, "section/data", "section/data")

    def _parse_code_index(self, rec: SectionRecord):
        # bodies validated in _validate_code once all index spaces exist
        self.code_section = rec

    # -- import contract ---------------------------------------------------
    def _check_import_contract(self):
        host_funcs = self.host.get("functions", [])
        host_mems = self.host.get("memories", [])
        for imp in self.res.imports:
            src = f"import/{imp['index']}"
            if imp["kind"] == 0x00:
                sig = imp.get("type", "?")
                matches = [h for h in host_funcs
                           if h["module"] == imp["module"] and h["name"] == imp["name"]]
                if not matches:
                    same_module = [h for h in host_funcs if h["module"] == imp["module"]]
                    if same_module:
                        options = [f"{h['module']}.{h['name']}" for h in same_module]
                        # field is close but not an exact contract match:
                        # retain every legal same-module candidate rather
                        # than silently guessing.
                        self._candidate(
                            subject=src,
                            question=("host contract has no exact function match; "
                                      "which same-module host function is intended?"),
                            options=options,
                            start=imp["byte_start"], end=imp["byte_end"], source=src)
                    self._finding("IMPORT_UNRESOLVED", "error",
                                  f"host contract has no function "
                                  f"{imp['module']}.{imp['name']}",
                                  imp["byte_start"], imp["byte_end"], src, src)
                    continue
                # exact module/name matches; verify signature against type
                params, results = (self.types[imp["typeidx"]]
                                   if imp["typeidx"] < len(self.types)
                                   else (["?"], ["?"]))
                for h in matches:
                    if (list(h["params"]) != params or list(h["results"]) != results):
                        self._finding("IMPORT_SIGNATURE_MISMATCH", "error",
                                      f"{imp['module']}.{imp['name']} expects "
                                      f"({','.join(h['params'])})->"
                                      f"({','.join(h['results'])}) but module declares "
                                      f"({','.join(params)})->({','.join(results)})",
                                      imp["byte_start"], imp["byte_end"], src, src)
            elif imp["kind"] == 0x02:
                lim = imp["limits"]
                matches = [m for m in host_mems
                           if m["module"] == imp["module"] and m["name"] == imp["name"]]
                if not matches:
                    self._finding("IMPORT_UNRESOLVED", "error",
                                  f"host contract has no memory "
                                  f"{imp['module']}.{imp['name']}",
                                  imp["byte_start"], imp["byte_end"], src, src)
                    continue
                h = matches[0]
                if h.get("min_pages") is not None and lim["min"] < h["min_pages"]:
                    self._finding("IMPORT_LIMITS_MISMATCH", "error",
                                  f"imported memory min {lim['min']} below host "
                                  f"requirement {h['min_pages']}",
                                  imp["byte_start"], imp["byte_end"], src, src)
                if h.get("max_pages") is not None and lim.get("max") is not None \
                        and lim["max"] > h["max_pages"]:
                    self._finding("IMPORT_LIMITS_MISMATCH", "error",
                                  f"imported memory max {lim['max']} above host "
                                  f"ceiling {h['max_pages']}",
                                  imp["byte_start"], imp["byte_end"], src, src)

    # -- code / type stack -------------------------------------------------
    def _validate_code(self):
        rec = getattr(self, "code_section", None)
        if rec is None:
            return
        pos = self._cursor(rec)
        cnt = self._leb(decode_uleb(self.raw, pos), "section/code/count")
        pos = cnt.end
        expected = len(self.func_types) - self.func_imports
        if cnt.value != expected:
            self._finding("FUNC_COUNT_MISMATCH", "error",
                          f"{cnt.value} code bodies for {expected} defined funcs",
                          rec.start, rec.end, "section/code", "section/code")
        for body_i in range(min(cnt.value, max(expected, 0))):
            funcidx = self.func_imports + body_i
            self._validate_function_body(funcidx, pos, body_i)
            br = self._leb(decode_uleb(self.raw, pos), f"code/{body_i}/size")
            pos = br.end + br.value

    def _validate_function_body(self, funcidx: int, body_pos: int, body_i: int):
        size_res = self._leb(decode_uleb(self.raw, self.raw and body_pos),
                             f"code/{body_i}/size")
        body_start = size_res.end
        body_end = body_start + size_res.value
        src = f"code/{body_i}"
        typeidx = (self.func_types[funcidx]
                   if funcidx < len(self.func_types) else 0)
        if typeidx >= len(self.types):
            self._finding("INDEX_OUT_OF_RANGE", "error",
                          f"function {funcidx} references missing type {typeidx}",
                          size_res.start, size_res.end, src, src)
            return
        params, results = self.types[typeidx]
        local_types = list(params)
        lc = self._leb(decode_uleb(self.raw, body_start), f"{src}/local_decls")
        p = lc.end
        for gi in range(lc.value):
            cnt2 = self._leb(decode_uleb(self.raw, p), f"{src}/local/{gi}/count")
            p = cnt2.end
            vt, p = self._parse_valtype(p, f"{src}/local/{gi}")
            for li in range(cnt2.value):
                local_types.append(vt)
                local_idx = len(local_types) - 1
                self.res.index_entries.append(IndexEntry(
                    id=stable_id("idx", "local", funcidx, local_idx),
                    space="local", index=local_idx, origin="local",
                    desc=vt, byte_start=p - 1, byte_end=p))
        for li, pt in enumerate(params):
            self.res.index_entries.append(IndexEntry(
                id=stable_id("idx", "local", funcidx, li), space="local",
                index=li, origin="param", desc=pt,
                byte_start=size_res.start, byte_end=size_res.end))

        frames: list[ControlFrame] = [
            ControlFrame("func", [], list(results), 0, False, body_start)]
        vstack: list[str] = []
        self.res.func_bodies.append({
            "func_index": funcidx,
            "id": stable_id("funcbody", funcidx, typeidx),
            "type_index": typeidx,
            "locals": local_types,
            "params": params, "results": results,
            "byte_start": size_res.start, "byte_end": body_end,
        })
        self._run_instruction_loop(funcidx, p, body_end, src, local_types,
                                   frames, vstack, results)

    def _polymorphic(self, frames) -> bool:
        return any(f.unreachable for f in frames)

    def _pop(self, vstack, frames, expected=None):
        """Pop with polymorphic freedom: inside an unreachable region a missing
        operand is satisfied with an unknown type instead of failing."""
        poly = self._polymorphic(frames)
        if vstack:
            got = vstack.pop()
            if expected is not None and got != "unknown" and expected != "unknown" \
                    and got != expected:
                return None, got
            return got, got
        if poly:
            return ("unknown" if expected is None else expected), "unknown"
        return None, None

    def _pop_expect(self, vstack, frames, expected, pc, src, opname):
        got, marker = self._pop(vstack, frames, expected)
        if got is None:
            self._finding("STACK_MISMATCH", "error",
                          f"{opname}: expected {expected} on empty value stack",
                          pc, pc + 1, f"{src}@{pc}", src)
            return False
        if marker is not None and marker != "unknown" and marker != expected:
            self._finding("STACK_TYPE_MISMATCH", "error",
                          f"{opname}: expected {expected}, found {marker}",
                          pc, pc + 1, f"{src}@{pc}", src)
            return False
        return True

    def _branch_label_types(self, frames, label):
        target = frames[-1 - label]
        return list(target.end_types), target

    def _record_transition(self, funcidx, pc, op, before, frames, vstack):
        self.res.transitions.append(TypeTransition(
            id=stable_id("tx", funcidx, pc, op),
            func_index=funcidx, pc=pc, opcode=op,
            stack_before=list(before), stack_after=list(vstack),
            control_depth=len(frames),
            polymorphic=self._polymorphic(frames)))

    def _run_instruction_loop(self, funcidx, p, body_end, src, local_types,
                              frames, vstack, results):
        raw = self.raw
        first_error_at = None
        while p < body_end:
            pc = p
            before = list(vstack)
            op = raw[p]
            p += 1
            if op == 0x0B:  # end
                if len(frames) == 1:
                    self._finalize_frame(frames[-1], vstack, frames, pc, src,
                                          terminates_func=True)
                    p = body_end
                    break
                frame = frames.pop()
                self._finalize_frame(frame, vstack, frames, pc, src)
                continue
            name, p = self._dispatch_op(funcidx, pc, op, p, body_end, src,
                                        local_types, frames, vstack)
            self._record_transition(funcidx, pc, name, before, frames, vstack)
            if first_error_at is None and self.res.findings and \
                    self.res.findings[-1].byte_start == pc and \
                    self.res.findings[-1].kind in (
                        "STACK_MISMATCH", "STACK_TYPE_MISMATCH",
                        "CAPABILITY_MISSING", "UNKNOWN_BYTE",
                        "INDEX_OUT_OF_RANGE"):
                first_error_at = pc

    def _finalize_frame(self, frame, vstack, frames, pc, src,
                        terminates_func=False):
        # values above frame.height are the operands/results of this frame
        operands = vstack[frame.height:]
        expected = frame.end_types
        poly = frame.unreachable or any(f.unreachable for f in frames)
        def diag_start():
            return pc
        if len(operands) < len(expected):
            if not poly:
                self._finding("STACK_ARITY_MISMATCH", "error",
                              f"{frame.opcode} returns {len(expected)} values, "
                              f"stack has {len(operands)}",
                              pc, pc + 1, f"{src}@{pc}", src)
            # leave expected unknown results for the enclosing frame
            operands = ["unknown"] * len(expected)
        elif len(operands) > len(expected):
            operands = operands[len(operands) - len(expected):]
        mismatch = any(a != b and a != "unknown" for a, b in zip(operands, expected))
        if mismatch and not poly:
            self._finding("STACK_TYPE_MISMATCH", "error",
                          f"{frame.opcode} result types {expected}, found {operands}",
                          pc, pc + 1, f"{src}@{pc}", src)
        del vstack[frame.height:]
        if not terminates_func:
            vstack.extend(list(expected))
