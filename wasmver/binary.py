"""Structural WebAssembly binary parser.

The parser is deliberately fault-tolerant: malformed sections still produce
as much of the section map, index table and byte-range bookkeeping as
possible, and every parse fault becomes a structured finding rather than an
exception.  Semantic validation (stack typing, proposals, imports) happens in
``wasmver.validator`` / ``wasmver.analysis``.
"""

from __future__ import annotations

from .leb import decode_u, decode_s, LebValue
from .types import VALUE_TYPES, VALUE_TYPE_PROPOSALS, FUNC_TYPE_MARKER, FuncType
from .model import byte_range, finding

MAGIC = b"\x00asm"
VERSION = b"\x01\x00\x00\x00"

STANDARD_SECTION_NAMES = {
    1: "type", 2: "import", 3: "function", 4: "table", 5: "memory",
    6: "global", 7: "export", 8: "start", 9: "element", 10: "code",
    11: "data", 12: "datacount",
}

IMPORT_KINDS = {0: "func", 1: "table", 2: "mem", 3: "global"}
EXPORT_KINDS = {0: "func", 1: "table", 2: "mem", 3: "global"}


class Reader:
    """Bounded cursor over a section payload, tracking absolute offsets."""

    def __init__(self, data: bytes, base: int = 0):
        self.data = data
        self.base = base
        self.pos = 0
        self.faults: list[dict] = []

    @property
    def abs_pos(self) -> int:
        return self.base + self.pos

    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def u8(self) -> int | None:
        if self.pos >= len(self.data):
            self.faults.append(finding(
                "truncated-section", "expected byte, section payload ended",
                byte_range(self.abs_pos, self.abs_pos + 1)))
            return None
        b = self.data[self.pos]
        self.pos += 1
        return b

    def u32(self) -> LebValue:
        v = decode_u(self.data, self.pos, 32)
        self.pos = min(v.end, len(self.data))
        if v.status != "ok":
            self.faults.append(_leb_finding(v, self.base))
        return v

    def s32(self) -> LebValue:
        v = decode_s(self.data, self.pos, 32)
        self.pos = min(v.end, len(self.data))
        if v.status != "ok":
            self.faults.append(_leb_finding(v, self.base))
        return v

    def s64(self) -> LebValue:
        v = decode_s(self.data, self.pos, 64)
        self.pos = min(v.end, len(self.data))
        if v.status != "ok":
            self.faults.append(_leb_finding(v, self.base))
        return v

    def raw(self, n: int) -> bytes:
        n = max(0, min(n, self.remaining()))
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def name(self) -> dict:
        start = self.abs_pos
        length = self.u32()
        n = length.value if length.value is not None else self.remaining()
        raw = self.raw(n)
        return {
            "text": raw.decode("utf-8", errors="replace"),
            "length_leb": length.as_dict(),
            "range": byte_range(start, self.abs_pos),
        }

    def block_type(self) -> dict:
        start = self.abs_pos
        b = self.u8()
        if b is None:
            return {"raw": None, "range": byte_range(start, self.abs_pos)}
        if b == 0x40:
            kind = "empty"
            params: tuple[str, ...] = ()
            results: tuple[str, ...] = ()
        elif b in VALUE_TYPES:
            kind = "value"
            params = ()
            results = (VALUE_TYPES[b],)
        elif b == 0x80:
            # s33 type index LEB (multi-value blocktype); read as signed LEB.
            v = self.s32()
            kind = "typeidx"
            params = ()
            results = ()
            return {
                "raw": {"marker": "0x80", "index_leb": v.as_dict()},
                "kind": kind,
                "params": list(params), "results": list(results),
                "range": byte_range(start, self.abs_pos),
            }
        else:
            kind = "bad"
            params = ()
            results = ()
        return {
            "raw": f"0x{b:02x}",
            "kind": kind,
            "params": list(params), "results": list(results),
            "value_type_proposal": VALUE_TYPE_PROPOSALS.get(b),
            "range": byte_range(start, self.abs_pos),
        }


def _leb_finding(v: LebValue, base: int) -> dict:
    return finding(
        f"leb128-{v.status}", v.reason or f"LEB128 {v.status}",
        byte_range(base + v.start, base + v.end),
        severity="error",
        leb=v.as_dict())


def _vec(reader: Reader, item_fn):
    count = reader.u32()
    items = []
    n = count.value if count.value is not None else 0
    for _ in range(n):
        if reader.eof():
            break
        items.append(item_fn(reader))
    return count, items


def _value_type(reader: Reader) -> dict:
    start = reader.abs_pos
    b = reader.u8()
    name = VALUE_TYPES.get(b) if b is not None else None
    entry = {
        "byte": f"0x{b:02x}" if b is not None else None,
        "name": name,
        "proposal": VALUE_TYPE_PROPOSALS.get(b) if b is not None else None,
        "range": byte_range(start, reader.abs_pos),
    }
    if b is not None and name is None:
        reader.faults.append(finding(
            "bad-value-type", f"0x{b:02x} is not a value type",
            byte_range(start, reader.abs_pos)))
    return entry


def _func_type(reader: Reader) -> dict:
    start = reader.abs_pos
    marker = reader.u8()
    if marker != FUNC_TYPE_MARKER:
        reader.faults.append(finding(
            "bad-functype-marker",
            f"expected 0x60 functype marker, got "
            f"{f'0x{marker:02x}' if marker is not None else 'end of section'}",
            byte_range(start, reader.abs_pos)))
    _, params = _vec(reader, _value_type)
    _, results = _vec(reader, _value_type)
    p = tuple(x["name"] for x in params if x["name"])
    r = tuple(x["name"] for x in results if x["name"])
    return {
        "func_type": FuncType(p, r).as_dict(),
        "params": params, "results": results,
        "range": byte_range(start, reader.abs_pos),
    }


def _limits(reader: Reader) -> dict:
    start = reader.abs_pos
    flags = reader.u8()
    entry: dict = {"flags": flags, "range": byte_range(start, start + 1)}
    if flags is None:
        return entry
    minimum = reader.u32()
    entry["min"] = minimum.as_dict()
    if flags & 0x01:
        maximum = reader.u32()
        entry["max"] = maximum.as_dict()
    if flags not in (0x00, 0x01):
        reader.faults.append(finding(
            "bad-limits-flags", f"limits flags 0x{flags:02x} invalid",
            byte_range(start, reader.abs_pos)))
    entry["range"] = byte_range(start, reader.abs_pos)
    return entry


def _tabletype(reader: Reader) -> dict:
    start = reader.abs_pos
    et = _value_type(reader)
    limits = _limits(reader)
    return {"element": et, "limits": limits,
            "range": byte_range(start, reader.abs_pos)}


def _globaltype(reader: Reader) -> dict:
    start = reader.abs_pos
    vt = _value_type(reader)
    mut = reader.u8()
    if mut not in (0, 1):
        reader.faults.append(finding(
            "bad-mutability", f"mutability {mut} must be 0 or 1",
            byte_range(reader.abs_pos - 1, reader.abs_pos)))
    return {"value_type": vt, "mutable": mut,
            "range": byte_range(start, reader.abs_pos)}


def _import(reader: Reader) -> dict:
    start = reader.abs_pos
    module = reader.name()
    field = reader.name()
    kind_byte = reader.u8()
    kind = IMPORT_KINDS.get(kind_byte)
    desc: dict = {"kind": kind, "kind_byte":
                  f"0x{kind_byte:02x}" if kind_byte is not None else None}
    if kind == "func":
        ti = reader.u32()
        desc["type_index"] = ti.as_dict()
    elif kind == "table":
        desc["table"] = _tabletype(reader)
    elif kind == "mem":
        desc["limits"] = _limits(reader)
    elif kind == "global":
        desc["global"] = _globaltype(reader)
    else:
        reader.faults.append(finding(
            "bad-import-kind", f"import kind {kind_byte} invalid",
            byte_range(reader.abs_pos - 1, reader.abs_pos)))
    return {"module": module, "field": field, "desc": desc,
            "range": byte_range(start, reader.abs_pos)}


def _export(reader: Reader) -> dict:
    start = reader.abs_pos
    name = reader.name()
    kind_byte = reader.u8()
    index = reader.u32()
    return {
        "name": name,
        "kind": EXPORT_KINDS.get(kind_byte),
        "kind_byte": f"0x{kind_byte:02x}" if kind_byte is not None else None,
        "index": index.as_dict(),
        "range": byte_range(start, reader.abs_pos),
    }


def _const_expr_skip(reader: Reader) -> dict:
    """Consume a constant expression; const ops + end."""
    start = reader.abs_pos
    ops: list[dict] = []
    while not reader.eof():
        op_start = reader.abs_pos
        op = reader.u8()
        if op == 0x0B:
            break
        if op in (0x41, 0x42):
            v = reader.s32() if op == 0x41 else reader.s64()
            ops.append({"op": f"0x{op:02x}", "leb": v.as_dict()})
        elif op in (0x43,):
            ops.append({"op": "f32.const", "raw": reader.raw(4).hex()})
        elif op in (0x44,):
            ops.append({"op": "f64.const", "raw": reader.raw(8).hex()})
        elif op == 0x23:
            v = reader.u32()
            ops.append({"op": "global.get", "leb": v.as_dict()})
        else:
            reader.faults.append(finding(
                "bad-const-expr",
                f"0x{op:02x} not allowed in constant expression",
                byte_range(op_start, reader.abs_pos)))
            break
    return {"ops": ops, "range": byte_range(start, reader.abs_pos)}


def _global(reader: Reader) -> dict:
    start = reader.abs_pos
    gt = _globaltype(reader)
    expr = _const_expr_skip(reader)
    return {"global_type": gt, "init": expr,
            "range": byte_range(start, reader.abs_pos)}


def _element(reader: Reader) -> dict:
    start = reader.abs_pos
    flags = reader.u32()
    # Full table-index/expression variants are elaborate; record flag and
    # consume a func-index vector for the common active cases.
    entry: dict = {"flags": flags.as_dict(),
                   "range": byte_range(start, reader.abs_pos)}
    if flags.value in (0, 2, 4):
        _, funcs = _vec(reader, lambda r: r.u32().as_dict())
        entry["func_indices"] = funcs
    entry["range"] = byte_range(start, reader.abs_pos)
    return entry


def _code_body(reader: Reader) -> dict:
    start = reader.abs_pos
    size = reader.u32()
    body_end = min(reader.abs_pos + (size.value or 0), reader.base + len(reader.data))
    _, locals_ = _vec(reader, lambda r: {"count": r.u32().as_dict(),
                                         "type": _value_type(r)})
    code_start = reader.abs_pos
    raw_end = min(body_end, reader.base + len(reader.data))
    body_bytes = reader.data[code_start - reader.base:raw_end - reader.base]
    reader.pos = raw_end - reader.base
    return {
        "size": size.as_dict(),
        "locals": locals_,
        "code_start": code_start,
        "code_end": raw_end,
        "body_hex": bytes(body_bytes).hex(),
        "range": byte_range(start, raw_end),
    }


SECTION_PARSERS = {}


def parse_module(data: bytes) -> dict:
    """Parse a module byte string into the structural map.

    Returns a dict with the header record, ordered sections, index spaces,
    module-level findings and the preserved raw input reference.
    """
    findings: list[dict] = []
    sections: list[dict] = []

    if len(data) < 8:
        findings.append(finding(
            "module-truncated",
            f"module needs at least 8 header bytes, got {len(data)}",
            byte_range(0, max(len(data), 8))))
        return {"sections": sections, "findings": findings, "index_spaces": {}}

    if data[0:4] != MAGIC:
        findings.append(finding(
            "bad-magic", f"magic must be 00 61 73 6d, got {data[0:4].hex()}",
            byte_range(0, 4)))
    if data[4:8] != VERSION:
        findings.append(finding(
            "bad-version", f"unsupported version field {data[4:8].hex()}",
            byte_range(4, 8)))

    pos = 8
    last_standard_id = 0
    seen_standard: dict[int, dict] = {}
    order_index = 0

    while pos < len(data):
        sec_start = pos
        sid_leb = decode_u(data, pos, 7)
        pos = sid_leb.end
        size_leb = decode_u(data, pos, 32)
        pos = size_leb.end
        declared = size_leb.value if size_leb.value is not None else 0
        payload_end = min(pos + declared, len(data))
        payload = data[pos:payload_end]
        truncated_section = pos + declared > len(data)
        sid = sid_leb.value

        if sid_leb.status != "ok":
            findings.append(_leb_finding(sid_leb, 0))
        if size_leb.status != "ok":
            findings.append(_leb_finding(size_leb, 0))

        if sid is None:
            sections.append({
                "order": order_index,
                "id_leb": sid_leb.as_dict(), "size_leb": size_leb.as_dict(),
                "name": "invalid", "custom": False,
                "payload_range": byte_range(pos, payload_end),
                "range": byte_range(sec_start, payload_end),
                "truncated": truncated_section,
            })
            break

        custom = sid == 0
        name = "custom" if custom else STANDARD_SECTION_NAMES.get(sid, f"unknown-{sid}")
        custom_name = None
        parsed = None
        reader = Reader(payload, base=pos)

        if custom:
            nm = reader.name()
            custom_name = nm["text"]
            name = f"custom:{custom_name}"
            parsed = {
                "name": nm,
                # Custom sections are preserved byte-for-byte, never parsed.
                "payload_after_name_hex":
                    payload[reader.pos:].hex(),
            }
        elif sid in STANDARD_SECTION_NAMES:
            if sid < last_standard_id:
                findings.append(finding(
                    "section-out-of-order",
                    f"section {STANDARD_SECTION_NAMES[sid]} (id {sid}) "
                    f"appears after section id {last_standard_id}",
                    byte_range(sec_start, sec_start + 1),
                    severity="error",
                    previous=STANDARD_SECTION_NAMES[last_standard_id]))
            if sid in seen_standard:
                findings.append(finding(
                    "section-duplicate",
                    f"section {STANDARD_SECTION_NAMES[sid]} (id {sid}) "
                    f"appears more than once",
                    byte_range(sec_start, sec_start + 1),
                    severity="error",
                    first_occurrence=seen_standard[sid]["range"]))
            seen_standard[sid] = {"range": byte_range(sec_start, payload_end)}
            last_standard_id = sid
            parsed = _parse_standard(reader, sid)
            findings.extend(reader.faults)
        else:
            findings.append(finding(
                "unknown-section-id", f"unknown standard section id {sid}",
                byte_range(sec_start, sec_start + 1),
                severity="warning"))

        if reader.remaining() > 0 and not custom:
            findings.append(finding(
                "section-trailing-bytes",
                f"{reader.remaining()} unconsumed byte(s) in {name} section",
                byte_range(reader.abs_pos, payload_end),
                severity="warning"))
        if truncated_section:
            findings.append(finding(
                "section-truncated",
                f"{name} section declares {declared} bytes but only "
                f"{len(payload)} remain",
                byte_range(size_leb.end, pos + declared)))

        sections.append({
            "order": order_index,
            "id": sid,
            "id_leb": sid_leb.as_dict(),
            "size_leb": size_leb.as_dict(),
            "name": name,
            "custom": custom,
            "custom_name": custom_name,
            "parsed": parsed,
            "payload_range": byte_range(pos, payload_end),
            "range": byte_range(sec_start, payload_end),
            "truncated": truncated_section,
        })
        order_index += 1
        pos = payload_end

    index_spaces = _build_index_spaces(sections)
    return {
        "sections": sections,
        "findings": findings,
        "index_spaces": index_spaces,
        "length": len(data),
    }


def _parse_standard(reader: Reader, sid: int) -> dict:
    if sid == 1:
        count, items = _vec(reader, _func_type)
        return {"count": count.as_dict(), "types": items}
    if sid == 2:
        count, items = _vec(reader, _import)
        return {"count": count.as_dict(), "imports": items}
    if sid == 3:
        count, items = _vec(reader, lambda r: r.u32().as_dict())
        return {"count": count.as_dict(), "type_indices": items}
    if sid == 4:
        count, items = _vec(reader, _tabletype)
        return {"count": count.as_dict(), "tables": items}
    if sid == 5:
        count, items = _vec(reader, _limits)
        return {"count": count.as_dict(), "memories": items}
    if sid == 6:
        count, items = _vec(reader, _global)
        return {"count": count.as_dict(), "globals": items}
    if sid == 7:
        count, items = _vec(reader, _export)
        return {"count": count.as_dict(), "exports": items}
    if sid == 8:
        idx = reader.u32()
        return {"function_index": idx.as_dict()}
    if sid == 9:
        count, items = _vec(reader, _element)
        return {"count": count.as_dict(), "elements": items}
    if sid == 10:
        count, items = _vec(reader, _code_body)
        return {"count": count.as_dict(), "bodies": items}
    if sid == 11:
        # data section: count, then segments (flags dependent). Preserve raw.
        count = reader.u32()
        return {"count": count.as_dict()}
    if sid == 12:
        count = reader.u32()
        return {"count": count.as_dict()}
    return None


def _build_index_spaces(sections: list[dict]) -> dict:
    """Index spaces with provenance: every entry names its source section."""
    type_space: list[dict] = []
    func_space: list[dict] = []
    table_space: list[dict] = []
    mem_space: list[dict] = []
    global_space: list[dict] = []

    for sec in sections:
        parsed = sec.get("parsed")
        if not parsed:
            continue
        sid = sec["id"]
        if sid == 1:
            for i, t in enumerate(parsed.get("types", [])):
                type_space.append({
                    "index": i,
                    "kind": "type",
                    "value": FuncType(
                        tuple(t["func_type"]["params"]),
                        tuple(t["func_type"]["results"])).pretty(),
                    "source_section_order": sec["order"],
                    "source_range": t["range"],
                })
        elif sid == 2:
            for i, imp in enumerate(parsed.get("imports", [])):
                desc = imp["desc"]
                entry_common = {
                    "module": imp["module"]["text"],
                    "field": imp["field"]["text"],
                    "source_section_order": sec["order"],
                    "source_range": imp["range"],
                }
                if desc["kind"] == "func":
                    func_space.append({
                        "index": len(func_space),
                        "kind": "imported-func",
                        "type_index": (desc["type_index"]["value"]
                                       if desc.get("type_index") else None),
                        **entry_common})
                elif desc["kind"] == "table":
                    table_space.append({"index": len(table_space),
                                        "kind": "imported-table",
                                        **entry_common})
                elif desc["kind"] == "mem":
                    mem_space.append({"index": len(mem_space),
                                      "kind": "imported-mem",
                                      **entry_common})
                elif desc["kind"] == "global":
                    global_space.append({"index": len(global_space),
                                         "kind": "imported-global",
                                         **entry_common})
        elif sid == 3:
            for i, ti in enumerate(parsed.get("type_indices", [])):
                func_space.append({
                    "index": len(func_space),
                    "kind": "defined-func",
                    "type_index": ti.get("value"),
                    "define_order": i,
                    "source_section_order": sec["order"],
                    "source_range": {"start": None, "end": None,
                                     "unit": "byte", "basis": "module[0]"},
                })
        elif sid == 4:
            for i, t in enumerate(parsed.get("tables", [])):
                table_space.append({"index": len(table_space),
                                    "kind": "defined-table",
                                    "source_section_order": sec["order"],
                                    "source_range": t["range"]})
        elif sid == 5:
            for i, m in enumerate(parsed.get("memories", [])):
                mem_space.append({"index": len(mem_space),
                                  "kind": "defined-mem",
                                  "source_section_order": sec["order"],
                                  "source_range": m["range"]})
        elif sid == 6:
            for i, g in enumerate(parsed.get("globals", [])):
                global_space.append({"index": len(global_space),
                                     "kind": "defined-global",
                                     "source_section_order": sec["order"],
                                     "source_range": g["range"]})

    # Attach code section ranges onto defined function entries.
    code_sec = next((s for s in sections if s.get("id") == 10 and s.get("parsed")),
                    None)
    if code_sec:
        bodies = code_sec["parsed"].get("bodies", [])
        defined = [f for f in func_space if f["kind"] == "defined-func"]
        for f, body in zip(defined, bodies):
            f["source_range"] = body["range"]
            f["code_section_order"] = code_sec["order"]

    return {
        "type": type_space,
        "func": func_space,
        "table": table_space,
        "memory": mem_space,
        "global": global_space,
    }
