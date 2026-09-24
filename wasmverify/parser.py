from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .domain import KNOWN_SECTIONS, VALTYPE_NAMES, cell_id, qty
from .leb import LEBError, read_uleb


@dataclass
class ParsedModule:
    module_id: str
    data: bytes
    sha256: str
    sections: list[dict] = field(default_factory=list)
    types: list[dict] = field(default_factory=list)
    imports: list[dict] = field(default_factory=list)
    functions: list[dict] = field(default_factory=list)
    exports: list[dict] = field(default_factory=list)
    code_bodies: list[dict] = field(default_factory=list)
    index_origins: list[dict] = field(default_factory=list)
    cells: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    raw: dict = field(default_factory=dict)
    status: str = "accepted"

    def add_finding(self, code, severity, title, rationale, brange, sources, **extra):
        local = hashlib.sha256(
            ("|".join(map(str, [code, brange, sources, title]))).encode()
        ).hexdigest()[:16]
        item = {
            "stable_id": cell_id(self.module_id, "finding", local),
            "code": code,
            "severity": severity,
            "title": title,
            "rationale": rationale,
            "minimal_failure_byte_range": list(brange),
            "sources": sources,
            "candidates": [],
            "rejected_reasons": [],
            "unknown": False,
            "accepted": None,
        }
        item.update(extra)
        self.findings.append(item)
        if severity in ("error", "fatal"):
            self.status = "rejected"
        return item

    def add_cell(self, kind, local, value, brange, sources, **extra):
        item = {
            "stable_id": cell_id(self.module_id, kind, local),
            "kind": kind,
            "value": value,
            "quantity": qty(value, "byte") if isinstance(value, int) and kind in ("offset", "length") else None,
            "byte_range": list(brange),
            "sources": sources,
            "raw_representation": self.data[brange[0]:brange[1]].hex() if brange[1] <= len(self.data) else None,
        }
        item.update(extra)
        item.pop("quantity", None) if item.get("quantity") is None else None
        self.cells.append(item)
        return item


def parse_module(data: bytes, module_identity: str) -> ParsedModule:
    pm = ParsedModule(module_identity, data, hashlib.sha256(data).hexdigest())
    pm.raw = {
        "stable_id": cell_id(module_identity, "raw", "bytes"),
        "original_byte_range": [0, len(data)],
        "sha256": pm.sha256,
        "length": qty(len(data), "byte", "linear byte offset from magic number"),
        "base64_ref": f"sha256:{pm.sha256}",
    }
    if len(data) < 8:
        pm.add_finding("MODULE_TRUNCATED", "fatal", "module header truncated", "magic/version requires eight bytes", (0, len(data)), [pm.raw["stable_id"]])
        return pm
    if data[:4] != b"\x00asm":
        pm.add_finding("INVALID_MAGIC", "fatal", "invalid WebAssembly magic", "module must begin with 00 61 73 6d", (0, 4), [cell_id(module_identity, "raw", "bytes")])
        return pm
    pm.add_cell("header", "magic", b"\0asm".hex(), (0, 4), [pm.raw["stable_id"]])
    if data[4:8] != b"\x01\x00\x00\x00":
        pm.add_finding("UNSUPPORTED_VERSION", "fatal", "unsupported binary version", "only WebAssembly binary version 1 is enabled", (4, 8), [pm.raw["stable_id"]])
        return pm
    pm.add_cell("header", "version", 1, (4, 8), [pm.raw["stable_id"]])
    pos = 8
    seen: dict[int, dict] = {}
    ordinal = 0
    while pos < len(data):
        sec_start = pos
        sid = data[pos]
        pos += 1
        try:
            sizev = read_uleb(data, pos, len(data), 32)
        except LEBError as exc:
            code = "NONCANONICAL_LEB128" if False else exc.code
            pm.add_finding(code, "fatal", f"section size {exc.message}", "section size LEB128 decoding failed before payload", (exc.start, exc.end), [pm.raw["stable_id"]])
            break
        size = sizev.value
        payload_start = sizev.end
        payload_end = payload_start + size
        if not sizev.canonical:
            pm.add_finding(
                "NONCANONICAL_LEB128",
                "error",
                "section size uses non-canonical LEB128",
                "LEB128 must omit unnecessary leading continuation groups; numeric range is checked separately",
                (sizev.start, sizev.end),
                [pm.raw["stable_id"]],
            )
        if payload_end > len(data):
            pm.add_finding("DECLARED_SIZE_OUT_OF_BOUNDS", "fatal", "section payload exceeds module", "the size integer is in range but its declared interval is not", (sizev.start, min(len(data), payload_end)), [pm.raw["stable_id"]])
            break
        section = {
            "stable_id": cell_id(module_identity, "section", str(ordinal)),
            "ordinal": ordinal,
            "id": sid,
            "name": "custom" if sid == 0 else KNOWN_SECTIONS.get(sid, f"unknown-{sid}"),
            "id_range": [sec_start, sec_start + 1],
            "size_leb": sizev.as_dict(),
            "payload_range": [payload_start, payload_end],
            "raw_range": [sec_start, payload_end],
            "raw_hex": data[sec_start:payload_end].hex(),
        }
        pm.sections.append(section)
        pm.add_cell("section-id", str(ordinal), sid, (sec_start, sec_start + 1), [pm.raw["stable_id"]])
        pm.add_cell("section-size", str(ordinal), size, (sizev.start, sizev.end), [pm.raw["stable_id"]])
        if sid == 0:
            section["custom"] = _parse_custom(data, payload_start, payload_end, pm)
        elif sid not in KNOWN_SECTIONS:
            pm.add_finding("UNKNOWN_SECTION_ID", "error", "unknown known-section id", "a nonzero section id has no section in the enabled binary grammar", (sec_start, sec_start + 1), [section["stable_id"]])
        else:
            if sid in seen:
                pm.add_finding("DUPLICATE_SECTION", "error", f"duplicate {KNOWN_SECTIONS[sid]} section", "known sections define one contiguous index space and must occur at most once", (sec_start, sec_start + 1), [section["stable_id"], seen[sid]["stable_id"]], candidates=[seen[sid]], rejected_reasons=[{"stable_id": section["stable_id"], "reason": "later occurrence cannot overwrite immutable source"}])
            previous = max(seen) if seen else None
            if previous is not None and sid < previous:
                pm.add_finding("SECTION_OUT_OF_ORDER", "error", "sections are out of order", "known section ids must be ascending; custom sections may appear anywhere", (sec_start, sec_start + 1), [section["stable_id"], seen[max(seen)]["stable_id"]])
            if sid not in seen:
                seen[sid] = section
                _dispatch_known(sid, data, payload_start, payload_end, pm, section)
        pos = payload_end
        ordinal += 1
    _build_origins(pm)
    return pm


def _read_vector_count(data, start, end, pm, section, what):
    try:
        countv = read_uleb(data, start, end, 32)
    except LEBError as exc:
        pm.add_finding(
            exc.code,
            "fatal",
            f"{what} count {exc.message}",
            "count LEB128 failure is reported without treating non-canonical encoding as overflow",
            (exc.start, exc.end),
            [section["stable_id"]],
        )
        return None, exc.end
    if not countv.canonical:
        pm.add_finding("NONCANONICAL_LEB128", "error", f"non-canonical {what} count", "the count has a valid numeric value but an unnecessary LEB128 continuation", (countv.start, countv.end), [section["stable_id"]])
    return countv.value, countv.end


def _read_name(data, pos, end, pm, section, local):
    start = pos
    try:
        length = read_uleb(data, pos, end, 32)
    except LEBError as exc:
        pm.add_finding(exc.code, "fatal", "name length is malformed", exc.message, (exc.start, exc.end), [section["stable_id"]])
        return None, pos
    if not length.canonical:
        pm.add_finding("NONCANONICAL_LEB128", "error", "non-canonical name length", "name length is numeric but over-encoded", (length.start, length.end), [section["stable_id"]])
    nend = length.end + length.value
    if nend > end:
        pm.add_finding("DECLARED_SIZE_OUT_OF_BOUNDS", "fatal", "name exceeds its section", "name interval is bounded by the parent section", (length.start, nend), [section["stable_id"]])
        return None, nend
    raw = data[length.end:nend]
    name = raw.decode("utf-8", errors="surrogateescape")
    return {
        "stable_id": cell_id(pm.module_id, "name", local),
        "value": name,
        "raw_representation": raw.hex(),
        "byte_range": [start, nend],
        "length_leb": length.as_dict(),
        "sources": [section["stable_id"]],
    }, nend


def _valtype(byte: int) -> dict:
    return {"code": f"0x{byte:02x}", "name": VALTYPE_NAMES.get(byte, f"unknown-0x{byte:02x}"), "known": byte in VALTYPE_NAMES}


def _read_type_vector(data, pos, end, pm, section, local_prefix):
    count, pos = _read_vector_count(data, pos, end, pm, section, "value type")
    if count is None:
        return None, pos
    types = []
    for i in range(count):
        start = pos
        if pos >= end:
            pm.add_finding("DECLARED_SIZE_OUT_OF_BOUNDS", "fatal", "value type is truncated", "declared result/parameter type count exceeds the section", (start, end), [section["stable_id"]])
            return None, pos
        vt = _valtype(data[pos])
        pos += 1
        if not vt["known"]:
            pm.add_finding("UNKNOWN_VALUE_TYPE", "fatal", "unknown value type byte", "the byte is not a number/reference type in the enabled grammar", (start, pos), [section["stable_id"]])
        item = {"stable_id": cell_id(pm.module_id, "valtype", f"{local_prefix}[{i}]"), "index": i, **vt, "byte_range": [start, pos], "sources": [section["stable_id"]]}
        pm.add_cell("valtype", f"{local_prefix}[{i}]", vt["code"], (start, pos), [section["stable_id"]], name=vt["name"])
        types.append(item)
    return [{"name": t["name"], "code": t["code"]} for t in types], pos


def _dispatch_known(sid, data, start, end, pm, section):
    if sid == 1:
        _parse_types(data, start, end, pm, section)
    elif sid == 2:
        _parse_imports(data, start, end, pm, section)
    elif sid == 3:
        _parse_functions(data, start, end, pm, section)
    elif sid == 7:
        _parse_exports(data, start, end, pm, section)
    elif sid == 10:
        _parse_code(data, start, end, pm, section)
    else:
        section["preserved_payload_hex"] = data[start:end].hex()


def _parse_types(data, start, end, pm, section):
    count, pos = _read_vector_count(data, start, end, pm, section, "type")
    if count is None:
        return
    for i in range(count):
        tstart = pos
        if pos >= end or data[pos] != 0x60:
            br = (pos, min(pos + 1, end))
            pm.add_finding("INVALID_FUNC_TYPE", "fatal", "function type marker missing", "function type vector entries must begin with 0x60", br, [section["stable_id"]])
            return
        marker_start = pos
        pos += 1
        params, pos = _read_type_vector(data, pos, end, pm, section, f"type[{i}].params")
        if params is None:
            return
        results_start = pos
        results, pos = _read_type_vector(data, pos, end, pm, section, f"type[{i}].results")
        if results is None:
            return
        item = {
            "stable_id": cell_id(pm.module_id, "type", str(i)),
            "index": i,
            "form": {"code": "0x60", "name": "func"},
            "params": params,
            "results": results,
            "byte_range": [tstart, pos],
            "marker_range": [marker_start, marker_start + 1],
            "results_range": [results_start, pos],
            "sources": [section["stable_id"]],
        }
        pm.types.append(item)


def _parse_imports(data, start, end, pm, section):
    count, pos = _read_vector_count(data, start, end, pm, section, "import")
    if count is None:
        return
    for i in range(count):
        istart = pos
        module_name, pos = _read_name(data, pos, end, pm, section, f"import[{i}].module")
        if module_name is None:
            return
        field_name, pos = _read_name(data, pos, end, pm, section, f"import[{i}].field")
        if field_name is None:
            return
        if pos >= end:
            pm.add_finding("DECLARED_SIZE_OUT_OF_BOUNDS", "fatal", "import kind truncated", "import descriptor requires a kind byte", (pos, end), [section["stable_id"]])
            return
        kind = data[pos]
        kind_range = (pos, pos + 1)
        pos += 1
        item = {
            "stable_id": cell_id(pm.module_id, "import", str(i)),
            "index": i,
            "module": module_name,
            "field": field_name,
            "kind_code": kind,
            "kind": {0: "function", 1: "table", 2: "memory", 3: "global"}.get(kind, "unknown"),
            "byte_range": [istart, end],
            "kind_range": list(kind_range),
            "sources": [section["stable_id"]],
        }
        if kind == 0:
            try:
                tv = read_uleb(data, pos, end, 32)
            except LEBError as exc:
                pm.add_finding(exc.code, "fatal", "imported function type index malformed", exc.message, (exc.start, exc.end), [section["stable_id"]])
                return
            if not tv.canonical:
                pm.add_finding("NONCANONICAL_LEB128", "error", "non-canonical import type index", "type index is numeric but over-encoded", (tv.start, tv.end), [section["stable_id"]])
            item["type_index"] = tv.value
            item["type_index_leb"] = tv.as_dict()
            item["byte_range"][1] = tv.end
            pos = tv.end
        else:
            item["preserved_descriptor_hex"] = data[pos:end].hex()
            pos = end
        pm.imports.append(item)


def _parse_functions(data, start, end, pm, section):
    count, pos = _read_vector_count(data, start, end, pm, section, "function")
    if count is None:
        return
    for i in range(count):
        fstart = pos
        try:
            tv = read_uleb(data, pos, end, 32)
        except LEBError as exc:
            pm.add_finding(exc.code, "fatal", "function type index malformed", exc.message, (exc.start, exc.end), [section["stable_id"]])
            return
        if not tv.canonical:
            pm.add_finding("NONCANONICAL_LEB128", "error", "non-canonical function type index", "type index is numeric but over-encoded", (tv.start, tv.end), [section["stable_id"]])
        pm.functions.append({
            "stable_id": cell_id(pm.module_id, "defined-func", str(i)),
            "defined_index": i,
            "type_index": tv.value,
            "type_index_leb": tv.as_dict(),
            "byte_range": [fstart, tv.end],
            "sources": [section["stable_id"]],
        })
        pos = tv.end


def _parse_exports(data, start, end, pm, section):
    count, pos = _read_vector_count(data, start, end, pm, section, "export")
    if count is None:
        return
    for i in range(count):
        estart = pos
        name, pos = _read_name(data, pos, end, pm, section, f"export[{i}].name")
        if name is None:
            return
        if pos + 1 >= end:
            pm.add_finding("DECLARED_SIZE_OUT_OF_BOUNDS", "fatal", "export descriptor truncated", "export requires kind and index", (pos, end), [section["stable_id"]])
            return
        kind = data[pos]
        idxstart = pos + 1
        try:
            idx = read_uleb(data, idxstart, end, 32)
        except LEBError as exc:
            pm.add_finding(exc.code, "fatal", "export index malformed", exc.message, (exc.start, exc.end), [section["stable_id"]])
            return
        pm.exports.append({
            "stable_id": cell_id(pm.module_id, "export", str(i)),
            "index": i,
            "name": name,
            "kind": {0: "function", 1: "table", 2: "memory", 3: "global"}.get(kind, "unknown"),
            "target_index": idx.value,
            "byte_range": [estart, idx.end],
            "sources": [section["stable_id"]],
        })
        pos = idx.end


def _parse_code(data, start, end, pm, section):
    count, pos = _read_vector_count(data, start, end, pm, section, "code body")
    if count is None:
        return
    for i in range(count):
        bstart = pos
        try:
            size = read_uleb(data, pos, end, 32)
        except LEBError as exc:
            pm.add_finding(exc.code, "fatal", "code body size malformed", exc.message, (exc.start, exc.end), [section["stable_id"]])
            return
        body_end = size.end + size.value
        if body_end > end:
            pm.add_finding("DECLARED_SIZE_OUT_OF_BOUNDS", "fatal", "code body exceeds code section", "body size is numeric but its interval leaves the parent section", (size.start, body_end), [section["stable_id"]])
            return
        pm.code_bodies.append({
            "stable_id": cell_id(pm.module_id, "code-body", str(i)),
            "defined_index": i,
            "size": size.as_dict(),
            "byte_range": [bstart, body_end],
            "declared_range": [size.end, body_end],
            "raw_expression_hex": data[size.end:body_end].hex(),
            "sources": [section["stable_id"]],
        })
        pos = body_end


def _parse_custom(data, start, end, pm, section):
    name, after = _read_name(data, start, end, pm, section, f"section-{section['ordinal']}.name")
    payload_start = after if name else end
    return {
        "name": name,
        "payload_range": [payload_start, end],
        "payload_hex": data[payload_start:end].hex(),
        "preserved_raw_range": section["raw_range"],
    }


def _build_origins(pm):
    imported_funcs = [x for x in pm.imports if x.get("kind") == "function"]
    for imp in imported_funcs:
        pm.index_origins.append({
            "stable_id": cell_id(pm.module_id, "function-index-origin", str(imp["index"])),
            "index_space": "function",
            "index": imp["index"],
            "origin": "import",
            "source_id": imp["stable_id"],
            "type_index": imp.get("type_index"),
        })
    for fn in pm.functions:
        idx = len(imported_funcs) + fn["defined_index"]
        pm.index_origins.append({
            "stable_id": cell_id(pm.module_id, "function-index-origin", str(idx)),
            "index_space": "function",
            "index": idx,
            "origin": "defined",
            "source_id": fn["stable_id"],
            "type_index": fn["type_index"],
        })


def as_dict(pm: ParsedModule) -> dict:
    return {
        "module_id": pm.module_id,
        "raw": pm.raw,
        "status": pm.status,
        "sections": pm.sections,
        "types": pm.types,
        "imports": pm.imports,
        "functions": pm.functions,
        "exports": pm.exports,
        "code_bodies": pm.code_bodies,
        "index_origins": pm.index_origins,
        "cells": pm.cells,
        "findings": pm.findings,
    }
