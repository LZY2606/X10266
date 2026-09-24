"""Module parser: section map, LEB128 records, index-space content.

Every parsed value keeps its original byte range (unit=byte, basis=module)
and raw representation; normalisation happens only in the derived layer.
"""
from __future__ import annotations

import hashlib

from .leb import decode_unsigned, LebError

SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "datacount",
}

VALTYPE_NAMES = {
    0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64",
    0x7B: "v128", 0x70: "funcref", 0x6F: "externref",
}

IMPORT_KIND_NAMES = {0: "func", 1: "table", 2: "memory", 3: "global"}


def diag(kind: str, start: int, end: int, message: str, **extra) -> dict:
    d = {
        "kind": kind,
        "byte_range": {"start": start, "end": end, "unit": "byte", "basis": "module"},
        "message": message,
    }
    d.update(extra)
    return d


class ParseAbort(Exception):
    pass


class Cursor:
    def __init__(self, data: bytes, pos: int, end: int, lebs: list, diags: list, ctx: str):
        self.data = data
        self.pos = pos
        self.end = end
        self.lebs = lebs
        self.diags = diags
        self.ctx = ctx

    def _record_leb(self, leb, what: str):
        self.lebs.append({
            "context": f"{self.ctx}.{what}",
            "value": leb.value,
            "start": leb.start,
            "end": leb.end,
            "raw": leb.raw.hex(),
            "canonical": leb.canonical,
            "unit": "byte",
            "basis": "module",
        })
        if not leb.canonical:
            self.diags.append(diag(
                "noncanonical_leb", leb.start, leb.end,
                f"{self.ctx}.{what}: overlong LEB128 encoding of {leb.value}",
                leb_raw=leb.raw.hex(), leb_value=leb.value,
            ))

    def u32(self, what: str) -> int:
        try:
            leb = decode_unsigned(self.data, self.pos, 32)
        except LebError as e:
            self.diags.append(diag(e.kind, e.start, e.end, f"{self.ctx}.{what}: {e}"))
            raise ParseAbort
        self._record_leb(leb, what)
        self.pos = leb.end
        return leb.value

    def byte(self, what: str) -> int:
        if self.pos >= self.end:
            self.diags.append(diag("truncated_section", self.pos, self.pos,
                                   f"{self.ctx}.{what}: unexpected end of section"))
            raise ParseAbort
        b = self.data[self.pos]
        self.pos += 1
        return b

    def bytes(self, n: int, what: str) -> bytes:
        if self.pos + n > self.end:
            self.diags.append(diag("truncated_section", self.pos, self.end,
                                   f"{self.ctx}.{what}: need {n} bytes, have {self.end - self.pos}"))
            raise ParseAbort
        b = self.data[self.pos:self.pos + n]
        self.pos += n
        return b

    def name(self, what: str):
        n = self.u32(what + ".len")
        raw = self.bytes(n, what)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            self.diags.append(diag("invalid_utf8", self.pos - n, self.pos,
                                   f"{self.ctx}.{what}: invalid UTF-8"))
            return None


def _parse_valtype(cur: Cursor, what: str) -> dict:
    start = cur.pos
    b = cur.byte(what)
    t = VALTYPE_NAMES.get(b)
    if t is None:
        cur.diags.append(diag("unknown_valtype", start, cur.pos,
                              f"{what}: unknown valtype byte 0x{b:02x}"))
    return {"type": t, "start": start, "end": cur.pos, "raw": f"{b:02x}"}


def _parse_types(data, sec, lebs, diags):
    cur = Cursor(data, sec["payload_start"], sec["payload_end"], lebs, diags, "type")
    types = []
    try:
        count = cur.u32("count")
        for i in range(count):
            tstart = cur.pos
            form = cur.byte(f"type[{i}].form")
            if form != 0x60:
                diags.append(diag("unknown_type_form", tstart, cur.pos,
                                  f"type[{i}] form 0x{form:02x}, expected 0x60"))
                raise ParseAbort
            nparams = cur.u32(f"type[{i}].params.count")
            params = [_parse_valtype(cur, f"type[{i}].params[{j}]") for j in range(nparams)]
            nresults = cur.u32(f"type[{i}].results.count")
            results = [_parse_valtype(cur, f"type[{i}].results[{j}]") for j in range(nresults)]
            types.append({
                "index": i,
                "params": [p["type"] for p in params],
                "results": [r["type"] for r in results],
                "params_raw": params,
                "results_raw": results,
                "start": tstart,
                "end": cur.pos,
            })
    except ParseAbort:
        pass
    return types


def _parse_limits(cur: Cursor, what: str):
    flag = cur.byte(what + ".flags")
    cur.u32(what + ".min")
    if flag & 0x01:
        cur.u32(what + ".max")


def _parse_imports(data, sec, lebs, diags):
    cur = Cursor(data, sec["payload_start"], sec["payload_end"], lebs, diags, "import")
    entries = []
    try:
        count = cur.u32("count")
        for i in range(count):
            start = cur.pos
            mod = cur.name(f"import[{i}].module")
            nm = cur.name(f"import[{i}].name")
            kstart = cur.pos
            kind = cur.byte(f"import[{i}].kind")
            entry = {"index": i, "module": mod, "name": nm,
                     "kind": IMPORT_KIND_NAMES.get(kind), "start": start}
            if kind == 0:
                entry["type_idx"] = cur.u32(f"import[{i}].type_idx")
            elif kind == 1:
                cur.byte(f"import[{i}].reftype")
                _parse_limits(cur, f"import[{i}].limits")
            elif kind == 2:
                _parse_limits(cur, f"import[{i}].limits")
            elif kind == 3:
                _parse_valtype(cur, f"import[{i}].globaltype")
                cur.byte(f"import[{i}].mutability")
            else:
                diags.append(diag("unknown_import_kind", kstart, cur.pos,
                                  f"import[{i}] kind byte 0x{kind:02x}"))
                raise ParseAbort
            entry["end"] = cur.pos
            entries.append(entry)
    except ParseAbort:
        pass
    return entries


def _parse_functions(data, sec, lebs, diags):
    cur = Cursor(data, sec["payload_start"], sec["payload_end"], lebs, diags, "function")
    funcs = []
    try:
        count = cur.u32("count")
        for i in range(count):
            start = cur.pos
            tidx = cur.u32(f"function[{i}].type_idx")
            funcs.append({"index": i, "type_idx": tidx, "start": start, "end": cur.pos})
    except ParseAbort:
        pass
    return funcs


def _parse_codes(data, sec, lebs, diags):
    cur = Cursor(data, sec["payload_start"], sec["payload_end"], lebs, diags, "code")
    codes = []
    try:
        count = cur.u32("count")
        for i in range(count):
            start = cur.pos
            size = cur.u32(f"code[{i}].size")
            body_end = cur.pos + size
            if body_end > cur.end:
                diags.append(diag("section_size_out_of_range", start, cur.pos,
                                  f"code[{i}] body of {size} bytes exceeds code section"))
                body_end = cur.end
            body = Cursor(data, cur.pos, body_end, lebs, diags, f"code[{i}]")
            locals_ = []
            try:
                nloc = body.u32("locals.count")
                for j in range(nloc):
                    lstart = body.pos
                    n = body.u32(f"locals[{j}].count")
                    t = _parse_valtype(body, f"locals[{j}].type")
                    locals_.append({"count": n, "type": t["type"],
                                    "start": lstart, "end": body.pos})
            except ParseAbort:
                pass
            codes.append({"index": i, "start": start, "end": body_end,
                          "locals": locals_,
                          "expr_start": body.pos, "expr_end": body_end})
            cur.pos = body_end
    except ParseAbort:
        pass
    return codes


def parse_module(data: bytes) -> dict:
    lebs: list = []
    diags: list = []
    sections: list = []
    header = {
        "magic_ok": False, "version": None,
        "byte_range": {"start": 0, "end": min(8, len(data)), "unit": "byte", "basis": "module"},
    }
    if len(data) >= 4 and data[:4] == b"\x00asm":
        header["magic_ok"] = True
    else:
        diags.append(diag("bad_magic", 0, min(4, len(data)), "missing \\0asm magic"))
    if len(data) < 8:
        diags.append(diag("truncated_header", len(data), len(data),
                          "module shorter than 8-byte header"))
        return {"header": header, "sections": sections, "lebs": lebs,
                "diagnostics": diags, "types": [], "imports": [],
                "functions": [], "codes": []}
    header["version"] = int.from_bytes(data[4:8], "little")
    if header["version"] != 1:
        diags.append(diag("unsupported_version", 4, 8,
                          f"unsupported version {header['version']}"))

    pos = 8
    last_known = 0
    seen: set = set()
    index = 0
    while pos < len(data):
        sec_start = pos
        sec_id = data[pos]
        pos += 1
        try:
            size = decode_unsigned(data, pos, 32)
        except LebError as e:
            diags.append(diag(e.kind, e.start, e.end, f"section[{index}] size: {e}"))
            break
        lebs.append({
            "context": f"section[{index}].size", "value": size.value,
            "start": size.start, "end": size.end, "raw": size.raw.hex(),
            "canonical": size.canonical, "unit": "byte", "basis": "module",
        })
        if not size.canonical:
            diags.append(diag("noncanonical_leb", size.start, size.end,
                              f"section[{index}] size uses non-canonical LEB128 for {size.value}",
                              leb_raw=size.raw.hex(), leb_value=size.value))
        pos = size.end
        payload_start = pos
        payload_end = pos + size.value
        if payload_end > len(data):
            diags.append(diag("section_size_out_of_range", size.start, size.end,
                              f"section[{index}] declares {size.value} bytes beyond module end"))
            payload_end = len(data)
        payload = data[payload_start:payload_end]
        sec = {
            "index": index, "id": sec_id, "name": SECTION_NAMES.get(sec_id),
            "start": sec_start, "end": payload_end,
            "size": {"value": size.value, "start": size.start, "end": size.end,
                     "raw": size.raw.hex(), "canonical": size.canonical},
            "payload_start": payload_start, "payload_end": payload_end,
            "unit": "byte", "basis": "module",
        }
        if sec_id == 0:
            cur = Cursor(data, payload_start, payload_end, lebs, diags,
                         f"section[{index}](custom)")
            try:
                sec["custom_name"] = cur.name("name")
            except ParseAbort:
                sec["custom_name"] = None
            sec["sha256"] = hashlib.sha256(payload).hexdigest()
            sec["raw_hex"] = payload.hex()
        elif sec_id not in SECTION_NAMES:
            diags.append(diag("unknown_section_id", sec_start, sec_start + 1,
                              f"unknown section id {sec_id}"))
        else:
            if sec_id in seen:
                diags.append(diag("duplicate_section", sec_start, sec_start + 1,
                                  f"duplicate {SECTION_NAMES[sec_id]} section",
                                  section=SECTION_NAMES[sec_id]))
            elif sec_id < last_known:
                diags.append(diag("section_out_of_order", sec_start, sec_start + 1,
                                  f"{SECTION_NAMES[sec_id]} section appears out of order",
                                  section=SECTION_NAMES[sec_id]))
            seen.add(sec_id)
            last_known = max(last_known, sec_id)
        sections.append(sec)
        pos = payload_end
        index += 1

    result = {"header": header, "sections": sections, "lebs": lebs,
              "diagnostics": diags, "types": [], "imports": [],
              "functions": [], "codes": []}
    parsed_ids: set = set()
    for sec in sections:
        sid = sec["id"]
        if sid in parsed_ids or sid not in (1, 2, 3, 10):
            continue
        parsed_ids.add(sid)
        if sid == 1:
            result["types"] = _parse_types(data, sec, lebs, diags)
        elif sid == 2:
            result["imports"] = _parse_imports(data, sec, lebs, diags)
        elif sid == 3:
            result["functions"] = _parse_functions(data, sec, lebs, diags)
        elif sid == 10:
            result["codes"] = _parse_codes(data, sec, lebs, diags)
    return result
