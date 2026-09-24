"""WebAssembly binary parsing and validation core.

First-class domain distinctions kept as machine-readable data:
- non-canonical LEB128 encodings vs numeric range violations
- polymorphic stack behaviour (only valid inside unreachable regions)
- capability-missing opcodes (known proposal, disabled) vs unknown bytes

Every error carries the minimal failing byte range and an "origin" record
describing where an index or value came from.
"""
from __future__ import annotations

import hashlib

import numpy as np

ALGO_VERSION = "wasmcore/1.0.0"

SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "data_count",
}
SECTION_ORDER = [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 10, 11]

VALTYPES = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64",
            0x7B: "v128", 0x70: "funcref", 0x6F: "externref"}
VALTYPE_PROPOSAL = {"v128": "simd", "funcref": "reference-types",
                    "externref": "reference-types"}

KNOWN_PROPOSALS = ["multi-value", "bulk-memory", "reference-types", "simd", "tail-call"]

OPCODE_INFO = {
    0x00: ("unreachable", "core"), 0x01: ("nop", "core"),
    0x02: ("block", "core"), 0x03: ("loop", "core"), 0x04: ("if", "core"),
    0x05: ("else", "core"), 0x0B: ("end", "core"),
    0x0C: ("br", "core"), 0x0D: ("br_if", "core"), 0x0F: ("return", "core"),
    0x10: ("call", "core"),
    0x1A: ("drop", "core"), 0x1B: ("select", "core"),
    0x1C: ("select_t", "reference-types"),
    0x20: ("local.get", "core"), 0x21: ("local.set", "core"), 0x22: ("local.tee", "core"),
    0x23: ("global.get", "core"), 0x24: ("global.set", "core"),
    0x28: ("i32.load", "core"), 0x36: ("i32.store", "core"),
    0x41: ("i32.const", "core"), 0x42: ("i64.const", "core"),
    0x43: ("f32.const", "core"), 0x44: ("f64.const", "core"),
    0x45: ("i32.eqz", "core"), 0x46: ("i32.eq", "core"),
    0x6A: ("i32.add", "core"), 0x6B: ("i32.sub", "core"), 0x6C: ("i32.mul", "core"),
    0x7C: ("i64.add", "core"),
    0x92: ("f32.add", "core"), 0xA0: ("f64.add", "core"),
    0xD0: ("ref.null", "reference-types"),
    0xFC: ("misc_prefix", "bulk-memory"), 0xFD: ("simd_prefix", "simd"),
}

UNKNOWN = "?"  # polymorphic stack slot


class WasmError(Exception):
    def __init__(self, code, message, start, end, details=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.start = start
        self.end = end
        self.details = details or {}

    def to_dict(self, origin=None):
        return {"code": self.code, "message": self.message,
                "range": {"start": self.start, "end": self.end},
                "origin": origin or {}, "details": self.details}


def _err(code, message, start, end, origin=None, details=None):
    return {"code": code, "message": message,
            "range": {"start": start, "end": end},
            "origin": origin or {}, "details": details or {}}


def _minimal_uleb_len(value):
    n = 1
    while value >= (1 << (7 * n)):
        n += 1
    return n


def read_uleb(data, pos, bits=32):
    """Unsigned LEB128. Non-canonical form and numeric overflow are
    reported as two distinct error codes."""
    start = pos
    result = 0
    shift = 0
    max_bytes = (bits + 6) // 7
    while True:
        if pos >= len(data):
            raise WasmError("truncated_leb128", "LEB128 runs past end of input", start, pos)
        byte = data[pos]
        pos += 1
        if pos - start > max_bytes:
            raise WasmError("noncanonical_leb128",
                            f"LEB128 longer than {max_bytes} bytes for u{bits}",
                            start, pos, {"bits": bits})
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            break
    if result >= (1 << bits):
        raise WasmError("value_out_of_range",
                        f"value {result} does not fit u{bits}",
                        start, pos, {"bits": bits, "value": result})
    info = {"start": start, "end": pos, "hex": data[start:pos].hex(),
            "noncanonical": (pos - start) > _minimal_uleb_len(result)}
    return result, pos, info


def read_sleb(data, pos, bits=32):
    start = pos
    result = 0
    shift = 0
    max_bytes = (bits + 6) // 7
    while True:
        if pos >= len(data):
            raise WasmError("truncated_leb128", "LEB128 runs past end of input", start, pos)
        byte = data[pos]
        pos += 1
        if pos - start > max_bytes:
            raise WasmError("noncanonical_leb128",
                            f"LEB128 longer than {max_bytes} bytes for s{bits}",
                            start, pos, {"bits": bits})
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            if shift < bits and (byte & 0x40):
                result |= -(1 << shift)
            break
    if result < -(1 << (bits - 1)) or result >= (1 << (bits - 1)):
        raise WasmError("value_out_of_range",
                        f"value {result} does not fit s{bits}",
                        start, pos, {"bits": bits, "value": result})
    info = {"start": start, "end": pos, "hex": data[start:pos].hex(),
            "noncanonical": False}
    return result, pos, info


def read_name(data, pos):
    length, pos, leb = read_uleb(data, pos, 32)
    start = pos
    end = pos + length
    if end > len(data):
        raise WasmError("truncated_name", "name runs past end of input", start, len(data))
    raw = data[start:end]
    try:
        text = raw.decode("utf-8")
        utf8 = True
    except UnicodeDecodeError:
        text = raw.decode("utf-8", "replace")
        utf8 = False
    return {"text": text, "utf8": utf8, "range": [start, end], "len_leb": leb}, end


def _read_valtype(data, pos, proposals):
    if pos >= len(data):
        raise WasmError("truncated_valtype", "value type missing", pos, pos)
    byte = data[pos]
    if byte not in VALTYPES:
        raise WasmError("unknown_valtype", f"unknown value type byte 0x{byte:02x}", pos, pos + 1)
    name = VALTYPES[byte]
    needed = VALTYPE_PROPOSAL.get(name)
    if needed and needed not in proposals:
        raise WasmError("capability_missing",
                        f"value type {name} requires proposal '{needed}'",
                        pos, pos + 1, {"proposal": needed})
    return name, pos + 1


def _read_limits(data, pos):
    if pos >= len(data):
        raise WasmError("truncated_limits", "limits flags missing", pos, pos)
    flags = data[pos]
    pos += 1
    if flags not in (0, 1):
        raise WasmError("malformed_limits", f"unsupported limits flags {flags}", pos - 1, pos)
    minimum, pos, _ = read_uleb(data, pos, 32)
    maximum = None
    if flags == 1:
        maximum, pos, _ = read_uleb(data, pos, 32)
    return {"min": minimum, "max": maximum}, pos


def parse_sections(wasm, proposals):
    """Split the module into sections, keeping raw byte ranges, LEB128
    encodings and custom-section payloads. Order/duplicate violations are
    collected as errors, never silently repaired."""
    errors = []
    sections = []
    if len(wasm) < 8 or wasm[:4] != b"\x00asm":
        errors.append(_err("bad_magic", "missing \\0asm magic", 0, min(4, len(wasm))))
        return sections, errors
    if wasm[4:8] != b"\x01\x00\x00\x00":
        errors.append(_err("bad_version", "unsupported binary version", 4, 8,
                           details={"version_hex": wasm[4:8].hex()}))
    pos = 8
    seen = set()
    last_order = -1
    while pos < len(wasm):
        sec_start = pos
        sid = wasm[pos]
        pos += 1
        try:
            size, pos, size_leb = read_uleb(wasm, pos, 32)
        except WasmError as exc:
            errors.append(exc.to_dict(origin={"section_id": sid, "field": "section_size"}))
            break
        content_start = pos
        content_end = pos + size
        if content_end > len(wasm):
            errors.append(_err("section_size_out_of_bounds",
                               f"section {sid} declares {size} bytes past end of module",
                               content_start, len(wasm),
                               origin={"section_id": sid}))
            break
        sec = {"id": sid, "name": SECTION_NAMES.get(sid, f"unknown_{sid}"),
               "range": [sec_start, content_end], "size": size,
               "size_leb": size_leb, "content_range": [content_start, content_end]}
        if sid == 0:
            content = wasm[content_start:content_end]
            try:
                cname, payload_off = read_name(content, 0)
                payload = content[payload_off:]
                sec["custom"] = {
                    "name": cname["text"], "name_utf8": cname["utf8"],
                    "name_range": [content_start + cname["range"][0],
                                   content_start + cname["range"][1]],
                    "payload_sha256": hashlib.sha256(payload).hexdigest(),
                    "payload_len": len(payload),
                    "payload_hex": payload.hex(),
                }
            except WasmError as exc:
                errors.append(exc.to_dict(origin={"section_id": 0, "field": "custom_name"}))
        else:
            if sid in seen:
                errors.append(_err("section_duplicate",
                                   f"section '{sec['name']}' appears more than once",
                                   sec_start, content_start,
                                   origin={"section_id": sid}))
            else:
                seen.add(sid)
                if sid not in SECTION_ORDER:
                    errors.append(_err("unknown_section_id",
                                       f"unknown section id {sid}", sec_start, sec_start + 1,
                                       origin={"section_id": sid}))
                else:
                    order = SECTION_ORDER.index(sid)
                    if order < last_order:
                        errors.append(_err("section_out_of_order",
                                           f"section '{sec['name']}' is out of canonical order",
                                           sec_start, content_start,
                                           origin={"section_id": sid}))
                    last_order = max(last_order, order)
        sections.append(sec)
        pos = content_end
    return sections, errors


def validate_expr(wasm, pos, end, ftype, ctx, proposals, func_index):
    """Validate one function body expression with an explicit control stack
    and type stack. The polymorphic stack (UNKNOWN slots) is only produced
    inside unreachable regions, per the spec validation algorithm.

    Returns (transitions, control_trace, errors, flags).
    """
    transitions = []
    control_trace = []
    errors = []
    flags = {"used_polymorphic_stack": False}
    vals = []
    ctrls = [{"opcode": "block", "start": [], "end": list(ftype["results"]),
              "height": 0, "unreachable": False, "offset": pos}]
    control_trace.append({"event": "push_frame", "frame": "function",
                          "offset": pos, "end_types": list(ftype["results"])})

    def frame():
        return ctrls[-1]

    def push(t, pushes):
        vals.append(t)
        pushes.append(t)

    def pop():
        frm = frame()
        if len(vals) == frm["height"]:
            if frm["unreachable"]:
                flags["used_polymorphic_stack"] = True
                return UNKNOWN
            raise WasmError("stack_underflow",
                            "operand stack empty at control frame boundary",
                            op_off, pos)
        return vals.pop()

    def pop_expect(expect):
        actual = pop()
        if actual is UNKNOWN:
            return expect
        if expect is UNKNOWN:
            return actual
        if actual != expect:
            raise WasmError("type_mismatch",
                            f"expected {expect}, got {actual}", op_off, pos,
                            {"expected": expect, "actual": actual})
        return actual

    def pop_vals(types, pops):
        for t in reversed(types):
            pop_expect(t)
            pops.append(t)

    def push_vals(types, pushes):
        for t in types:
            push(t, pushes)

    def set_unreachable():
        frm = frame()
        del vals[frm["height"]:]
        frm["unreachable"] = True
        control_trace.append({"event": "unreachable", "offset": op_off,
                              "frame_depth": len(ctrls)})

    def label_types(idx, off):
        if idx >= len(ctrls):
            raise WasmError("label_out_of_range",
                            f"label index {idx} exceeds control depth {len(ctrls)}",
                            off, off + 1,
                            {"index_source": "br_immediate", "index": idx})
        frm = ctrls[-1 - idx]
        return frm["start"] if frm["opcode"] == "loop" else frm["end"]

    while pos < end:
        op_off = pos
        op = wasm[pos]
        pos += 1
        pops, pushes = [], []
        name, proposal = OPCODE_INFO.get(op, (None, None))
        try:
            if name is None:
                raise WasmError("unknown_opcode",
                                f"byte 0x{op:02x} is not a known opcode in any registered proposal",
                                op_off, pos, {"byte": f"0x{op:02x}"})
            if proposal != "core" and proposal not in proposals:
                raise WasmError("capability_missing",
                                f"opcode {name} requires proposal '{proposal}' which is not enabled",
                                op_off, pos, {"proposal": proposal, "opcode": name})
            if op == 0x00:  # unreachable
                set_unreachable()
            elif op == 0x01:  # nop
                pass
            elif op in (0x02, 0x03, 0x04):  # block / loop / if
                params, results, pos = _read_blocktype(wasm, pos, ctx["types"], proposals, op_off)
                if op == 0x04:
                    pop_expect("i32")
                    pops.append("i32")
                pop_vals(params, pops)
                ctrls.append({"opcode": name, "start": params, "end": results,
                              "height": len(vals), "unreachable": False,
                              "offset": op_off})
                control_trace.append({"event": "push_frame", "frame": name,
                                      "offset": op_off, "start_types": params,
                                      "end_types": results})
                push_vals(params, pushes)
            elif op == 0x05:  # else
                frm = frame()
                if frm["opcode"] != "if":
                    raise WasmError("else_without_if", "else without matching if", op_off, pos)
                pop_vals(frm["end"], pops)
                if len(vals) != frm["height"]:
                    raise WasmError("stack_height_mismatch",
                                    "operand stack height differs from frame entry",
                                    op_off, pos)
                ctrls[-1] = {"opcode": "else", "start": frm["end"], "end": frm["end"],
                             "height": len(vals), "unreachable": False, "offset": op_off}
                control_trace.append({"event": "else", "offset": op_off})
                push_vals(frm["end"], pushes)
            elif op == 0x0B:  # end
                frm = ctrls[-1]
                pop_vals(frm["end"], pops)
                if len(vals) != frm["height"]:
                    raise WasmError("stack_height_mismatch",
                                    f"stack height {len(vals)} != frame height {frm['height']} at end",
                                    op_off, pos)
                ctrls.pop()
                control_trace.append({"event": "pop_frame", "frame": frm["opcode"],
                                      "offset": op_off, "end_types": frm["end"]})
                push_vals(frm["end"], pushes)
                if not ctrls:
                    if pos != end:
                        raise WasmError("trailing_bytes_after_end",
                                        "bytes remain after function end", pos, end)
                    pos = end
                    break
            elif op == 0x0C:  # br
                idx, pos, _ = read_uleb(wasm, op_off + 1, 32)
                pop_vals(label_types(idx, op_off), pops)
                set_unreachable()
            elif op == 0x0D:  # br_if
                idx, pos, _ = read_uleb(wasm, op_off + 1, 32)
                pop_expect("i32")
                pops.append("i32")
                lt = label_types(idx, op_off)
                pop_vals(lt, pops)
                push_vals(lt, pushes)
            elif op == 0x0F:  # return
                pop_vals(ftype["results"], pops)
                set_unreachable()
            elif op == 0x10:  # call
                idx, pos, _ = read_uleb(wasm, op_off + 1, 32)
                if idx >= len(ctx["func_types"]):
                    raise WasmError("index_out_of_range",
                                    f"function index {idx} out of range",
                                    op_off, pos,
                                    {"index_source": "call_immediate", "index": idx,
                                     "space": "funcs"})
                ft = ctx["func_types"][idx]
                pop_vals(ft["params"], pops)
                push_vals(ft["results"], pushes)
            elif op == 0x1A:  # drop
                got = pop()
                pops.append(got)
            elif op == 0x1B:  # select
                pop_expect("i32")
                pops.append("i32")
                first = pop()
                pop_expect(first)
                pops.append(first)
                push(first, pushes)
            elif op == 0x20 or op == 0x21 or op == 0x22:  # local.get/set/tee
                idx, pos, _ = read_uleb(wasm, op_off + 1, 32)
                if idx >= len(ctx["locals"]):
                    raise WasmError("index_out_of_range",
                                    f"local index {idx} out of range", op_off, pos,
                                    {"index_source": "local_immediate", "index": idx,
                                     "space": "locals"})
                lt = ctx["locals"][idx]
                if op == 0x20:
                    push(lt, pushes)
                elif op == 0x21:
                    pop_expect(lt)
                    pops.append(lt)
                else:
                    pop_expect(lt)
                    pops.append(lt)
                    push(lt, pushes)
            elif op == 0x23 or op == 0x24:  # global.get/set
                idx, pos, _ = read_uleb(wasm, op_off + 1, 32)
                if idx >= len(ctx["globals"]):
                    raise WasmError("index_out_of_range",
                                    f"global index {idx} out of range", op_off, pos,
                                    {"index_source": "global_immediate", "index": idx,
                                     "space": "globals"})
                gt = ctx["globals"][idx]
                if op == 0x23:
                    push(gt["valtype"], pushes)
                else:
                    if not gt["mutable"]:
                        raise WasmError("global_immutable",
                                        "cannot global.set an immutable global", op_off, pos)
                    pop_expect(gt["valtype"])
                    pops.append(gt["valtype"])
            elif op == 0x28 or op == 0x36:  # i32.load / i32.store
                if ctx["memories"] == 0:
                    raise WasmError("memory_not_defined",
                                    "memory instruction without a memory", op_off, pos)
                _, pos, _ = read_uleb(wasm, pos, 32)  # align
                _, pos, _ = read_uleb(wasm, pos, 32)  # offset
                pop_expect("i32")
                pops.append("i32")
                if op == 0x28:
                    push("i32", pushes)
                else:
                    pop_expect("i32")
                    pops.append("i32")
            elif op == 0x41:
                _, pos, _ = read_sleb(wasm, pos, 32)
                push("i32", pushes)
            elif op == 0x42:
                _, pos, _ = read_sleb(wasm, pos, 64)
                push("i64", pushes)
            elif op == 0x43:
                if pos + 4 > end:
                    raise WasmError("truncated_immediate", "f32 immediate truncated", op_off, end)
                pos += 4
                push("f32", pushes)
            elif op == 0x44:
                if pos + 8 > end:
                    raise WasmError("truncated_immediate", "f64 immediate truncated", op_off, end)
                pos += 8
                push("f64", pushes)
            elif op in (0x45,):
                pop_expect("i32"); pops.append("i32"); push("i32", pushes)
            elif op in (0x46, 0x6A, 0x6B, 0x6C):
                pop_expect("i32"); pop_expect("i32")
                pops += ["i32", "i32"]; push("i32", pushes)
            elif op == 0x7C:
                pop_expect("i64"); pop_expect("i64")
                pops += ["i64", "i64"]; push("i64", pushes)
            elif op == 0x92:
                pop_expect("f32"); pop_expect("f32")
                pops += ["f32", "f32"]; push("f32", pushes)
            elif op == 0xA0:
                pop_expect("f64"); pop_expect("f64")
                pops += ["f64", "f64"]; push("f64", pushes)
            elif op == 0xD0:  # ref.null
                if pos >= end:
                    raise WasmError("truncated_immediate", "ref.null heap type missing", op_off, pos)
                heap = wasm[pos]; pos += 1
                push(VALTYPES.get(heap, "externref"), pushes)
            elif op == 0xFC:  # bulk-memory prefix
                sub, pos, _ = read_uleb(wasm, pos, 32)
                if sub == 10:  # memory.copy
                    if pos + 2 > end:
                        raise WasmError("truncated_immediate", "memory.copy immediates truncated", op_off, end)
                    pos += 2
                    pop_expect("i32"); pop_expect("i32"); pop_expect("i32")
                    pops += ["i32", "i32", "i32"]
                    name = "memory.copy"
                elif sub == 11:  # memory.fill
                    if pos + 1 > end:
                        raise WasmError("truncated_immediate", "memory.fill immediate truncated", op_off, end)
                    pos += 1
                    pop_expect("i32"); pop_expect("i32"); pop_expect("i32")
                    pops += ["i32", "i32", "i32"]
                    name = "memory.fill"
                else:
                    raise WasmError("unknown_opcode",
                                    f"unknown 0xFC sub-opcode {sub}", op_off, pos,
                                    {"byte": f"0xfc {sub}"})
            elif op == 0xFD:
                raise WasmError("unknown_opcode",
                                "simd sub-opcodes are not modelled by this validator",
                                op_off, pos, {"byte": "0xfd"})
            else:
                raise WasmError("unknown_opcode",
                                f"opcode {name} is registered but not modelled",
                                op_off, pos, {"byte": f"0x{op:02x}"})
        except WasmError as exc:
            errors.append(exc.to_dict(origin={"function": func_index, "offset": op_off}))
            break
        transitions.append({"offset": op_off, "opcode": f"0x{op:02x}", "name": name,
                            "pops": pops, "pushes": pushes, "stack": list(vals)})
    else:
        if ctrls:
            errors.append(_err("unterminated_block",
                               f"{len(ctrls)} control frame(s) not closed at end of body",
                               end, end, origin={"function": func_index}))
    return transitions, control_trace, errors, flags


def _read_blocktype(wasm, pos, types, proposals, op_off):
    if pos >= len(wasm):
        raise WasmError("truncated_blocktype", "blocktype missing", pos, pos)
    byte = wasm[pos]
    if byte == 0x40:
        return [], [], pos + 1
    if byte in VALTYPES:
        return [], [VALTYPES[byte]], pos + 1
    idx, pos2, _ = read_sleb(wasm, pos, 33)
    if idx < 0:
        raise WasmError("value_out_of_range", "negative blocktype type index",
                        pos, pos2, {"value": idx})
    if "multi-value" not in proposals:
        raise WasmError("capability_missing",
                        "blocktype as type index requires proposal 'multi-value'",
                        op_off, pos2, {"proposal": "multi-value"})
    if idx >= len(types):
        raise WasmError("index_out_of_range", f"blocktype type index {idx} out of range",
                        pos, pos2, {"index_source": "blocktype", "index": idx, "space": "types"})
    ft = types[idx]
    return list(ft["params"]), list(ft["results"]), pos2


def validate_module(wasm, proposals, host_imports):
    """Full structural + code validation. Returns a JSON-able dict that
    preserves raw byte ranges, LEB128 encodings, index origins, feature
    switches, import contracts and custom sections."""
    proposals = set(proposals)
    errors = []
    sections, sec_errors = parse_sections(wasm, proposals)
    errors.extend(sec_errors)

    contents = {}
    for sec in sections:
        if sec["id"] not in contents and sec["id"] != 0:
            s, e = sec["content_range"]
            contents[sec["id"]] = (wasm[s:e], s)

    types, imports, func_tidx, globals_, memories, tables = [], [], [], [], [], []
    exports = []
    code_entries = []

    # --- type section ---
    if 1 in contents:
        data, base = contents[1]
        pos = 0
        try:
            count, pos, _ = read_uleb(data, pos, 32)
            for i in range(count):
                tstart = pos
                if data[pos] != 0x60:
                    raise WasmError("expected_functype", "type entry is not a functype",
                                    base + pos, base + pos + 1)
                pos += 1
                nparams, pos, _ = read_uleb(data, pos, 32)
                params = []
                for _ in range(nparams):
                    vt, pos = _read_valtype(data, pos, proposals)
                    params.append(vt)
                nresults, pos, res_leb = read_uleb(data, pos, 32)
                results = []
                for _ in range(nresults):
                    vt, pos = _read_valtype(data, pos, proposals)
                    results.append(vt)
                if len(results) > 1 and "multi-value" not in proposals:
                    errors.append(_err(
                        "capability_missing",
                        f"type {i} has {len(results)} results; requires proposal 'multi-value'",
                        base + tstart, base + pos,
                        origin={"type_index": i}, details={"proposal": "multi-value"}))
                types.append({"params": params, "results": results,
                              "range": [base + tstart, base + pos]})
        except WasmError as exc:
            errors.append(exc.to_dict(origin={"section": "type", "type_index": len(types)}))

    # --- import section ---
    if 2 in contents:
        data, base = contents[2]
        pos = 0
        try:
            count, pos, _ = read_uleb(data, pos, 32)
            for i in range(count):
                istart = pos
                mod, pos = read_name(data, pos)
                nm, pos = read_name(data, pos)
                kind = data[pos]
                pos += 1
                desc = None
                if kind == 0:
                    tidx, pos, _ = read_uleb(data, pos, 32)
                    if tidx >= len(types):
                        errors.append(_err("index_out_of_range",
                                           f"import type index {tidx} out of range",
                                           base + istart, base + pos,
                                           origin={"index_source": "import_desc",
                                                   "index": tidx, "space": "types"}))
                    desc = {"kind": "func", "type": tidx}
                elif kind == 1:
                    elem = data[pos]; pos += 1
                    lim, pos = _read_limits(data, pos)
                    desc = {"kind": "table", "elem": VALTYPES.get(elem, "?"), "limits": lim}
                    tables.append({"source": "import"})
                elif kind == 2:
                    lim, pos = _read_limits(data, pos)
                    desc = {"kind": "memory", "limits": lim}
                    memories.append({"source": "import"})
                elif kind == 3:
                    vt, pos = _read_valtype(data, pos, proposals)
                    mut = data[pos]; pos += 1
                    desc = {"kind": "global", "valtype": vt, "mutable": bool(mut)}
                    globals_.append({"valtype": vt, "mutable": bool(mut), "source": "import"})
                else:
                    raise WasmError("unknown_import_kind", f"unknown import kind {kind}",
                                    base + pos - 1, base + pos)
                entry = {"module": mod["text"], "name": nm["text"], "desc": desc,
                         "range": [base + istart, base + pos]}
                imports.append(entry)
                if desc and desc["kind"] == "func":
                    func_tidx.append(("import", desc["type"]))
        except WasmError as exc:
            errors.append(exc.to_dict(origin={"section": "import", "import_index": len(imports)}))

    # --- host import contract check ---
    host = {(h["module"], h["name"]): h for h in host_imports}
    for imp in imports:
        key = (imp["module"], imp["name"])
        offer = host.get(key)
        rng = imp["range"]
        if offer is None:
            errors.append(_err("import_not_provided",
                               f"host does not provide {imp['module']}.{imp['name']}",
                               rng[0], rng[1],
                               origin={"import": f"{imp['module']}.{imp['name']}"}))
            continue
        desc = imp["desc"]
        mismatch = None
        if desc["kind"] != offer.get("kind"):
            mismatch = {"kind": (desc["kind"], offer.get("kind"))}
        elif desc["kind"] == "func" and desc["type"] < len(types):
            want = types[desc["type"]]
            got = {"params": offer.get("params", []), "results": offer.get("results", [])}
            if want["params"] != got["params"] or want["results"] != got["results"]:
                mismatch = {"module_type": want, "host_type": got}
        elif desc["kind"] == "global":
            if desc["valtype"] != offer.get("valtype") or desc["mutable"] != offer.get("mutable", False):
                mismatch = {"module_type": desc, "host_type": offer}
        if mismatch:
            errors.append(_err("import_signature_mismatch",
                               f"import {imp['module']}.{imp['name']} does not match host signature",
                               rng[0], rng[1],
                               origin={"import": f"{imp['module']}.{imp['name']}"},
                               details=mismatch))

    # --- function section ---
    defined_tidx = []
    if 3 in contents:
        data, base = contents[3]
        pos = 0
        try:
            count, pos, _ = read_uleb(data, pos, 32)
            for i in range(count):
                tstart = pos
                tidx, pos, _ = read_uleb(data, pos, 32)
                if tidx >= len(types):
                    errors.append(_err("index_out_of_range",
                                       f"function {i} references missing type {tidx}",
                                       base + tstart, base + pos,
                                       origin={"index_source": "function_section",
                                               "index": tidx, "space": "types"}))
                defined_tidx.append(tidx)
                func_tidx.append(("defined", tidx))
        except WasmError as exc:
            errors.append(exc.to_dict(origin={"section": "function",
                                              "entry": len(defined_tidx)}))

    # --- memory / global sections (index spaces only) ---
    if 5 in contents:
        data, base = contents[5]
        pos = 0
        try:
            count, pos, _ = read_uleb(data, pos, 32)
            for _ in range(count):
                lim, pos = _read_limits(data, pos)
                memories.append({"source": "defined", "limits": lim})
        except WasmError as exc:
            errors.append(exc.to_dict(origin={"section": "memory"}))
    if 6 in contents:
        data, base = contents[6]
        pos = 0
        try:
            count, pos, _ = read_uleb(data, pos, 32)
            for _ in range(count):
                vt, pos = _read_valtype(data, pos, proposals)
                mut = data[pos]; pos += 1
                depth = 0
                while pos < len(data):  # skip init expr
                    b = data[pos]; pos += 1
                    if b == 0x0B and depth == 0:
                        break
                    if b in (0x41, 0x42):
                        _, pos, _ = read_sleb(data, pos, 64)
                    elif b == 0x43:
                        pos += 4
                    elif b == 0x44:
                        pos += 8
                    elif b == 0x23:
                        _, pos, _ = read_uleb(data, pos, 32)
                globals_.append({"valtype": vt, "mutable": bool(mut), "source": "defined"})
        except WasmError as exc:
            errors.append(exc.to_dict(origin={"section": "global"}))

    # --- export section ---
    if 7 in contents:
        data, base = contents[7]
        pos = 0
        try:
            count, pos, _ = read_uleb(data, pos, 32)
            for _ in range(count):
                nm, pos = read_name(data, pos)
                kind = data[pos]; pos += 1
                idx, pos, _ = read_uleb(data, pos, 32)
                exports.append({"name": nm["text"], "kind": kind, "index": idx})
        except WasmError as exc:
            errors.append(exc.to_dict(origin={"section": "export"}))

    # --- code section ---
    if 10 in contents:
        data, base = contents[10]
        pos = 0
        try:
            count, pos, _ = read_uleb(data, pos, 32)
            if count != len(defined_tidx):
                errors.append(_err("code_function_count_mismatch",
                                   f"code section has {count} bodies but function section declares {len(defined_tidx)}",
                                   base, base + len(data),
                                   origin={"section": "code"}))
            for i in range(count):
                esize, pos, _ = read_uleb(data, pos, 32)
                estart = pos
                eend = pos + esize
                if eend > len(data):
                    raise WasmError("section_size_out_of_bounds",
                                    "code entry runs past section", base + estart, base + len(data))
                code_entries.append((base + estart, base + eend))
                pos = eend
        except WasmError as exc:
            errors.append(exc.to_dict(origin={"section": "code",
                                              "entry": len(code_entries)}))

    # --- function bodies ---
    func_types = []
    for origin_kind, tidx in func_tidx:
        func_types.append(types[tidx] if tidx < len(types)
                          else {"params": [], "results": []})
    functions = []
    n_imported = len(func_tidx) - len(defined_tidx)
    for di, (bstart, bend) in enumerate(code_entries):
        findex = n_imported + di
        tidx = defined_tidx[di] if di < len(defined_tidx) else 0
        ftype = types[tidx] if tidx < len(types) else {"params": [], "results": []}
        body = wasm[bstart:bend]
        pos = 0
        locals_ = list(ftype["params"])
        try:
            ngroups, pos, _ = read_uleb(body, pos, 32)
            for _ in range(ngroups):
                n, pos, _ = read_uleb(body, pos, 32)
                vt, pos = _read_valtype(body, pos, proposals)
                locals_.extend([vt] * n)
        except WasmError as exc:
            errors.append(exc.to_dict(origin={"function": findex, "field": "locals"}))
            continue
        ctx = {"types": types, "func_types": func_types, "locals": locals_,
               "globals": globals_, "memories": len(memories)}
        transitions, control_trace, ferrs, flags = validate_expr(
            wasm, bstart + pos, bend, ftype, ctx, proposals, findex)
        functions.append({
            "index": findex, "type_index": tidx,
            "type": {"params": ftype["params"], "results": ftype["results"]},
            "body_range": [bstart, bend],
            "body_sha256": hashlib.sha256(wasm[bstart:bend]).hexdigest(),
            "locals": locals_, "control_trace": control_trace,
            "type_transitions": transitions, "errors": ferrs,
            "used_polymorphic_stack": flags["used_polymorphic_stack"],
        })

    index_spaces = {
        "types": [{"index": i, "params": t["params"], "results": t["results"]}
                  for i, t in enumerate(types)],
        "funcs": [{"index": i, "source": kind, "type_index": tidx}
                  for i, (kind, tidx) in enumerate(func_tidx)],
        "globals": [{"index": i, **g} for i, g in enumerate(globals_)],
        "memories": [{"index": i, **m} for i, m in enumerate(memories)],
        "tables": [{"index": i, **t} for i, t in enumerate(tables)],
    }
    custom_sections = [s["custom"] | {"range": s["range"]}
                       for s in sections if s["id"] == 0 and "custom" in s]

    fn_errors = [e for f in functions for e in f["errors"]]
    all_errors = errors + fn_errors

    judgments = []
    leb_form = [e for e in all_errors if e["code"] == "noncanonical_leb128"]
    leb_range = [e for e in all_errors if e["code"] == "value_out_of_range"]
    if leb_form or leb_range:
        judgments.append({
            "rule": "leb128_form_vs_range",
            "basis": "non-canonical LEB128 encodings and numeric range violations are distinct defects",
            "evidence": {"noncanonical": len(leb_form), "out_of_range": len(leb_range)}})
    poly = [f["index"] for f in functions if f["used_polymorphic_stack"]]
    if poly:
        judgments.append({
            "rule": "polymorphic_stack_scope",
            "basis": "polymorphic stack slots were only produced inside unreachable regions",
            "evidence": {"functions": poly}})
    cap = [e for e in all_errors if e["code"] == "capability_missing"]
    unk = [e for e in all_errors if e["code"] == "unknown_opcode"]
    if cap or unk:
        judgments.append({
            "rule": "capability_vs_unknown",
            "basis": "disabled-proposal opcodes report capability_missing; unregistered bytes report unknown_opcode",
            "evidence": {"capability_missing": len(cap), "unknown_opcode": len(unk)}})

    histogram = np.bincount(np.frombuffer(wasm, dtype=np.uint8), minlength=256).tolist()
    return {
        "ok": not all_errors,
        "errors": errors,
        "function_errors": fn_errors,
        "sections": sections,
        "index_spaces": index_spaces,
        "imports": imports,
        "exports": exports,
        "functions": functions,
        "custom_sections": custom_sections,
        "judgments": judgments,
        "histogram": histogram,
        "proposals": sorted(proposals),
        "algo_version": ALGO_VERSION,
    }
