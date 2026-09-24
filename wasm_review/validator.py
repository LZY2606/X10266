"""Validation state machine.

Emits structured findings (never just a verdict string). Each finding is a
first-class datum with:
  * stable ``uid`` (deterministic over code, range and message key)
  * precise minimal failing byte range
  * ``direct_sources``  which inputs it depends on
  * ``candidates``      every still-legal alternative when ambiguous
  * ``severity``        error | note

Severity/error distinctions required by the domain:
  * noncanonical LEB128  -> encoding error, *not* numeric overflow
  * polymorphic stack pops are legal only inside an unreachable region
  * a gated opcode with its switch off -> ``capability_missing``
    (never ``unknown_byte``); a byte with no known opcode at all ->
    ``unknown_byte`` with the capability switches explicitly considered.
"""

import hashlib

from . import ALGORITHM_VERSION_VALIDATE
from .leb128 import read_leb
from .opcodes import (MVP_OPCODES, GATED_OPCODES, FC_SUB, VALTYPES,
                      REFTYPES, KNOWN_PROPOSALS,
                      UNASSIGNED_PROOF_BYTE)

SRC_MODULE = "module"
SRC_PROPOSALS = "proposals"
SRC_HOST = "host_imports"


def _fid(code: str, start: int, end: int, key: str = "") -> str:
    h = hashlib.sha256(f"{code}|{start}|{end}|{key}".encode()).hexdigest()
    return f"fnd_{h[:16]}"


def finding(code, message, start, end, category, sources, *,
            severity="error", candidates=None, details=None):
    return {
        "uid": _fid(code, start, end, message + str(details or "")),
        "code": code,
        "category": category,
        "message": message,
        "severity": severity,
        "byte_start": start,
        "byte_end": end,
        "direct_sources": sources,
        "candidates": candidates or [],
        "details": details or {},
    }


def decode_instructions(data: bytes, start: int, end: int,
                        lebs_out: list, base_uid: str):
    """Decode raw instruction bytes for one function expression.

    Returns (instructions, decode_error|None). Decoding stops at the first
    opcode that cannot be structurally decoded (unknown/gated prefix); the
    caller decides capability status. All LEB immediates keep representations.
    """
    pos = start
    ins = []
    seq = 0

    def rec(op, mnemonic, imm, s, e, gate, mvp, prefix=None):
        nonlocal seq
        uid = f"{base_uid}/in{seq:04x}@{s}"
        ins.append({"uid": uid, "seq": seq, "op": op,
                    "mnemonic": mnemonic, "imm": imm, "gate": gate,
                    "is_mvp": mvp, "prefix": prefix,
                    "byte_start": s, "byte_end": e})
        seq += 1

    def u32imm():
        lv = read_leb(data, pos, "u32")
        lebs_out.append((lv.start, lv.end, lv.to_diag()))
        return lv

    def memarg():
        align = u32imm()
        offset = u32imm()
        return {"align": align.value, "offset": offset.value,
                "align_leb": align.to_diag(), "offset_leb": offset.to_diag()}

    while pos < end:
        s = pos
        op = data[pos]
        pos += 1
        if op == 0x0B and pos == end:
            # the function-level terminating end is implicit frame close
            break
        if op in MVP_OPCODES:
            mnemonic, kind = MVP_OPCODES[op]
            imm: dict = {}
            gate = frozenset()
            if kind == "none":
                pass
            elif kind in ("u32imm", "localidx", "globalidx", "funcidx"):
                lv = u32imm()
                imm = {"index": lv.value, "leb": lv.to_diag()}
            elif kind == "s32imm":
                lv = read_leb(data, pos, "s32"); pos = lv.end
                lebs_out.append((lv.start, lv.end, lv.to_diag()))
                imm = {"value": lv.value, "leb": lv.to_diag()}
            elif kind == "s64imm":
                lv = read_leb(data, pos, "s64"); pos = lv.end
                lebs_out.append((lv.start, lv.end, lv.to_diag()))
                imm = {"value": lv.value, "leb": lv.to_diag()}
            elif kind == "memarg":
                imm = memarg()
            elif kind == "blocktype":
                bt = data[pos]; pos += 1
                imm = {"raw_byte": bt}
                if bt in VALTYPES:
                    imm["blocktype"] = VALTYPES[bt]
                elif bt == 0x40:
                    imm["blocktype"] = "void"
                else:
                    # Positive signed-LEB block type = function type index
                    lv = read_leb(data, pos - 1, "s32")
                    pos = lv.end
                    lebs_out.append((lv.start, lv.end, lv.to_diag()))
                    imm["type_index"] = lv.value
                    imm["leb"] = lv.to_diag()
                    imm["blocktype"] = f"typeidx:{lv.value}"
            elif kind == "call_indirect":
                ti = u32imm()
                table = u32imm()
                imm = {"type_index": ti.value, "leb": ti.to_diag(),
                       "table_index": table.value,
                       "table_leb": table.to_diag()}
            rec(op, mnemonic, imm, s, pos, gate, True)
            if op == 0x0B:
                # inner end; continue (blocks validated by validator)
                continue
            continue

        if op in GATED_OPCODES:
            mnemonic, kind, gate = GATED_OPCODES[op]
            if op == 0xFC:
                sub_lv = u32imm()
                sub = sub_lv.value
                info = FC_SUB.get(sub)
                imm = {"sub_opcode": sub, "leb": sub_lv.to_diag()}
                if info is None:
                    return ins, {"op": op, "sub": sub, "start": s,
                                 "end": pos, "gate": gate, "kind": "fc_unknown"}
                name, _, sub_gate = info
                rec((0xFC << 32) | sub, name, imm, s, pos,
                    sub_gate, False, prefix=0xFC)
                continue
            if op == 0xFD:
                return ins, {"op": op, "start": s, "end": pos,
                             "gate": frozenset({"simd"}), "kind": "simd"}
            imm = {}
            if kind == "funcidx" or kind == "u32imm":
                lv = u32imm()
                imm = {"index": lv.value, "leb": lv.to_diag()}
            rec(op, mnemonic, imm, s, pos, gate, False)
            continue

        return ins, {"op": op, "start": s, "end": pos,
                     "gate": None, "kind": "unknown"}
    return ins, None


def validate(parsed, data: bytes, capabilities: dict, host_imports: dict):
    """Run all validation stages. Returns a structured run result."""
    findings = []
    p = parsed
    sections = p.get("sections")

    # Stage 1: section order / duplicates / header
    if not p.get("magic_ok") or not p.get("version_ok"):
        findings.append(finding(
            "module_header_invalid",
            "magic/version header invalid; structural validation aborted",
            0, min(8, p.get("byte_len", 0)), "section",
            [SRC_MODULE]))
        return _run_result(findings, [], [], capabilities)

    seen_known = {}
    last_order = 0
    for sec in sections:
        sid = sec["sec_id"]
        if sid == 0:
            continue
        if sid not in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]:
            findings.append(finding(
                "unknown_section_id",
                f"section id {sid} is not a known wasm section",
                sec["byte_start"], sec["byte_start"] + 1, "section",
                [SRC_MODULE]))
            continue
        if sid in seen_known:
            findings.append(finding(
                "duplicate_section",
                f"{sec['name']} section (id {sid}) appears more than once",
                sec["byte_start"], sec["size_leb"]["byte_end"], "section",
                [SRC_MODULE], severity="error",
                details={"first_section_uid": seen_known[sid]["uid"],
                         "first_index": seen_known[sid]["index_in_file"]}))
        order = sid  # ids 1..12 are already canonical
        if sid in seen_known or order < last_order:
            first = seen_known.get(sid)
            findings.append(finding(
                "section_out_of_order",
                f"{sec['name']} section at file index {sec['index_in_file']} "
                f"violates canonical section order",
                sec["byte_start"], sec["size_leb"]["byte_end"], "section",
                [SRC_MODULE], severity="error",
                details={"canonical_predecessor_id":
                         max(s for s in CANONICAL if s < sid)
                         if sid > 1 else None,
                         "prior_section_uid": first["uid"] if first else None}))
        seen_known[sid] = sec
        last_order = max(last_order, order)

    # Stage 2: parser-level structural / LEB findings (codes preserved)
    for issue in p.get("issues", []):
        findings.append(finding(
            issue["code"], issue["message"], issue["byte_start"],
            issue["byte_end"], "encoding", [SRC_MODULE],
            severity="error", details={"parse_issue_uid": issue["uid"]}))

    types = p.get("types", [])
    # Stage 3: capability-gated declarations (multi-value type arity)
    for t in types:
        arity = len(t["functype"]["results"])
        if arity > 1 and not capabilities.get("multi_value"):
            findings.append(finding(
                "capability_missing",
                f"function type {t['index']} returns {arity} values; the "
                "multi_value proposal switch is off",
                t["byte_start"], t["byte_end"], "capability",
                [SRC_MODULE, SRC_PROPOSALS],
                candidates=[{
                    "switch": "multi_value", "switch_value": True,
                    "would_resolve": True}],
                details={"proposal": "multi_value", "result_arity": arity,
                         "kind": "type_arity"}))

    _check_limits(findings, p)
    _check_imports(findings, p, host_imports)
    _check_index_spaces(findings, p)
    body_results = _validate_bodies(findings, p, data, capabilities)
    _check_custom_preserved(findings, p, data)
    return _run_result(findings, body_results, types, capabilities)


CANONICAL = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]


def _run_result(findings, body_results, types, capabilities):
    accepted_codes = [f["uid"] for f in findings]
    return {
        "algorithm_version": ALGORITHM_VERSION_VALIDATE,
        "findings": findings,
        "body_results": body_results,
        "type_count": len(types),
        "capabilities_used": dict(capabilities),
        "finding_index": {f["uid"]: f for f in findings},
    }


MEMORY_LIMIT_MAX = 65536
TABLE_LIMIT_MAX = 10_000_000


def _check_limits(findings, p):
    for sec, items, cap in (
            ("memory", p.get("memories", []), MEMORY_LIMIT_MAX),
            ("table", p.get("tables", []), TABLE_LIMIT_MAX)):
        for item in items:
            lim = item["limits"]
            mn = lim.get("min")
            mx = lim.get("max")
            start = lim["byte_start"]
            end = lim["byte_end"]
            if isinstance(mn, int) and mn > cap:
                findings.append(finding(
                    "limit_exceeded",
                    f"{sec} minimum {mn} exceeds implementation limit {cap}",
                    start, end, "limits", [SRC_MODULE],
                    details={"minimum": mn, "limit": cap, "unit": "pages"
                             if sec == "memory" else "elements"}))
            if mx is not None and (mx > cap or (mn is not None and mx < mn)):
                findings.append(finding(
                    "limit_exceeded",
                    f"{sec} maximum {mx} invalid (limit {cap}, min {mn})",
                    start, end, "limits", [SRC_MODULE],
                    details={"maximum": mx, "minimum": mn, "limit": cap}))
    # imported memories/tables share the same limits
    for imp in p.get("imports", []):
        if imp["kind"] == "memory":
            lim = imp["desc"]["limits"]
            _limit_one(findings, lim, MEMORY_LIMIT_MAX, "memory", imp)
        if imp["kind"] == "table":
            lim = imp["desc"]["limits"]
            _limit_one(findings, lim, TABLE_LIMIT_MAX, "table", imp)


def _limit_one(findings, lim, cap, sec, imp):
    mn = lim.get("min")
    mx = lim.get("max")
    if isinstance(mn, int) and mn > cap:
        findings.append(finding(
            "limit_exceeded",
            f"imported {sec} minimum {mn} exceeds limit {cap}",
            lim["byte_start"], lim["byte_end"], "limits",
            [SRC_MODULE, SRC_HOST],
            details={"minimum": mn, "limit": cap, "import_uid": imp["uid"]}))
    if mx is not None and (mx > cap or (mn is not None and mx < mn)):
        findings.append(finding(
            "limit_exceeded",
            f"imported {sec} maximum {mx} invalid",
            lim["byte_start"], lim["byte_end"], "limits",
            [SRC_MODULE, SRC_HOST],
            details={"maximum": mx, "minimum": mn, "limit": cap,
                     "import_uid": imp["uid"]}))


def _signature_of_type(p, type_index):
    for t in p.get("types", []):
        if t["index"] == type_index:
            return t["functype"]
    return None


def _check_imports(findings, p, host_imports):
    for imp in p.get("imports", []):
        if imp["kind"] != "function":
            continue
        module = imp["module"]
        field = imp["field"]
        contracts = host_imports.get(module)
        if contracts is None or field not in contracts:
            findings.append(finding(
                "host_import_absent",
                f"host provides no import {module}.{field}",
                imp["byte_start"], imp["byte_end"], "import",
                [SRC_MODULE, SRC_HOST],
                details={"module": module, "field": field,
                         "import_uid": imp["uid"]}))
            continue
        contract = contracts[field]
        type_index = imp["desc"]["type_index"]
        ft = _signature_of_type(p, type_index)
        if ft is None:
            findings.append(finding(
                "import_type_index_oob",
                f"import {module}.{field} uses missing type {type_index}",
                imp["byte_start"], imp["byte_end"], "index",
                [SRC_MODULE, SRC_HOST],
                details={"type_index": type_index}))
            continue
        want_params = contract.get("params", [])
        want_results = contract.get("results", [])
        got_params = [x if isinstance(x, str) else x.get("type")
                      for x in ft["params"]]
        got_results = [x if isinstance(x, str) else x.get("type")
                       for x in ft["results"]]
        mismatch = None
        if got_params != want_params:
            mismatch = ("params", got_params, want_params)
        elif got_results != want_results:
            mismatch = ("results", got_results, want_results)
        if mismatch:
            slot, got, want = mismatch
            findings.append(finding(
                "import_signature_mismatch",
                f"import {module}.{field} {slot} {got} do not match host "
                f"contract {want}",
                imp["byte_start"], imp["byte_end"], "import",
                [SRC_MODULE, SRC_HOST],
                candidates=[
                    {"adjust": "module_type", slot: want},
                    {"adjust": "host_contract", slot: got}],
                details={"module_name": module, "field": field,
                         "slot": slot, "module_side": got,
                         "host_side": want, "import_uid": imp["uid"]}))


def _check_index_spaces(findings, p):
    types = p.get("types", [])
    ntypes = len(types)
    func_type_index = p.get("func_type_index", [])
    n_func_decls = len(func_type_index)
    n_bodies = len(p.get("func_bodies", []))
    imported_funcs = [i for i in p.get("imports", [])
                      if i["kind"] == "function"]

    if n_func_decls != n_bodies and (n_func_decls or n_bodies):
        # only fire if parser did not already record it
        codes = {f["code"] for f in findings}
        if "function_code_count_mismatch" not in codes:
            findings.append(finding(
                "function_code_count_mismatch",
                f"function section declares {n_func_decls}, code section has "
                f"{n_bodies}", 0, 0, "index", [SRC_MODULE],
                details={"declared": n_func_decls, "bodies": n_bodies}))

    for imp in imported_funcs:
        ti = imp["desc"]["type_index"]
        if ti >= ntypes:
            leb = imp["desc"]["type_index_leb"]
            findings.append(finding(
                "type_index_oob",
                f"import {imp['module']}.{imp['field']} references type "
                f"{ti} but only {ntypes} types exist",
                leb["byte_start"], leb["byte_end"], "index",
                [SRC_MODULE], details={"index": ti, "space_size": ntypes,
                                       "index_space": "type",
                                       "origin": "import"}))
    for k, ti in enumerate(func_type_index):
        if ti >= ntypes:
            leb = p["func_type_index_lebs"][k]
            findings.append(finding(
                "type_index_oob",
                f"defined function {k} references type {ti} but only "
                f"{ntypes} types exist",
                leb["byte_start"], leb["byte_end"], "index",
                [SRC_MODULE], details={"index": ti, "space_size": ntypes,
                                       "index_space": "type",
                                       "origin": "function_section"}))

    n_globals = len(p.get("globals", []))
    n_funcs = len(imported_funcs) + n_func_decls
    for exp in p.get("exports", []):
        kind_name = exp["kind_name"]
        idx = exp["target_index"]
        space = {"function": n_funcs, "global": n_globals,
                 "table": len(p.get("tables", [])) +
                 sum(1 for i in p.get("imports", []) if i["kind"] == "table"),
                 "memory": len(p.get("memories", [])) +
                 sum(1 for i in p.get("imports", []) if i["kind"] == "memory")
                 }.get(kind_name, 0)
        if kind_name != "unknown" and idx >= space:
            leb = exp["target_index_leb"]
            findings.append(finding(
                "export_index_oob",
                f"export {exp['name']} targets {kind_name} {idx} but space "
                f"size is {space}",
                leb["byte_start"], leb["byte_end"], "index",
                [SRC_MODULE],
                details={"index": idx, "space_size": space,
                         "index_space": kind_name}))


def _check_custom_preserved(findings, p, data):
    """Custom sections must survive byte-for-byte. The derived map keeps both
    the name bytes and the payload bytes; we add a note proving fidelity."""
    for sec in p.get("sections", []):
        if sec["sec_id"] != 0:
            continue
        # recompute from original blob coordinates
        recomputed = data[sec["payload_start"]:sec["payload_end"]]
        name_part = data[sec["custom_name_leb"]["byte_start"]:
                         sec["custom_name_leb"]["byte_end"]]
        if recomputed[len(name_part):].hex() != sec["custom_hex"]:
            findings.append(finding(
                "custom_section_corrupted",
                f"custom section {sec['name']} payload was not preserved",
                sec["payload_start"], sec["payload_end"], "custom",
                [SRC_MODULE],
                details={"section_uid": sec["uid"]}))
