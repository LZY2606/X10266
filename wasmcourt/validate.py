"""模块验证：函数类型栈 / 控制栈 / 提案能力 / import 契约。

关键判定原则（验收硬要求）：
* polymorphic（多态）栈只在 unreachable 区域生效：unreachable 弹出整帧后
  该帧变为多态，pop 永远成功但产生的类型记为 unknown；帧结束时多态状态
  随帧丢弃，不会泄漏到外层可达区域。
* 未启用 proposal 的 opcode 报 capability_missing（能力缺失），
  不是 unknown_byte；真正无法识别的字节才是 unknown_opcode。
* 多值块类型（类型索引块类型）/ 多结果 functype 需要 multi_value。
"""
from __future__ import annotations

from .parser import byte_range, _finding
from .units import UNIT_SLOTS, UNIT_FRAMES

# opcode -> (助记, 弹出, 压入, 能力 or None)
OPCODES = {
    0x00: ("unreachable", [], [], None),
    0x01: ("nop", [], [], None),
    0x02: ("block", [], [], "blocktype"),
    0x03: ("loop", [], [], "blocktype"),
    0x04: ("if", ["i32"], [], "blocktype"),
    0x05: ("else", [], [], "control"),
    0x0B: ("end", [], [], "control"),
    0x0C: ("br", [], [], "br"),
    0x0D: ("br_if", ["i32"], ["i32"], "br"),
    0x10: ("call", [], [], "call"),
    0x11: ("call_indirect", ["i32"], [], "call_indirect"),
    0x1A: ("drop", ["any"], [], None),
    0x20: ("local.get", [], ["local"], "local"),
    0x21: ("local.set", ["local"], [], "local"),
    0x22: ("local.tee", ["local"], ["local"], "local"),
    0x41: ("i32.const", [], ["i32"], "i32"),
    0x42: ("i64.const", [], ["i64"], "i64"),
    0x45: ("i32.eqz", ["i32"], ["i32"], None),
    0x46: ("i32.eq", ["i32", "i32"], ["i32"], None),
    0x4A: ("i32.gt_s", ["i32", "i32"], ["i32"], None),
    0x6A: ("i32.add", ["i32", "i32"], ["i32"], None),
    0x6B: ("i32.sub", ["i32", "i32"], ["i32"], None),
    0x7C: ("i64.add", ["i64", "i64"], ["i64"], None),
    0x7D: ("i64.sub", ["i64", "i64"], ["i64"], None),
    0x0F: ("return", [], [], "return"),
    0x12: ("return_call", [], [], "tail_call"),
    0xD0: ("ref.null", [], ["funcref"], "reference_types"),
    0xD2: ("ref.is_null", ["any"], ["i32"], "reference_types"),
    0xFD: ("simd-prefix", [], [], "simd"),
}

# 需要跳过的立即数字节（LEB/固定），用于能力缺失时仍能继续流扫描
OPERANDS = {
    0x02: [("leb", "blocktype")], 0x03: [("leb", "blocktype")],
    0x04: [("leb", "blocktype")],
    0x0C: [("leb", "label")], 0x0D: [("leb", "label")],
    0x10: [("leb", "funcidx")],
    0x11: [("leb", "typeidx"), ("leb", "tableidx")],
    0x20: [("leb", "localidx")], 0x21: [("leb", "localidx")],
    0x22: [("leb", "localidx")],
    0x41: [("leb32", "i32")], 0x42: [("leb64", "i64")],
    0x12: [("leb", "funcidx")],
    0xD0: [("u8", "heaptype")],
    0xFD: [("leb", "simd_op")],
}

KNOWN_PREFIXES = {0xFD: "simd"}


class VFrame:
    def __init__(self, kind, start, params=None, results=None,
                 unreachable=False, base_height=0, else_at=None):
        self.kind = kind              # block / loop / if / if-else / func
        self.start = start            # opcode 字节坐标
        self.params = params or []
        self.results = results or []
        self.unreachable = unreachable
        self.base_height = base_height
        self.else_at = else_at        # if 帧记录 else/end 位置

    def state(self):
        return {"kind": self.kind,
                "polymorphic": self.unreachable,
                "params": list(self.params), "results": list(self.results),
                "start": self.start, "base_height": self.base_height}


def validate_module(parsed: dict, features: dict,
                    host_contract: dict | None = None) -> dict:
    findings = [dict(f) for f in parsed.get("findings", [])]
    transitions = []
    controls = []
    types = _types(parsed)
    func_rows = parsed.get("index_summary", {}).get("func_rows", [])

    _check_multi_value_types(types, findings, features)
    _check_index_spaces(parsed, types, func_rows, findings)
    contract_findings = check_import_contract(parsed, host_contract or {})
    findings.extend(contract_findings)

    body_frames = []
    for section in parsed["sections"]:
        if section.get("id") != 10:
            continue
        bodies = section.get("bodies", [])
        for body in bodies:
            decl_index = body["body_index"]
            funcidx = _funcidx_for_body(parsed, decl_index)
            ftype = _func_type(funcidx, func_rows, types)
            report = _validate_body(parsed["sections"], parsed.get("_raw", b""),
                                    body, ftype, features, types, funcidx)
            findings.extend(report["findings"])
            transitions.extend(report["transitions"])
            for frame in report["frames"]:
                frame["funcidx"] = funcidx
                body_frames.append(frame)

    status = "reject" if any(f.get("severity") == "error" for f in findings) \
        else "accept"
    return {"status": status, "findings": findings,
            "type_transitions": transitions, "control_stack_log": body_frames,
            "capabilities": {"enabled": sorted(k for k, v in features.items()
                                               if v),
                             "mvp": True}}


def _types(parsed):
    for section in parsed["sections"]:
        if section.get("id") == 1:
            return section.get("types", [])
    return []


def _check_multi_value_types(types, findings, features):
    for t in types:
        if len(t["results"]) > 1 and not features.get("multi_value"):
            r = t["range"]
            findings.append(_finding(
                "capability_missing_type",
                f"type {t['index']} returns {len(t['results'])} values but "
                "proposal multi_value is disabled",
                r["start"], r["end"], category="capability",
                candidates=[
                    {"resolution": "enable multi_value", "valid_if": True},
                    {"resolution": "treat-as-unknown", "valid_if": False,
                     "rejected": "known opcode/type, not unknown"},
                ]).as_dict())


def _check_index_spaces(parsed, types, func_rows, findings):
    summary = parsed.get("index_summary", {})
    if not summary.get("decl_code_match", True):
        decl = summary.get("defined_func_count", 0)
        code = summary.get("code_body_count", 0)
        findings.append(_finding(
            "index_space_mismatch",
            f"function section declares {decl} defined functions but code "
            f"section has {code} bodies", 0, 0, category="index").as_dict())
    for row in func_rows:
        ti = row.get("typeidx")
        if ti is not None and ti >= len(types):
            rng = row.get("desc_range") or row.get("range") or byte_range(0, 0)
            findings.append(_finding(
                "unknown_typeidx",
                f"funcidx {} typeidx {ti} is out of type index space "
                "(size {})".format(row["funcidx"], len(types)),
                rng["start"], rng["end"], category="index").as_dict())


def _funcidx_for_body(parsed, decl_index):
    return parsed.get("index_summary", {}).get("imported_func_count", 0) + decl_index


def _func_type(funcidx, func_rows, types):
    for row in func_rows:
        if row["funcidx"] == funcidx and row.get("typeidx") is not None \
                and row["typeidx"] < len(types):
            return types[row["typeidx"]]
    return {"params": [], "results": []}


def check_import_contract(parsed, contract) -> list[dict]:
    """host import 签名契约核对。

    contract: {"module.field": {"kind":"func","params":[...],"results":[...]}}
    模块需要但契约未提供 -> import_unresolved；
    提供但签名不一致 -> import_mismatch（精确指向 import 条目字节）。
    """
    out = []
    if not contract:
        return out
    for section in parsed["sections"]:
        if section.get("id") != 2:
            continue
        for imp in section.get("imports", []):
            if imp["kind"] != "func":
                continue
            key = f"{imp['module']}.{imp['field']}"
            rng = imp["range"]
            if key not in contract:
                out.append(_finding(
                    "import_unresolved",
                    f"host does not provide import {key}",
                    rng["start"], rng["end"], category="import",
                    provenance={"contract_source": contract.get("_source",
                                                                "host-v1")},
                    candidates=[{"resolution": "add host function",
                                 "valid_if": True},
                                {"resolution": "drop import",
                                 "valid_if": False}]).as_dict())
                continue
            expected = contract[key]
            actual_sig = _import_signature(imp, parsed)
            if expected.get("params") != actual_sig.get("params") or \
                    expected.get("results") != actual_sig.get("results"):
                out.append(_finding(
                    "import_mismatch",
                    f"import {key} signature {_sig(actual_sig)} does not match "
                    f"host contract {_sig(expected)}",
                    rng["start"], rng["end"], category="import",
                    provenance={"contract_source": contract.get("_source",
                                                                "host-v1")},
                    candidates=[
                        {"resolution": "update host contract",
                         "expected": expected, "actual": actual_sig},
                        {"resolution": "change module import type",
                         "valid_if": True}]).as_dict())
    return out


def _import_signature(imp, parsed):
    types = _types(parsed)
    ti = imp.get("typeidx")
    if ti is None or ti >= len(types):
        return {"params": None, "results": None}
    t = types[ti]
    return {"params": [p["name"] for p in t["params"]],
            "results": [r["name"] for r in t["results"]]}


def _sig(sig):
    return f"({','.join(sig.get('params') or [])})->" \
           f"({','.join(sig.get('results') or [])})"


def _validate_body(sections, raw, body, ftype, features, types, funcidx):
    findings = []
    transitions = []
    frames_log = []
    # body range 起点是 locals 向量
    body_start = body["range"]["start"]
    body_end = body["range"]["end"]

    # raw 由 parse_module 附带（_raw）。若无则不能做指令验证。
    if not raw:
        return {"findings": findings, "transitions": transitions,
                "frames": frames_log}

    pos = body_start
    # --- locals ---
    from .leb128 import decode_u32
    local_groups_n = decode_u32(raw, pos)
    pos += local_groups_n.width
    locals_ = list(ftype.get("params", []))
    for _g in range(local_groups_n.value or 0):
        cnt = decode_u32(raw, pos)
        pos += cnt.width
        t_byte = raw[pos]
        pos += 1
        from .parser import VALTYPE_NAMES
        tname = VALTYPE_NAMES.get(t_byte, f"0x{t_byte:02x}")
        locals_.extend([tname] * (cnt.value or 0))
    locals_ = [l["name"] if isinstance(l, dict) else l for l in locals_]

    stack: list[str] = []
    frames: list[VFrame] = [VFrame("func", body_start,
                                   [p["name"] for p in ftype.get("params", [])],
                                   [r["name"] for r in ftype.get("results", [])])]

    def add(code, message, start, end, category="stack", candidates=None,
            severity="error"):
        findings.append(_finding(code, message, start, end, severity=severity,
                                 category=category,
                                 candidates=candidates or []).as_dict())

    def snap(op, op_start, op_end, note="", popped=None, pushed=None):
        transitions.append({
            "funcidx": funcidx, "op": op,
            "range": byte_range(op_start, op_end),
            "stack_before": list(stack),
            "stack_after": list(stack),
            "cstack_depth": len(frames),
            "polymorphic_region": any(f.unreachable for f in frames),
            "unit_stack_depth": UNIT_SLOTS,
            "note": note,
        })

    def pop_expect(expected, op_start, op_end, mnemonic):
        """从当前帧栈顶弹出一个值；polymorphic 帧内允许 unknown。"""
        frame = frames[-1]
        frame_base = frame.base_height
        frame_stack = stack[frame_base:]
        if frame.unreachable and not frame_stack:
            return "unknown"
        if not frame_stack:
            add("type_stack_underflow",
                f"{mnemonic}: operand stack empty (need {expected})"
                + (" in unreachable polymorphic region"
                   if frame.unreachable else ""),
                op_start, op_end,
                candidates=([{"resolution": "polymorphic-unknown",
                              "accepted": frame.unreachable}]
                            if frame.unreachable else []))
            return "unknown"
        actual = stack.pop()
        if expected != "any" and actual != "unknown" and actual != expected:
            add("type_stack_mismatch",
                f"{mnemonic}: expected {expected} on stack top, found "
                f"{actual}", op_start, op_end,
                candidates=[
                    {"actual": actual, "expected": expected,
                     "in_polymorphic_region": frame.unreachable,
                     "resolution": "matching producer needed"},
                ])
        return actual

    pos = _instr_loop(raw, pos, body_end, frames, stack, locals_, features,
                      types, ftype, add, snap, pop_expect, frames_log, funcidx,
                      findings)
    for t in transitions:
        t["stack_after"] = list(t.get("stack_after", []))
    return {"findings": findings, "transitions": transitions,
            "frames": frames_log}
