"""离线案例包：模块边界庭 —— WebAssembly 段索引、类型栈与提案能力验证。

The package builds real Wasm binaries byte-by-byte, keeps the original byte
ranges / section ids+sizes / LEB128 encodings / index origins / feature
switches / import contracts / custom sections intact, and scripts:

  v1 baseline import -> v2 local source change (one function body) ->
  v3 parameter revision (disable multi-value) -> conflicting human decisions
  -> seven boundary scenario branches.

`load_case(store)` replays the whole narrative into a store.
"""
from __future__ import annotations

import hashlib
import json

VT = {"i32": 0x7F, "i64": 0x7E, "f32": 0x7D, "f64": 0x7C}
HEADER = b"\x00asm\x01\x00\x00\x00"
PROPOSALS = ["multi-value", "bulk-memory", "reference-types"]
HOST = [{"module": "env", "name": "log", "kind": "func",
         "params": ["i32"], "results": []}]


def uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(n):
    out = bytearray()
    more = True
    while more:
        b = n & 0x7F
        n >>= 7
        if (n == 0 and not (b & 0x40)) or (n == -1 and (b & 0x40)):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)


def section(sid, payload, size_bytes=None):
    return bytes([sid]) + (size_bytes if size_bytes is not None else uleb(len(payload))) + payload


def vec(items):
    return uleb(len(items)) + b"".join(items)


def name(s):
    raw = s.encode()
    return uleb(len(raw)) + raw


def functype(params, results):
    return b"\x60" + vec([bytes([VT[p]]) for p in params]) + vec([bytes([VT[r]]) for r in results])


def code_entry(body):
    return uleb(len(body)) + body


# ---------------- baseline module ----------------
# types: 0: ()->(i32,i32)  1: (i32)->()  2: ()->()
TYPES = section(1, vec([functype([], ["i32", "i32"]),
                        functype(["i32"], []),
                        functype([], [])]))
IMPORTS = section(2, vec([name("env") + name("log") + b"\x00" + uleb(1)]))
FUNCS = section(3, vec([uleb(0), uleb(2)]))  # fn1=pair (type0), fn2=helper (type2)
EXPORTS = section(7, vec([name("pair") + b"\x00" + uleb(1),
                        name("helper") + b"\x00" + uleb(2)]))
BODY_PAIR_V1 = vec([]) + b"\x41" + sleb(7) + b"\x41" + sleb(9) + b"\x0b"
BODY_PAIR_V2 = vec([]) + b"\x41" + sleb(8) + b"\x41" + sleb(9) + b"\x0b"
BODY_HELPER = vec([]) + b"\x01\x0b"  # nop; end
CUSTOM = section(0, name("boundaryCourt") + bytes(range(16)))


def baseline_wasm(pair_body=BODY_PAIR_V1):
    code = section(10, vec([code_entry(pair_body), code_entry(BODY_HELPER)]))
    return HEADER + TYPES + IMPORTS + FUNCS + EXPORTS + code + CUSTOM


BASELINE = baseline_wasm()
V2_WASM = baseline_wasm(BODY_PAIR_V2)  # only fn1 body changes: const 7 -> 8

# ---------------- scenario modules ----------------

def _dup_section():
    return HEADER + TYPES + IMPORTS + TYPES + FUNCS + section(10, vec([
        code_entry(BODY_PAIR_V1), code_entry(BODY_HELPER)]))


def _out_of_order():
    code = section(10, vec([code_entry(BODY_PAIR_V1), code_entry(BODY_HELPER)]))
    return HEADER + TYPES + IMPORTS + code + FUNCS


def _noncanonical_leb():
    # type section size (len of TYPES payload) encoded in 6 bytes -> non-canonical
    types_payload = vec([functype([], ["i32", "i32"]),
                         functype(["i32"], []),
                         functype([], [])])
    size6 = bytes([0x80 | len(types_payload)]) + b"\x80\x80\x80\x80\x00"
    bad_types = section(1, types_payload, size_bytes=size6)
    return HEADER + bad_types


def _leb_range():
    # function section declares type index 2**32 -> value_out_of_range (u32)
    big = uleb(2 ** 32)
    funcs = section(3, vec([big]))
    types = section(1, vec([functype([], [])]))
    return HEADER + types + funcs


def _unreachable_stack():
    types = section(1, vec([functype([], [])]))
    funcs = section(3, vec([uleb(0), uleb(0)]))
    # fn0: unreachable; i32.add; drop; end  -> valid polymorphic stack
    body_ok = vec([]) + b"\x00\x6a\x1a\x0b"
    # fn1: i32.add; end -> stack_underflow (no unreachable region)
    body_bad = vec([]) + b"\x6a\x0b"
    code = section(10, vec([code_entry(body_ok), code_entry(body_bad)]))
    return HEADER + types + funcs + code


def _multi_value_block():
    types = section(1, vec([functype([], ["i32", "i32"])]))
    funcs = section(3, vec([uleb(0)]))
    # block (type 0) i32.const 1 i32.const 2 end; end   (fn result = [i32, i32])
    body = vec([]) + b"\x02" + sleb(0) + b"\x41" + sleb(1) + b"\x41" + sleb(2) + b"\x0b\x0b"
    code = section(10, vec([code_entry(body)]))
    return HEADER + types + funcs + code


def _proposal_off():
    types = section(1, vec([functype([], [])]))
    funcs = section(3, vec([uleb(0), uleb(0)]))
    mem = section(5, vec([b"\x00" + uleb(1)]))
    # fn0: memory.copy (0xFC 0x0A 0x00 0x00) -> capability_missing when bulk-memory off
    body_mc = vec([]) + b"\x41\x00\x41\x00\x41\x00" + b"\xfc" + uleb(10) + b"\x00\x00" + b"\x0b"
    # fn1: 0xFF -> unknown_opcode in every proposal set
    body_unk = vec([]) + b"\xff\x0b"
    code = section(10, vec([code_entry(body_mc), code_entry(body_unk)]))
    return HEADER + types + funcs + mem + code


def _import_mismatch():
    types = section(1, vec([functype(["i32"], []), functype([], [])]))
    imports = section(2, vec([
        name("env") + name("log") + b"\x00" + uleb(0),      # host offers (i64)->()
        name("env") + name("ghost") + b"\x00" + uleb(1),    # host does not offer
    ]))
    return HEADER + types + imports


def _custom_fidelity():
    payload = bytes(range(256))
    custom = section(0, name("fidelity") + payload)
    types = section(1, vec([functype([], [])]))
    return HEADER + types + custom


SCENARIOS = [
    {"key": "section-duplicate", "label": "section 重复",
     "wasm": _dup_section(), "proposals": PROPOSALS, "host": HOST,
     "expect": {"errors": ["section_duplicate"]}},
    {"key": "section-out-of-order", "label": "section 乱序",
     "wasm": _out_of_order(), "proposals": PROPOSALS, "host": HOST,
     "expect": {"errors": ["section_out_of_order"]}},
    {"key": "noncanonical-leb128", "label": "非规范 LEB128",
     "wasm": _noncanonical_leb(), "proposals": PROPOSALS, "host": HOST,
     "expect": {"errors": ["noncanonical_leb128"]}},
    {"key": "leb128-range-vs-form", "label": "LEB128 数值越界（与形式分开）",
     "wasm": _leb_range(), "proposals": PROPOSALS, "host": HOST,
     "expect": {"errors": ["value_out_of_range"],
                "absent": ["noncanonical_leb128"]}},
    {"key": "unreachable-stack", "label": "unreachable 多态栈",
     "wasm": _unreachable_stack(), "proposals": PROPOSALS, "host": HOST,
     "expect": {"errors": ["stack_underflow"],
                "judgments": ["polymorphic_stack_scope"],
                "polymorphic_functions": [0]}},
    {"key": "multi-value-off", "label": "多值返回 proposal 关闭",
     "wasm": _multi_value_block(), "proposals": ["bulk-memory"], "host": HOST,
     "expect": {"errors": ["capability_missing"],
                "judgments": ["capability_vs_unknown"]}},
    {"key": "multi-value-on", "label": "多值返回 proposal 开启",
     "wasm": _multi_value_block(), "proposals": PROPOSALS, "host": HOST,
     "expect": {"ok": True}},
    {"key": "proposal-off-opcode", "label": "proposal 关闭的 opcode 报能力缺失",
     "wasm": _proposal_off(), "proposals": ["multi-value"], "host": HOST,
     "expect": {"errors": ["capability_missing", "unknown_opcode"],
                "judgments": ["capability_vs_unknown"]}},
    {"key": "import-mismatch", "label": "import 契约不匹配",
     "wasm": _import_mismatch(), "proposals": PROPOSALS,
     "host": [{"module": "env", "name": "log", "kind": "func",
               "params": ["i64"], "results": []}],
     "expect": {"errors": ["import_signature_mismatch", "import_not_provided"]}},
    {"key": "custom-fidelity", "label": "自定义段保真",
     "wasm": _custom_fidelity(), "proposals": PROPOSALS, "host": HOST,
     "expect": {"ok": True,
                "custom_sha256": hashlib.sha256(bytes(range(256))).hexdigest()}},
]


def build_case():
    return {
        "name": "模块边界庭：WebAssembly 段索引、类型栈与提案能力验证",
        "format": "boundary-court/1",
        "narrative": [
            "v1 导入基线模块：原字节范围、section id/size、LEB128 编码、索引来源、功能开关、import 契约、自定义段均保留",
            "v2 局部源数据改动：仅修改函数 pair 的一个立即数（7→8），只有依赖它的派生结果过期",
            "v3 参数修订：关闭 multi-value proposal，能力缺失判定出现",
            "两位审阅者对同一结果作出互相冲突的裁定，随后其中一人撤销",
            "七个边界场景分支：section 重复与乱序、非规范 LEB128、unreachable 栈、多值返回、proposal 关闭、import 不匹配、自定义段保真",
        ],
        "baseline": {"wasm_hex": BASELINE.hex(), "proposals": PROPOSALS, "host": HOST},
        "v2_wasm_hex": V2_WASM.hex(),
        "scenarios": [{k: (v.hex() if k == "wasm" else v) for k, v in s.items()}
                      for s in SCENARIOS],
    }


def load_case(store):
    """Replay the whole 模块边界庭 narrative into a store. Returns a summary."""
    log = {"versions": [], "scenarios": [], "decisions": []}
    v1 = store.commit_input("baseline-v1", BASELINE, PROPOSALS, HOST)
    log["versions"].append(v1)
    v2 = store.commit_input("fix-pair-const-v2", V2_WASM, PROPOSALS, HOST, parent_id=v1)
    log["versions"].append(v2)
    v3 = store.commit_input("disable-multi-value-v3", V2_WASM,
                            ["bulk-memory", "reference-types"], HOST, parent_id=v2)
    log["versions"].append(v3)

    view = store.input_view(v3)
    fn1 = next(r for r in view["results"] if r["subject"] == "function/1")
    rid = fn1["result"]["id"]
    d1 = store.decide(rid, "reject", "multi-value 已关闭，type0 判定不成立", reviewer="aoi")
    d2 = store.decide(rid, "accept", "已知限制，接受风险", reviewer="ren")
    log["decisions"] += [d1, d2]
    store.undo_decision(d2)  # conflict resolved, but both rulings stay in history

    for sc in SCENARIOS:
        iid = store.commit_input(f"scenario:{sc['key']}", sc["wasm"],
                                 sc["proposals"], sc["host"])
        log["scenarios"].append({"key": sc["key"], "input_id": iid})
    return log


if __name__ == "__main__":
    case = build_case()
    for s in case["scenarios"]:
        s["wasm_hex"] = s.pop("wasm")
    print(json.dumps(case, ensure_ascii=False, indent=2, sort_keys=True))
