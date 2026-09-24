"""WebAssembly 提案能力、值类型与 opcode 元数据。

能力模型:
- 每个非 MVP 指令都挂在一个 proposal 上。
- 未启用 proposal 的 opcode -> CAPABILITY_MISSING (而不是 UNKNOWN_OPCODE)。
- 已知 proposal 集合之外、且不在任何已知表里的字节 -> UNKNOWN_OPCODE。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

ALL_PROPOSALS = (
    "multi_value",
    "reference_types",
    "bulk_memory",
    "simd",
    "sign_extension",
    "saturating_float_to_int",
)
DEFAULT_CAPABILITIES = {
    "multi_value": True,
    "reference_types": True,
    "bulk_memory": True,
    "simd": False,
    "sign_extension": False,
    "saturating_float_to_int": False,
}

VALTYPE = {
    0x7F: ("i32", None),
    0x7E: ("i64", None),
    0x7D: ("f32", None),
    0x7C: ("f64", None),
    0x7B: ("v128", "simd"),
    0x70: ("funcref", "reference_types"),
    0x6F: ("externref", "reference_types"),
}

CUSTOM = 0
SEC_TYPE, SEC_IMPORT, SEC_FUNCTION, SEC_TABLE, SEC_MEMORY = 1, 2, 3, 4, 5
SEC_GLOBAL, SEC_EXPORT, SEC_START, SEC_ELEMENT = 6, 7, 8, 9
SEC_CODE, SEC_DATA, SEC_DATACOUNT = 10, 11, 12

SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "datacount",
}
CANON_ORDER = [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 10, 11]

DEFAULT_LIMITS = {
    "max_types": 1_000_000,
    "max_functions": 1_000_000,
    "max_imports": 100_000,
    "max_exports": 100_000,
    "max_locals": 50_000,
    "max_memory_pages": 65536,
    "max_table_elements": 10_000_000,
    "max_code_bytes": 30_000_000,
}

# 导入 kind
IMPORT_FUNC, IMPORT_TABLE, IMPORT_MEM, IMPORT_GLOBAL = 0, 1, 2, 3
EXPORT_KIND = {0: "func", 1: "table", 2: "mem", 3: "global"}


@dataclass
class OpInfo:
    mnemonic: str
    pops: List[str]
    pushes: List[str]
    proposal: Optional[str]
    family: str  # const|numeric|memory|ref|control|parametric|bulk|simd|var


_OPS: Dict[int, OpInfo] = {}


def _reg(op, mn, pops, pushes, prop, family):
    _OPS[op] = OpInfo(mn, list(pops) if pops is not None else None,
                      list(pushes) if pushes is not None else None,
                      prop, family)


def _range(lo, hi, prefix, pops, pushes, family="numeric", prop=None):
    for op in range(lo, hi + 1):
        _reg(op, f"{prefix}.{op:02x}", pops, pushes, prop, family)


# 常量
_reg(0x41, "i32.const", [], ["i32"], None, "const")
_reg(0x42, "i64.const", [], ["i64"], None, "const")
_reg(0x43, "f32.const", [], ["f32"], None, "const")
_reg(0x44, "f64.const", [], ["f64"], None, "const")

# 参数化
_reg(0x1A, "drop", ["t"], [], None, "parametric")
_reg(0x1B, "select", ["t", "t", "i32"], ["t"], None, "parametric")
_reg(0x1C, "select_typed", None, None, "reference_types", "parametric")

# 数值
_reg(0x45, "i32.eqz", ["i32"], ["i32"], None, "numeric")
_range(0x46, 0x4F, "i32", ["i32", "i32"], ["i32"])
_reg(0x50, "i64.eqz", ["i64"], ["i32"], None, "numeric")
_range(0x51, 0x5A, "i64", ["i64", "i64"], ["i32"])
_range(0x5B, 0x60, "f32rel", ["f32", "f32"], ["i32"])
_range(0x61, 0x66, "f64rel", ["f64", "f64"], ["i32"])
_range(0x67, 0x79, "iari", ["i32", "i32"], ["i32"])
_range(0x80, 0x89, "iari64", ["i64", "i64"], ["i64"])
_range(0x8B, 0x98, "fari32", ["f32", "f32"], ["f32"])
_range(0x9A, 0xA5, "fari64", ["f64", "f64"], ["f64"])
_range(0xA7, 0xBF, "conv", [], [], "numeric")
# 修正具体转换签名
for _op, _pops, _pushes in [
    (0xA7, ["i64"], ["i32"]),
    (0xA8, ["f32"], ["i32"]), (0xA9, ["f32"], ["i32"]),
    (0xAA, ["f64"], ["i32"]), (0xAB, ["f64"], ["i32"]),
    (0xAC, ["i32"], ["i64"]), (0xAD, ["i32"], ["i64"]),
    (0xAE, ["f32"], ["i64"]), (0xAF, ["f32"], ["i64"]),
    (0xB0, ["f64"], ["i64"]), (0xB1, ["f64"], ["i64"]),
    (0xB2, ["i32"], ["f32"]), (0xB3, ["i32"], ["f32"]),
    (0xB4, ["i64"], ["f32"]), (0xB5, ["i64"], ["f32"]),
    (0xB6, ["f64"], ["f32"]),
    (0xB7, ["i32"], ["f64"]), (0xB8, ["i32"], ["f64"]),
    (0xB9, ["i64"], ["f64"]), (0xBA, ["i64"], ["f64"]),
    (0xBB, ["f32"], ["f64"]),
    (0xBC, ["f32"], ["i32"]), (0xBD, ["f64"], ["i64"]),
    (0xBE, ["i32"], ["f32"]), (0xBF, ["i64"], ["f64"]),
]:
    _OPS[_op].pops = list(_pops)
    _OPS[_op].pushes = list(_pushes)
_range(0xC0, 0xC1, "i32ext", ["i32"], ["i32"], prop="sign_extension")
_range(0xC2, 0xC3, "i64ext", ["i64"], ["i64"], prop="sign_extension")
_reg(0xC4, "i64.extend32_s", ["i64"], ["i64"], "sign_extension", "numeric")

# 内存 load/store
def _mem_range(lo, hi, val):
    for op in range(lo, hi + 1):
        _reg(op, f"mem.{op:02x}", ["i32"], [val], None, "memory")
_mem_range(0x28, 0x2E, "i32")
_mem_range(0x2F, 0x35, "i64")
_mem_range(0x36, 0x38, "f32")
_mem_range(0x3B, 0x3D, "f64")
_reg(0x39, "f32.store", ["i32", "f32"], [], None, "memory")
_reg(0x3A, "f64.load", ["i32"], ["f64"], None, "memory")
_reg(0x3E, "f64.store", ["i32", "f64"], [], None, "memory")
_reg(0x3F, "memory.size", [], ["i32"], None, "memory")
_reg(0x40, "memory.grow", ["i32"], ["i32"], None, "memory")

# 变量
_reg(0x20, "local.get", [], None, None, "var")
_reg(0x21, "local.set", None, [], None, "var")
_reg(0x22, "local.tee", None, None, None, "var")
_reg(0x23, "global.get", [], None, None, "var")
_reg(0x24, "global.set", None, [], None, "var")

# 引用 / bulk / simd 前缀
_reg(0xD0, "ref.null", [], ["ref"], "reference_types", "ref")
_reg(0xD2, "ref.is_null", ["ref"], ["i32"], "reference_types", "ref")
_reg(0xD3, "ref.func", [], ["funcref"], "reference_types", "ref")
_reg(0xFC, "fc.prefix", None, None, None, "bulk_prefix")
_reg(0xFD, "simd.prefix", None, None, "simd", "simd_prefix")

# 0xFC 子操作 (bulk memory / reference-types table ops)
FC_SUB = {
    0: ("memory.copy", ["i32", "i32", "i32"], [], "bulk_memory"),
    1: ("memory.fill", ["i32", "i32", "i32"], [], "bulk_memory"),
    8: ("memory.init", ["i32", "i32", "i32"], [], "bulk_memory"),
    9: ("data.drop", [], [], "bulk_memory"),
    10: ("memory.copy.0", ["i32", "i32", "i32"], [], "bulk_memory"),
    12: ("table.copy", None, None, "reference_types"),
    13: ("table.grow", None, None, "reference_types"),
}

CONTROL_NAMES = {
    0x00: "unreachable", 0x01: "nop", 0x02: "block", 0x03: "loop",
    0x04: "if", 0x05: "else", 0x0B: "end", 0x0C: "br",
    0x0D: "br_if", 0x0E: "br_table", 0x0F: "return",
    0x10: "call", 0x11: "call_indirect",
}


def lookup(op: int) -> Optional[OpInfo]:
    return _OPS.get(op)
