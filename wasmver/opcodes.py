"""Opcode catalogue: encoding shape, type effect and originating proposal.

The validator never guesses whether an unknown byte belongs to a gated
proposal: the catalogue distinguishes three cases explicitly:

* known core opcode                       -> normal typing
* known opcode whose proposal is disabled -> ``capability-missing``
* byte used by no known proposal at all   -> ``unknown-opcode``
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OpInfo:
    name: str
    proposal: str | None
    operand: str
    effect: tuple


def _family(prefix: str, first: int, names: list[str]) -> dict[int, OpInfo]:
    return {first + i: OpInfo(f"{prefix}.{n}", None, "none",
                              ("binary", prefix)) for i, n in enumerate(names)}


def _comp(prefix: str, first: int, names: list[str]) -> dict[int, OpInfo]:
    out = {}
    for i, n in enumerate(names):
        if n == "eqz":
            out[first + i] = OpInfo(f"{prefix}.eqz", None, "none", ("test", prefix))
        else:
            out[first + i] = OpInfo(f"{prefix}.{n}", None, "none",
                                    ("compare", prefix))
    return out


TABLE: dict[int, OpInfo] = {}

# --- control (structure operands are parsed by the validator) ---------------
for _b, _n in [(0x00, "unreachable"), (0x01, "nop"), (0x0B, "end"),
               (0x05, "else"), (0x0F, "return")]:
    TABLE[_b] = OpInfo(_n, None, "none", ("control", _n))
TABLE[0x02] = OpInfo("block", None, "blocktype", ("control", "block"))
TABLE[0x03] = OpInfo("loop", None, "blocktype", ("control", "loop"))
TABLE[0x04] = OpInfo("if", None, "blocktype", ("control", "if"))
TABLE[0x0C] = OpInfo("br", None, "u32", ("control", "br"))
TABLE[0x0D] = OpInfo("br_if", None, "u32", ("control", "br_if"))
TABLE[0x0E] = OpInfo("br_table", None, "br_table", ("control", "br_table"))
TABLE[0x10] = OpInfo("call", None, "u32", ("control", "call"))
TABLE[0x11] = OpInfo("call_indirect", None, "call_indirect",
                     ("control", "call_indirect"))
TABLE[0x12] = OpInfo("return_call", "tail-call", "u32",
                     ("control", "return_call"))
TABLE[0x13] = OpInfo("return_call_indirect", "tail-call", "call_indirect",
                     ("control", "return_call_indirect"))

# --- parametric --------------------------------------------------------------
TABLE[0x1A] = OpInfo("drop", None, "none", ("parametric", "drop"))
TABLE[0x1B] = OpInfo("select", None, "none", ("parametric", "select"))

# --- variable references -----------------------------------------------------
for _b, _n in [(0x20, "local.get"), (0x21, "local.set"), (0x22, "local.tee"),
               (0x23, "global.get"), (0x24, "global.set")]:
    TABLE[_b] = OpInfo(_n, None, "u32", ("variable", _n))

# --- memory: loads / stores --------------------------------------------------
_LOADS = [
    (0x28, "i32.load", "i32"), (0x29, "i64.load", "i64"),
    (0x2A, "f32.load", "f32"), (0x2B, "f64.load", "f64"),
    (0x2C, "i32.load8_s", "i32"), (0x2D, "i32.load8_u", "i32"),
    (0x2E, "i32.load16_s", "i32"), (0x2F, "i32.load16_u", "i32"),
    (0x30, "i64.load8_s", "i64"), (0x31, "i64.load8_u", "i64"),
    (0x32, "i64.load16_s", "i64"), (0x33, "i64.load16_u", "i64"),
    (0x34, "i64.load32_s", "i64"), (0x35, "i64.load32_u", "i64"),
]
for _b, _n, _t in _LOADS:
    TABLE[_b] = OpInfo(_n, None, "memarg", ("load", _t))
_STORES = [
    (0x36, "i32.store", "i32"), (0x37, "i64.store", "i64"),
    (0x38, "f32.store", "f32"), (0x39, "f64.store", "f64"),
    (0x3A, "i32.store8", "i32"), (0x3B, "i32.store16", "i32"),
    (0x3C, "i64.store8", "i64"), (0x3D, "i64.store16", "i64"),
    (0x3E, "i64.store32", "i64"),
]
for _b, _n, _t in _STORES:
    TABLE[_b] = OpInfo(_n, None, "memarg", ("store", _t))
TABLE[0x3F] = OpInfo("memory.size", None, "reserved_zero", ("unary_i32",))
TABLE[0x40] = OpInfo("memory.grow", None, "reserved_zero", ("unary_i32",))

# --- constants ---------------------------------------------------------------
TABLE[0x41] = OpInfo("i32.const", None, "s32", ("const", "i32"))
TABLE[0x42] = OpInfo("i64.const", None, "s64", ("const", "i64"))
TABLE[0x43] = OpInfo("f32.const", None, "f32", ("const", "f32"))
TABLE[0x44] = OpInfo("f64.const", None, "f64", ("const", "f64"))

# --- comparisons -------------------------------------------------------------
TABLE.update(_comp("i32", 0x45,
                   ["eqz", "eq", "ne", "lt_s", "lt_u", "gt_s", "gt_u",
                    "le_s", "le_u", "ge_s", "ge_u"]))
TABLE.update(_comp("i64", 0x50,
                   ["eqz", "eq", "ne", "lt_s", "lt_u", "gt_s", "gt_u",
                    "le_s", "le_u", "ge_s", "ge_u"]))
TABLE.update(_comp("f32", 0x5B, ["eq", "ne", "lt", "gt", "le", "ge"]))
TABLE.update(_comp("f64", 0x61, ["eq", "ne", "lt", "gt", "le", "ge"]))

# --- numeric families --------------------------------------------------------
TABLE.update(_family("i32", 0x6A,
                     ["add", "sub", "mul", "div_s", "div_u", "rem_s", "rem_u",
                      "and", "or", "xor", "shl", "shr_s", "shr_u",
                      "rotl", "rotr"]))
TABLE.update(_family("i64", 0x7C,
                     ["add", "sub", "mul", "div_s", "div_u", "rem_s", "rem_u",
                      "and", "or", "xor", "shl", "shr_s", "shr_u",
                      "rotl", "rotr"]))
TABLE.update(_family("f32", 0x92,
                     ["add", "sub", "mul", "div", "min", "max", "copysign"]))
TABLE.update(_family("f64", 0xA0,
                     ["add", "sub", "mul", "div", "min", "max", "copysign"]))

# A representative subset of conversions (MVP, prefix 0xA7..0xC4).
_CONV = [
    (0xA7, "i32.wrap_i64", "i64", "i32"),
    (0xA8, "i32.trunc_f32_s", "f32", "i32"),
    (0xA9, "i32.trunc_f32_u", "f32", "i32"),
    (0xAA, "i32.trunc_f64_s", "f64", "i32"),
    (0xAB, "i32.trunc_f64_u", "f64", "i32"),
    (0xAC, "i64.extend_i32_s", "i32", "i64"),
    (0xAD, "i64.extend_i32_u", "i32", "i64"),
    (0xAE, "i64.trunc_f32_s", "f32", "i64"),
    (0xB2, "f32.convert_i32_s", "i32", "f32"),
    (0xB7, "f64.convert_i32_s", "i32", "f64"),
]
for _b, _n, _src, _dst in _CONV:
    TABLE[_b] = OpInfo(_n, None, "none", ("convert", _src, _dst))

# --- sign-extension operators ------------------------------------------------
for _b, _n, _t in [
        (0xC0, "i32.extend8_s", "i32"), (0xC1, "i32.extend16_s", "i32"),
        (0xC2, "i64.extend8_s", "i64"), (0xC3, "i64.extend16_s", "i64"),
        (0xC4, "i64.extend32_s", "i64")]:
    TABLE[_b] = OpInfo(_n, "sign-extension", "none", ("unary", _t))

# --- reference types ---------------------------------------------------------
TABLE[0xD0] = OpInfo("ref.null", "reference-types", "u32", ("ref_null",))
TABLE[0xD1] = OpInfo("ref.is_null", "reference-types", "none",
                     ("ref_is_null",))
TABLE[0xD2] = OpInfo("ref.func", "reference-types", "u32", ("ref_func",))

# --- 0xFC prefix: bulk-memory + non-trapping float-to-int --------------------
PREFIX_FC: dict[int, OpInfo] = {}
for _i, (_n, _src, _dst) in enumerate([
        ("i32.trunc_sat_f32_s", "f32", "i32"),
        ("i32.trunc_sat_f32_u", "f32", "i32"),
        ("i32.trunc_sat_f64_s", "f64", "i32"),
        ("i32.trunc_sat_f64_u", "f64", "i32"),
        ("i64.trunc_sat_f32_s", "f32", "i64"),
        ("i64.trunc_sat_f32_u", "f32", "i64"),
        ("i64.trunc_sat_f64_s", "f64", "i64"),
        ("i64.trunc_sat_f64_u", "f64", "i64")]):
    PREFIX_FC[_i] = OpInfo(_n, "nontrapping-float-to-int", "none",
                           ("convert", _src, _dst))
PREFIX_FC[0x08] = OpInfo("memory.init", "bulk-memory", "dataidx_zero",
                         ("bulk", "memory.init"))
PREFIX_FC[0x09] = OpInfo("data.drop", "bulk-memory", "u32",
                         ("bulk", "data.drop"))
PREFIX_FC[0x0A] = OpInfo("memory.copy", "bulk-memory", "two_zero",
                         ("bulk", "memory.copy"))
PREFIX_FC[0x0B] = OpInfo("memory.fill", "bulk-memory", "one_zero",
                         ("bulk", "memory.fill"))

# --- 0xFD prefix: SIMD --------------------------------------------------------
PREFIX_FD: dict[int, OpInfo] = {}
PREFIX_FD[0x0C] = OpInfo("v128.const", "simd", "v128", ("vconst", "v128"))
for _i, _n in [(0x0A, "i32x4.splat"), (0x0B, "i64x4.splat")]:
    PREFIX_FD[_i] = OpInfo(_n, "simd", "none", ("splat", "i32"))
PREFIX_FD[0x21] = OpInfo("i32x4.add", "simd", "none", ("binary", "v128"))

# Whole-prefix fallbacks for bytes belonging to a known proposal family even
# when the exact sub-opcode is not catalogued.
PREFIX_PROPOSAL = {0xFC: None, 0xFD: "simd", 0xFB: "gc", 0xFE: "threads"}

# Encoding shapes used while walking sub-prefixed opcodes.
SUB_OPERAND_SHAPE = {
    "v128": "v128",
    "dataidx_zero": "dataidx_zero",
    "u32": "u32",
    "two_zero": "two_zero",
    "one_zero": "one_zero",
}
