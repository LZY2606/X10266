"""Opcode metadata: mnemonic, stack effect, introducing proposal.

Generated from the authoritative WebAssembly binary opcode layout. Every byte
the validator sees is classified: an MVP opcode, a recognised proposal opcode
(capability gate), or a genuinely unknown byte.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from . import typesys as T


@dataclass(frozen=True)
class OpSig:
    mnemonic: str
    pops: Tuple[str, ...]
    pushes: Tuple[str, ...]
    proposal: str = "mvp"
    kind: str = "plain"


def _s(mn, pops, pushes, proposal="mvp", kind="plain"):
    return OpSig(mn, tuple(pops), tuple(pushes), proposal, kind)


OPS: Dict[int, OpSig] = {}


OPS[0x45] = _s("i32.eqz", (T.I32,), (T.I32,))
OPS[0x46] = _s("i32.eq", (T.I32, T.I32), (T.I32,))
OPS[0x47] = _s("i32.ne", (T.I32, T.I32), (T.I32,))
OPS[0x48] = _s("i32.lt_s", (T.I32, T.I32), (T.I32,))
OPS[0x49] = _s("i32.lt_u", (T.I32, T.I32), (T.I32,))
OPS[0x4A] = _s("i32.gt_s", (T.I32, T.I32), (T.I32,))
OPS[0x4B] = _s("i32.gt_u", (T.I32, T.I32), (T.I32,))
OPS[0x4C] = _s("i32.le_s", (T.I32, T.I32), (T.I32,))
OPS[0x4D] = _s("i32.le_u", (T.I32, T.I32), (T.I32,))
OPS[0x4E] = _s("i32.ge_s", (T.I32, T.I32), (T.I32,))
OPS[0x4F] = _s("i32.ge_u", (T.I32, T.I32), (T.I32,))
OPS[0x50] = _s("i64.eqz", (T.I64,), (T.I32,))
OPS[0x51] = _s("i64.eq", (T.I64, T.I64), (T.I32,))
OPS[0x52] = _s("i64.ne", (T.I64, T.I64), (T.I32,))
OPS[0x53] = _s("i64.lt_s", (T.I64, T.I64), (T.I32,))
OPS[0x54] = _s("i64.lt_u", (T.I64, T.I64), (T.I32,))
OPS[0x55] = _s("i64.gt_s", (T.I64, T.I64), (T.I32,))
OPS[0x56] = _s("i64.gt_u", (T.I64, T.I64), (T.I32,))
OPS[0x57] = _s("i64.le_s", (T.I64, T.I64), (T.I32,))
OPS[0x58] = _s("i64.le_u", (T.I64, T.I64), (T.I32,))
OPS[0x59] = _s("i64.ge_s", (T.I64, T.I64), (T.I32,))
OPS[0x5A] = _s("i64.ge_u", (T.I64, T.I64), (T.I32,))
OPS[0x5B] = _s("f32.eqz", (T.F32,), (T.I32,))
OPS[0x5C] = _s("f32.eq", (T.F32, T.F32), (T.I32,))
OPS[0x5D] = _s("f32.ne", (T.F32, T.F32), (T.I32,))
OPS[0x5E] = _s("f32.lt", (T.F32, T.F32), (T.I32,))
OPS[0x5F] = _s("f32.gt", (T.F32, T.F32), (T.I32,))
OPS[0x60] = _s("f32.le", (T.F32, T.F32), (T.I32,))
OPS[0x61] = _s("f32.ge", (T.F32, T.F32), (T.I32,))
OPS[0x62] = _s("f64.eqz", (T.F64,), (T.I32,))
OPS[0x63] = _s("f64.eq", (T.F64, T.F64), (T.I32,))
OPS[0x64] = _s("f64.ne", (T.F64, T.F64), (T.I32,))
OPS[0x65] = _s("f64.lt", (T.F64, T.F64), (T.I32,))
OPS[0x66] = _s("f64.gt", (T.F64, T.F64), (T.I32,))
OPS[0x67] = _s("f64.le", (T.F64, T.F64), (T.I32,))
OPS[0x68] = _s("f64.ge", (T.F64, T.F64), (T.I32,))
OPS[0x69] = _s("i32.clz", (T.I32,), (T.I32,))
OPS[0x6A] = _s("i32.ctz", (T.I32,), (T.I32,))
OPS[0x6B] = _s("i32.popcnt", (T.I32,), (T.I32,))
OPS[0x6C] = _s("i32.add", (T.I32,T.I32), (T.I32,))
OPS[0x6D] = _s("i32.sub", (T.I32,T.I32), (T.I32,))
OPS[0x6E] = _s("i32.mul", (T.I32,T.I32), (T.I32,))
OPS[0x6F] = _s("i32.div_s", (T.I32,T.I32), (T.I32,))
OPS[0x70] = _s("i32.div_u", (T.I32,T.I32), (T.I32,))
OPS[0x71] = _s("i32.rem_s", (T.I32,T.I32), (T.I32,))
OPS[0x72] = _s("i32.rem_u", (T.I32,T.I32), (T.I32,))
OPS[0x73] = _s("i32.and", (T.I32,T.I32), (T.I32,))
OPS[0x74] = _s("i32.or", (T.I32,T.I32), (T.I32,))
OPS[0x75] = _s("i32.xor", (T.I32,T.I32), (T.I32,))
OPS[0x76] = _s("i32.shl", (T.I32,T.I32), (T.I32,))
OPS[0x77] = _s("i32.shr_s", (T.I32,T.I32), (T.I32,))
OPS[0x78] = _s("i32.shr_u", (T.I32,T.I32), (T.I32,))
OPS[0x79] = _s("i32.rotl", (T.I32,T.I32), (T.I32,))
OPS[0x7A] = _s("i32.rotr", (T.I32,T.I32), (T.I32,))
OPS[0x7B] = _s("i64.clz", (T.I64,), (T.I64,))
OPS[0x7C] = _s("i64.ctz", (T.I64,), (T.I64,))
OPS[0x7D] = _s("i64.popcnt", (T.I64,), (T.I64,))
OPS[0x7E] = _s("i64.add", (T.I64,T.I64), (T.I64,))
OPS[0x7F] = _s("i64.sub", (T.I64,T.I64), (T.I64,))
OPS[0x80] = _s("i64.mul", (T.I64,T.I64), (T.I64,))
OPS[0x81] = _s("i64.div_s", (T.I64,T.I64), (T.I64,))
OPS[0x82] = _s("i64.div_u", (T.I64,T.I64), (T.I64,))
OPS[0x83] = _s("i64.rem_s", (T.I64,T.I64), (T.I64,))
OPS[0x84] = _s("i64.rem_u", (T.I64,T.I64), (T.I64,))
OPS[0x85] = _s("i64.and", (T.I64,T.I64), (T.I64,))
OPS[0x86] = _s("i64.or", (T.I64,T.I64), (T.I64,))
OPS[0x87] = _s("i64.xor", (T.I64,T.I64), (T.I64,))
OPS[0x88] = _s("i64.shl", (T.I64,T.I64), (T.I64,))
OPS[0x89] = _s("i64.shr_s", (T.I64,T.I64), (T.I64,))
OPS[0x8A] = _s("i64.shr_u", (T.I64,T.I64), (T.I64,))
OPS[0x8B] = _s("i64.rotl", (T.I64,T.I64), (T.I64,))
OPS[0x8C] = _s("i64.rotr", (T.I64,T.I64), (T.I64,))
OPS[0x8D] = _s("f32.abs", (T.F32,), (T.F32,))
OPS[0x8E] = _s("f32.neg", (T.F32,), (T.F32,))
OPS[0x8F] = _s("f32.ceil", (T.F32,), (T.F32,))
OPS[0x90] = _s("f32.floor", (T.F32,), (T.F32,))
OPS[0x91] = _s("f32.trunc", (T.F32,), (T.F32,))
OPS[0x92] = _s("f32.nearest", (T.F32,), (T.F32,))
OPS[0x93] = _s("f32.sqrt", (T.F32,), (T.F32,))
OPS[0x94] = _s("f32.add", (T.F32,T.F32), (T.F32,))
OPS[0x95] = _s("f32.sub", (T.F32,T.F32), (T.F32,))
OPS[0x96] = _s("f32.mul", (T.F32,T.F32), (T.F32,))
OPS[0x97] = _s("f32.div", (T.F32,T.F32), (T.F32,))
OPS[0x98] = _s("f32.min", (T.F32,T.F32), (T.F32,))
OPS[0x99] = _s("f32.max", (T.F32,T.F32), (T.F32,))
OPS[0x9A] = _s("f32.copysign", (T.F32,T.F32), (T.F32,))
OPS[0x9B] = _s("f64.abs", (T.F64,), (T.F64,))
OPS[0x9C] = _s("f64.neg", (T.F64,), (T.F64,))
OPS[0x9D] = _s("f64.ceil", (T.F64,), (T.F64,))
OPS[0x9E] = _s("f64.floor", (T.F64,), (T.F64,))
OPS[0x9F] = _s("f64.trunc", (T.F64,), (T.F64,))
OPS[0xA0] = _s("f64.nearest", (T.F64,), (T.F64,))
OPS[0xA1] = _s("f64.sqrt", (T.F64,), (T.F64,))
OPS[0xA2] = _s("f64.add", (T.F64,T.F64), (T.F64,))
OPS[0xA3] = _s("f64.sub", (T.F64,T.F64), (T.F64,))
OPS[0xA4] = _s("f64.mul", (T.F64,T.F64), (T.F64,))
OPS[0xA5] = _s("f64.div", (T.F64,T.F64), (T.F64,))
OPS[0xA6] = _s("f64.min", (T.F64,T.F64), (T.F64,))
OPS[0xA7] = _s("f64.max", (T.F64,T.F64), (T.F64,))
OPS[0xA8] = _s("f64.copysign", (T.F64,T.F64), (T.F64,))
OPS[0xA9] = _s("i32.wrap_i64", (T.I64,), (T.I32,), "mvp")
OPS[0xAA] = _s("i32.trunc_f32_s", (T.F32,), (T.I32,), "mvp")
OPS[0xAB] = _s("i32.trunc_f32_u", (T.F32,), (T.I32,), "mvp")
OPS[0xAC] = _s("i32.trunc_f64_s", (T.F64,), (T.I32,), "mvp")
OPS[0xAD] = _s("i32.trunc_f64_u", (T.F64,), (T.I32,), "mvp")
OPS[0xAE] = _s("i64.extend_i32_s", (T.I32,), (T.I64,), "mvp")
OPS[0xAF] = _s("i64.extend_i32_u", (T.I32,), (T.I64,), "mvp")
OPS[0xB0] = _s("i64.trunc_f32_s", (T.F32,), (T.I64,), "mvp")
OPS[0xB1] = _s("i64.trunc_f32_u", (T.F32,), (T.I64,), "mvp")
OPS[0xB2] = _s("i64.trunc_f64_s", (T.F64,), (T.I64,), "mvp")
OPS[0xB3] = _s("i64.trunc_f64_u", (T.F64,), (T.I64,), "mvp")
OPS[0xB4] = _s("f32.convert_i32_s", (T.I32,), (T.F32,), "mvp")
OPS[0xB5] = _s("f32.convert_i32_u", (T.I32,), (T.F32,), "mvp")
OPS[0xB6] = _s("f32.convert_i64_s", (T.I64,), (T.F32,), "mvp")
OPS[0xB7] = _s("f32.convert_i64_u", (T.I64,), (T.F32,), "mvp")
OPS[0xB8] = _s("f32.demote_f64", (T.F64,), (T.F32,), "mvp")
OPS[0xB9] = _s("f64.convert_i32_s", (T.I32,), (T.F64,), "mvp")
OPS[0xBA] = _s("f64.convert_i32_u", (T.I32,), (T.F64,), "mvp")
OPS[0xBB] = _s("f64.convert_i64_s", (T.I64,), (T.F64,), "mvp")
OPS[0xBC] = _s("f64.convert_i64_u", (T.I64,), (T.F64,), "mvp")
OPS[0xBD] = _s("f64.promote_f32", (T.F32,), (T.F64,), "mvp")
OPS[0xBE] = _s("i32.reinterpret_f32", (T.F32,), (T.I32,), "mvp")
OPS[0xBF] = _s("i64.reinterpret_f64", (T.F64,), (T.I64,), "mvp")
OPS[0xC0] = _s("f32.reinterpret_i32", (T.I32,), (T.F32,), "mvp")
OPS[0xC1] = _s("f64.reinterpret_i64", (T.I64,), (T.F64,), "mvp")
OPS[0xC2] = _s("i32.extend8_s", (T.I32,), (T.I32,), "sign_extension")
OPS[0xC3] = _s("i32.extend16_s", (T.I32,), (T.I32,), "sign_extension")
OPS[0xC4] = _s("i64.extend8_s", (T.I64,), (T.I64,), "sign_extension")
OPS[0xC5] = _s("i64.extend16_s", (T.I64,), (T.I64,), "sign_extension")
OPS[0xC6] = _s("i64.extend32_s", (T.I64,), (T.I64,), "sign_extension")
OPS[0x28] = _s("i32.load", (T.I32,), (T.I32,), "mvp", "load")
OPS[0x29] = _s("i64.load", (T.I32,), (T.I64,), "mvp", "load")
OPS[0x2A] = _s("f32.load", (T.I32,), (T.F32,), "mvp", "load")
OPS[0x2B] = _s("f64.load", (T.I32,), (T.F64,), "mvp", "load")
OPS[0x2C] = _s("i32.load8_s", (T.I32,), (T.I32,), "mvp", "load")
OPS[0x2D] = _s("i32.load8_u", (T.I32,), (T.I32,), "mvp", "load")
OPS[0x2E] = _s("i32.load16_s", (T.I32,), (T.I32,), "mvp", "load")
OPS[0x2F] = _s("i32.load16_u", (T.I32,), (T.I32,), "mvp", "load")
OPS[0x30] = _s("i64.load8_s", (T.I32,), (T.I64,), "mvp", "load")
OPS[0x31] = _s("i64.load8_u", (T.I32,), (T.I64,), "mvp", "load")
OPS[0x32] = _s("i64.load16_s", (T.I32,), (T.I64,), "mvp", "load")
OPS[0x33] = _s("i64.load16_u", (T.I32,), (T.I64,), "mvp", "load")
OPS[0x34] = _s("i64.load32_s", (T.I32,), (T.I64,), "mvp", "load")
OPS[0x35] = _s("i64.load32_u", (T.I32,), (T.I64,), "mvp", "load")
OPS[0x36] = _s("i32.store", (T.I32,T.I32,), (), "mvp", "store")
OPS[0x37] = _s("i64.store", (T.I32,T.I64,), (), "mvp", "store")
OPS[0x38] = _s("f32.store", (T.I32,T.F32,), (), "mvp", "store")
OPS[0x39] = _s("f64.store", (T.I32,T.F64,), (), "mvp", "store")
OPS[0x3A] = _s("i32.store8", (T.I32,T.I32,), (), "mvp", "store")
OPS[0x3B] = _s("i32.store16", (T.I32,T.I32,), (), "mvp", "store")
OPS[0x3C] = _s("i64.store8", (T.I32,T.I64,), (), "mvp", "store")
OPS[0x3D] = _s("i64.store16", (T.I32,T.I64,), (), "mvp", "store")
OPS[0x3E] = _s("i64.store32", (T.I32,T.I64,), (), "mvp", "store")
OPS[0x3F] = _s("memory.size", (), (T.I32,), "mvp", "mem")
OPS[0x40] = _s("memory.grow", (T.I32,), (T.I32,), "mvp", "mem")
OPS[0xD0] = _s("ref.null", (), (T.FUNCREF,), "reference_types", "const")
OPS[0xD1] = _s("ref.is_null", (T.FUNCREF,), (T.I32,), "reference_types")
OPS[0xD2] = _s("ref.func", (), (T.FUNCREF,), "reference_types", "const")


PREFIX_FC = {
    0: _s("i32.trunc_sat_f32_s", (T.F32,), (T.I32,), "saturating_float_to_int"),
    1: _s("i32.trunc_sat_f32_u", (T.F32,), (T.I32,), "saturating_float_to_int"),
    2: _s("i32.trunc_sat_f64_s", (T.F64,), (T.I32,), "saturating_float_to_int"),
    3: _s("i32.trunc_sat_f64_u", (T.F64,), (T.I32,), "saturating_float_to_int"),
    4: _s("i64.trunc_sat_f32_s", (T.F32,), (T.I64,), "saturating_float_to_int"),
    5: _s("i64.trunc_sat_f32_u", (T.F32,), (T.I64,), "saturating_float_to_int"),
    6: _s("i64.trunc_sat_f64_s", (T.F64,), (T.I64,), "saturating_float_to_int"),
    7: _s("i64.trunc_sat_f64_u", (T.F64,), (T.I64,), "saturating_float_to_int"),
    8: _s("memory.init", (), (), "bulk_memory"),
    9: _s("data.drop", (), (), "bulk_memory"),
    10: _s("memory.copy", (T.I32, T.I32, T.I32), (), "bulk_memory"),
    11: _s("memory.fill", (T.I32, T.I32, T.I32), (), "bulk_memory"),
}

PREFIX_PROPOSAL = {0xFC: "saturating_float_to_int", 0xFD: "simd", 0xFE: "threads"}


def lookup(opcode: int) -> Optional[OpSig]:
    return OPS.get(opcode)

