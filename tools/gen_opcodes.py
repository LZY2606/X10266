header = '''"""Opcode metadata: mnemonic, stack effect, introducing proposal.

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
'''
lines = [header, ""]

def emit(code, expr):
    lines.append(f"OPS[0x{code:02X}] = {expr}")

def emit_range(base, items, prefix, pops, pushes):
    for i, name in enumerate(items):
        p = f"({pops},)" if isinstance(pops, str) else f"{tuple(pops)}"
        emit(base+i, f'_s("{prefix}.{name}", {pops}, {pushes})')

# ---- comparisons (eqz + binary compares) ----
icmp = ["eq","ne","lt_s","lt_u","gt_s","gt_u","le_s","le_u","ge_s","ge_u"]
fcmp = ["eq","ne","lt","gt","le","ge"]
blocks = [
    (0x45, "i32", True), (0x50, "i64", True),
    (0x5B, "f32", False), (0x62, "f64", False),
]
for base, typ, signed in blocks:
    emit(base, f'_s("{typ}.eqz", (T.{typ.upper()},), (T.I32,))')
    for j, name in enumerate(icmp if signed else fcmp):
        emit(base+1+j, f'_s("{typ}.{name}", (T.{typ.upper()}, T.{typ.upper()}), (T.I32,))')

# ---- integer arithmetic: clz,ctz,popcnt (unary) then 14 binary ----
iarith = ["add","sub","mul","div_s","div_u","rem_s","rem_u","and","or","xor","shl","shr_s","shr_u","rotl","rotr"]
iun = ["clz","ctz","popcnt"]
flt_arith = ["add","sub","mul","div","min","max","copysign"]
flt_un = ["abs","neg","ceil","floor","trunc","nearest","sqrt"]

def arith_block(base, typ):
    Tn = f"T.{typ.upper()}"
    for k, name in enumerate(iun):
        emit(base+k, f'_s("{typ}.{name}", ({Tn},), ({Tn},))')
    b2 = base+len(iun)
    for k, name in enumerate(iarith):
        emit(b2+k, f'_s("{typ}.{name}", ({Tn},{Tn}), ({Tn},))')
    return b2+len(iarith)

def float_arith_block(base, typ):
    Tn = f"T.{typ.upper()}"
    for k, name in enumerate(flt_un):
        emit(base+k, f'_s("{typ}.{name}", ({Tn},), ({Tn},))')
    b2 = base+len(flt_un)
    for k, name in enumerate(flt_arith):
        emit(b2+k, f'_s("{typ}.{name}", ({Tn},{Tn}), ({Tn},))')
    return b2+len(flt_arith)

nxt = arith_block(0x69, "i32")
assert nxt == 0x7B, hex(nxt)
nxt = arith_block(nxt, "i64")
assert nxt == 0x8D, hex(nxt)
nxt = float_arith_block(nxt, "f32")
assert nxt == 0x9B, hex(nxt)
nxt = float_arith_block(nxt, "f64")
assert nxt == 0xA9, hex(nxt)

# ---- conversions A9..C1 ----
convs = [
 ("i32.wrap_i64",["i64"],["i32"],"mvp"),
 ("i32.trunc_f32_s",["f32"],["i32"],"mvp"),
 ("i32.trunc_f32_u",["f32"],["i32"],"mvp"),
 ("i32.trunc_f64_s",["f64"],["i32"],"mvp"),
 ("i32.trunc_f64_u",["f64"],["i32"],"mvp"),
 ("i64.extend_i32_s",["i32"],["i64"],"mvp"),
 ("i64.extend_i32_u",["i32"],["i64"],"mvp"),
 ("i64.trunc_f32_s",["f32"],["i64"],"mvp"),
 ("i64.trunc_f32_u",["f32"],["i64"],"mvp"),
 ("i64.trunc_f64_s",["f64"],["i64"],"mvp"),
 ("i64.trunc_f64_u",["f64"],["i64"],"mvp"),
 ("f32.convert_i32_s",["i32"],["f32"],"mvp"),
 ("f32.convert_i32_u",["i32"],["f32"],"mvp"),
 ("f32.convert_i64_s",["i64"],["f32"],"mvp"),
 ("f32.convert_i64_u",["i64"],["f32"],"mvp"),
 ("f32.demote_f64",["f64"],["f32"],"mvp"),
 ("f64.convert_i32_s",["i32"],["f64"],"mvp"),
 ("f64.convert_i32_u",["i32"],["f64"],"mvp"),
 ("f64.convert_i64_s",["i64"],["f64"],"mvp"),
 ("f64.convert_i64_u",["i64"],["f64"],"mvp"),
 ("f64.promote_f32",["f32"],["f64"],"mvp"),
 ("i32.reinterpret_f32",["f32"],["i32"],"mvp"),
 ("i64.reinterpret_f64",["f64"],["i64"],"mvp"),
 ("f32.reinterpret_i32",["i32"],["f32"],"mvp"),
 ("f64.reinterpret_i64",["i64"],["f64"],"mvp"),
]
for k,(mn,pops,pushes,prop) in enumerate(convs):
    code = 0xA9+k
    pt = ",".join(f"T.{x.upper()}" for x in pops)
    qt = ",".join(f"T.{x.upper()}" for x in pushes)
    pt = (pt + ",") if pt else ""
    qt = (qt + ",") if qt else ""
    emit(code, f'_s("{mn}", ({pt}), ({qt}), "{prop}")')
assert 0xA9+len(convs)-1 == 0xC1

# ---- sign extension C2..C6 ----
sx = [("i32.extend8_s","i32"),("i32.extend16_s","i32"),
      ("i64.extend8_s","i64"),("i64.extend16_s","i64"),("i64.extend32_s","i64")]
for k,(mn,typ) in enumerate(sx):
    Tn=f"T.{typ.upper()}"
    emit(0xC2+k, f'_s("{mn}", ({Tn},), ({Tn},), "sign_extension")')

mem = {
 0x28:("i32.load",["i32"],["i32"],"load"),0x29:("i64.load",["i32"],["i64"],"load"),
 0x2A:("f32.load",["i32"],["f32"],"load"),0x2B:("f64.load",["i32"],["f64"],"load"),
 0x2C:("i32.load8_s",["i32"],["i32"],"load"),0x2D:("i32.load8_u",["i32"],["i32"],"load"),
 0x2E:("i32.load16_s",["i32"],["i32"],"load"),0x2F:("i32.load16_u",["i32"],["i32"],"load"),
 0x30:("i64.load8_s",["i32"],["i64"],"load"),0x31:("i64.load8_u",["i32"],["i64"],"load"),
 0x32:("i64.load16_s",["i32"],["i64"],"load"),0x33:("i64.load16_u",["i32"],["i64"],"load"),
 0x34:("i64.load32_s",["i32"],["i64"],"load"),0x35:("i64.load32_u",["i32"],["i64"],"load"),
 0x36:("i32.store",["i32","i32"],[],"store"),0x37:("i64.store",["i32","i64"],[],"store"),
 0x38:("f32.store",["i32","f32"],[],"store"),0x39:("f64.store",["i32","f64"],[],"store"),
 0x3A:("i32.store8",["i32","i32"],[],"store"),0x3B:("i32.store16",["i32","i32"],[],"store"),
 0x3C:("i64.store8",["i32","i64"],[],"store"),0x3D:("i64.store16",["i32","i64"],[],"store"),
 0x3E:("i64.store32",["i32","i64"],[],"store"),
 0x3F:("memory.size",[],["i32"],"mem"),0x40:("memory.grow",["i32"],["i32"],"mem"),
}
for code,(mn,pops,pushes,kind) in sorted(mem.items()):
    pt=",".join(f"T.{x.upper()}" for x in pops)
    qt=",".join(f"T.{x.upper()}" for x in pushes)
    pt=(pt+",") if pt else ""
    qt=(qt+",") if qt else ""
    emit(code, f'_s("{mn}", ({pt}), ({qt}), "mvp", "{kind}")')

# references
emit(0xD0, '_s("ref.null", (), (T.FUNCREF,), "reference_types", "const")')
emit(0xD1, '_s("ref.is_null", (T.FUNCREF,), (T.I32,), "reference_types")')
emit(0xD2, '_s("ref.func", (), (T.FUNCREF,), "reference_types", "const")')

tail = '''

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
'''
lines.append(tail)
open("wasm_audit/core/opcodes.py","w").write("\n".join(lines)+"\n")
print("written", len(lines), "lines")
