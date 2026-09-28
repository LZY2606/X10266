"""Opcode metadata and WebAssembly proposal/capability mapping.

Every defined byte is recorded, including opcodes that only exist behind a
proposal flag.  A byte that exists in no known proposal is reported as
``opcode.unknown``; a byte that exists only behind a disabled proposal is
reported as ``capability.missing``.  These two verdicts must never be merged.
"""
from __future__ import annotations

I32, I64, F32, F64, FUNCREF, EXTERNREF, V128 = (
    "i32", "i64", "f32", "f64", "funcref", "externref", "v128",
)

VALUE_TYPE_BYTES = {
    0x7F: I32,
    0x7E: I64,
    0x7D: F32,
    0x7C: F64,
    0x7B: V128,
    0x70: FUNCREF,
    0x6F: EXTERNREF,
}

VALUE_TYPE_PROPOSAL = {
    V128: "simd",
    EXTERNREF: "reference_types",
}

# proposal name -> set of opcodes gated by it
GATED_OPCODES: dict[str, set[int]] = {
    "tail_call": {0x12, 0x13},
    "reference_types": {0x16, 0x25, 0x26, 0xD0, 0xD1, 0xD2},
    "sign_extension": {0xC0, 0xC1, 0xC2, 0xC3, 0xC4},
    "exception_handling": {0x06, 0x07},
}

# Prefix families: 0xFC sub-opcodes
FC_SUBOPS: dict[int, tuple[str, str]] = {}
for sub in range(0, 8):
    FC_SUBOPS[sub] = ("nontrapping_f2i", "trunc_sat")
for sub in (8, 9, 10, 11):
    FC_SUBOPS[sub] = ("bulk_memory", "memory")
for sub in (12, 13, 14, 15, 16, 17):
    FC_SUBOPS[sub] = ("bulk_memory", "table")
PREFIX_PROPOSAL = {0xFD: "simd", 0xFE: "threads"}

# Numeric instruction stack signatures: opcode -> (pops, pushes)
_SIGS: dict[int, tuple[tuple[str, ...], tuple[str, ...]]] = {}

def _reg(op, pops=(), pushes=()):
    _SIGS[op] = (tuple(pops), tuple(pushes))

# comparisons / unary / binary for i32, i64, f32, f64
for op in range(0x45, 0x50):
    _reg(op, (I32, I32) if op != 0x45 else (I32,), (I32,))
for op in range(0x51, 0x63):
    _reg(op, (I32, I32) if op >= 0x54 else (I32,), (I32,))
for op in range(0x63, 0x79):
    _reg(op, (I64, I64) if op != 0x53 else (I64,), (I32,))
for op in range(0x79, 0x8B):
    _reg(op, (I64, I64) if op >= 0x7C else (I64,), (I64,))
for op in range(0x8B, 0x91):
    _reg(op, (F32, F32), (I32,))
for op in range(0x91, 0x98):
    _reg(op, (F32,), (F32,))
for op in range(0x98, 0x9F):
    _reg(op, (F32, F32), (F32,))
for op in range(0x9F, 0xA5):
    _reg(op, (F64, F64), (I32,))
for op in range(0xA5, 0xAC):
    _reg(op, (F64,), (F64,))
for op in range(0xAC, 0xB3):
    _reg(op, (F64, F64), (F64,))
# common conversions
_reg(0xA7, (I64,), (I32))       # i32.wrap_i64
_reg(0xAC, (I32,), (I64))       # i64.extend_i32_s
_reg(0xAD, (I32,), (I64))       # i64.extend_i32_u
_reg(0xBC, (F32,), (I32))       # i32.trunc_f32_s
_reg(0xC5, (F64,), (I32))       # i32.trunc_f64_s? reserved-safe extra
SIGNATURES = _SIGS

CONST_OPCODES = {0x41: I32, 0x42: I64, 0x43: F32, 0x44: F64}

MEMORY_LOADS: dict[int, tuple[str, int, bool]] = {}
for op, (t, w, signed) in {
    0x28: (I32, 32, None), 0x29: (I64, 32, None), 0x2A: (F32, 32, None),
    0x2B: (F64, 32, None), 0x2C: (I32, 8, True), 0x2D: (I32, 8, False),
    0x2E: (I32, 16, True), 0x2F: (I32, 16, False), 0x30: (I64, 8, True),
    0x31: (I64, 8, False), 0x32: (I64, 16, True), 0x33: (I64, 16, False),
    0x34: (I64, 32, True), 0x35: (I64, 32, False),
}.items():
    MEMORY_LOADS[op] = (t, w, signed)
MEMORY_STORES: dict[int, tuple[str, int]] = {}
for op, (t, w) in {
    0x36: (I32, 32), 0x37: (I64, 32), 0x38: (F32, 32), 0x39: (F64, 32),
    0x3A: (I32, 8), 0x3B: (I32, 16), 0x3C: (I64, 8), 0x3D: (I64, 16),
    0x3E: (I64, 32),
}.items():
    MEMORY_STORES[op] = (t, w)

KNOWN_PROPOSALS = (
    "multivalue", "reference_types", "sign_extension", "bulk_memory",
    "nontrapping_f2i", "simd", "threads", "tail_call", "exception_handling",
    "memory64",
)
DEFAULT_CAPABILITIES = {
    "multivalue": False,
    "reference_types": False,
    "sign_extension": False,
    "bulk_memory": False,
    "nontrapping_f2i": False,
    "simd": False,
    "threads": False,
    "tail_call": False,
    "exception_handling": False,
    "memory64": False,
}
