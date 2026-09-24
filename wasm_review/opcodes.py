"""Opcode catalogue with proposal gates.

Every known non-MVP opcode carries the set of proposal switches that unlock
it.  An opcode that belongs to a *disabled* proposal produces a
``capability_missing`` finding (listing every candidate switch that would
unlock it); an opcode belonging to no known proposal produces
``unknown_byte``. The two are never confused.
"""

# Proposal switches recognised by the capability set.
KNOWN_PROPOSALS = (
    "multi_value",
    "reference_types",
    "bulk_memory",
    "simd",
    "tail_call",
)

# value types
VALTYPES = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64"}
REFTYPES = {0x70: "funcref", 0x6F: "externref"}

# MVP opcode -> (mnemonic, immediate kind).
# immediate kinds: none, localidx, globalidx, funcidx, memarg,
# blocktype, call_indirect, u32imm, s32imm, s64imm
MVP_OPCODES: dict[int, tuple[str, str]] = {
    0x00: ("unreachable", "none"),
    0x01: ("nop", "none"),
    0x02: ("block", "blocktype"),
    0x03: ("loop", "blocktype"),
    0x04: ("if", "blocktype"),
    0x05: ("else", "none"),
    0x0B: ("end", "none"),
    0x0C: ("br", "u32imm"),
    0x0D: ("br_if", "u32imm"),
    0x0F: ("return", "none"),
    0x10: ("call", "funcidx"),
    0x11: ("call_indirect", "call_indirect"),
    0x1A: ("drop", "none"),
    0x1B: ("select", "none"),
    0x20: ("local.get", "localidx"),
    0x21: ("local.set", "localidx"),
    0x22: ("local.tee", "localidx"),
    0x23: ("global.get", "globalidx"),
    0x24: ("global.set", "globalidx"),
    0x28: ("i32.load", "memarg"),
    0x36: ("i32.store", "memarg"),
    0x3F: ("memory.size", "u32imm"),
    0x40: ("memory.grow", "u32imm"),
    0x41: ("i32.const", "s32imm"),
    0x42: ("i64.const", "s64imm"),
    0x45: ("i32.eqz", "none"),
    0x46: ("i32.eq", "none"),
    0x48: ("i32.lt_s", "none"),
    0x6A: ("i32.add", "none"),
    0x6B: ("i32.sub", "none"),
}

# Gated opcodes: opcode -> (mnemonic, immediate kind, frozenset of switches)
GATED_OPCODES: dict[int, tuple[str, str, frozenset[str]]] = {
    0x12: ("return_call", "funcidx", frozenset({"tail_call"})),
    0xD0: ("ref.null", "u32imm", frozenset({"reference_types"})),
    0xD2: ("ref.func", "funcidx", frozenset({"reference_types"})),
    0xFC: ("__prefix_fc__", "fc_prefix", frozenset()),
    0xFD: ("__prefix_fd__", "simd_prefix", frozenset({"simd"})),
}

# 0xFC sub-opcodes (bulk_memory).
FC_SUB: dict[int, tuple[str, str, frozenset[str]]] = {
    8:  ("memory.init", "mem_data_table", frozenset({"bulk_memory"})),
    9:  ("data.drop", "dataidx", frozenset({"bulk_memory"})),
    10: ("memory.copy", "two_memzero", frozenset({"bulk_memory"})),
    11: ("memory.fill", "memzero", frozenset({"bulk_memory"})),
}

# A deliberately unassigned byte so the archive can prove the distinction
# between "capability missing" and "unknown byte".
UNASSIGNED_PROOF_BYTE = 0x07


def lookup(opcode: int) -> tuple[str, str, frozenset[str] | None, bool]:
    """Return (mnemonic, imm_kind, gate, is_mvp)."""
    if opcode in MVP_OPCODES:
        m, k = MVP_OPCODES[opcode]
        return m, k, frozenset(), True
    if opcode in GATED_OPCODES:
        m, k, gate = GATED_OPCODES[opcode]
        return m, k, gate, False
    return "unknown", "unknown", None, False


def default_capabilities() -> dict[str, bool]:
    return {name: False for name in KNOWN_PROPOSALS}
