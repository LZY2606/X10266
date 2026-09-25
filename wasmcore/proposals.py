"""Proposal registry: which opcodes / features are gated behind which
WebAssembly proposal. Used to distinguish capability-missing (opcode is
registered but its proposal is disabled) from unknown-byte (opcode is
not registered anywhere)."""

ALL_PROPOSALS = (
    "multi-value",
    "bulk-memory",
    "sign-extension",
    "saturating-float-to-int",
    "reference-types",
    "mutable-globals",
)

# value-type byte -> proposal that gates it (None = MVP)
VALTYPE_PROPOSAL = {
    0x7B: "simd",
    0x6F: "reference-types",
}

# opcode byte -> (mnemonic, gating proposal or None, handler kind)
OPS = {
    0x00: ("unreachable", None, "unreachable"),
    0x01: ("nop", None, "none"),
    0x02: ("block", None, "block"),
    0x03: ("loop", None, "loop"),
    0x04: ("if", None, "if"),
    0x05: ("else", None, "else"),
    0x0B: ("end", None, "end"),
    0x0C: ("br", None, "br"),
    0x0D: ("br_if", None, "br_if"),
    0x0F: ("return", None, "return"),
    0x10: ("call", None, "call"),
    0x1A: ("drop", None, "drop"),
    0x1B: ("select", None, "select"),
    0x20: ("local.get", None, "localget"),
    0x21: ("local.set", None, "localset"),
    0x22: ("local.tee", None, "localtee"),
    0x23: ("global.get", None, "globalget"),
    0x24: ("global.set", None, "globalset"),
    0x28: ("i32.load", None, "memload_i32"),
    0x36: ("i32.store", None, "memstore_i32"),
    0x3F: ("memory.size", None, "memsize"),
    0x40: ("memory.grow", None, "memgrow"),
    0x41: ("i32.const", None, "i32const"),
    0x42: ("i64.const", None, "i64const"),
    0x45: ("i32.eqz", None, "testi32"),
    0x46: ("i32.eq", None, "cmpi32"),
    0x6A: ("i32.add", None, "bini32"),
    0x6B: ("i32.sub", None, "bini32"),
    0x6C: ("i32.mul", None, "bini32"),
    0xC0: ("i32.extend8_s", "sign-extension", "uni32"),
    0xC1: ("i32.extend16_s", "sign-extension", "uni32"),
    0xC2: ("i64.extend8_s", "sign-extension", "uni64"),
    0xD0: ("ref.null", "reference-types", "refnull"),
    0xD1: ("ref.is_null", "reference-types", "refisnull"),
    0xFC: (None, None, "fc"),
}

# 0xFC-prefixed sub-opcodes: subop -> (mnemonic, gating proposal, handler kind)
FC_OPS = {
    0: ("i32.trunc_sat_f32_s", "saturating-float-to-int", "truncsat_i32"),
    10: ("memory.copy", "bulk-memory", "memcopy"),
    11: ("memory.fill", "bulk-memory", "memfill"),
}

FEATURE_MULTI_VALUE = "multi-value"
FEATURE_MUTABLE_GLOBALS = "mutable-globals"
