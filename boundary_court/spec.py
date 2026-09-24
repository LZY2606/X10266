"""WebAssembly spec constants: value types, sections, feature switches."""
from __future__ import annotations

# Well-known section ids (0 = custom).
SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "data_count",
}
ORDERED_KNOWN = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]

VALTYPE = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64"}
# v128 is gated by simd; funcref/externref are gated by reference_types,
# but type-index shorthand 0x62 (funcref) remains available everywhere.
REFTYPE = {0x70: "funcref", 0x6F: "externref"}
V128 = 0x7B

FUNC_KIND = 0x00
TABLE_KIND = 0x01
MEM_KIND = 0x02
GLOBAL_KIND = 0x03

# Known proposals understood by the capability gate.
KNOWN_FEATURES = [
    "multivalue",
    "simd",
    "reference_types",
    "bulk_memory",
    "sign_extension",
]
DEFAULT_FEATURES = {
    "multivalue": True,
    "simd": False,
    "reference_types": False,
    "bulk_memory": False,
    "sign_extension": False,
}
