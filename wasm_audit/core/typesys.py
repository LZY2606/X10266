"""Value types, function/block types and numeric limits."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple


# Numeric / reference value types (stack entries).
I32 = "i32"
I64 = "i64"
F32 = "f32"
F64 = "f64"
V128 = "v128"
FUNCREF = "funcref"
EXTERNREF = "externref"

VALTYPE_BYTES = {
    0x7F: I32,
    0x7E: I64,
    0x7D: F32,
    0x7C: F64,
    0x7B: V128,
    0x70: FUNCREF,
    0x6F: EXTERNREF,
}


@dataclass
class FuncType:
    params: List[str]
    results: List[str]

    def key(self) -> str:
        return "(" + ",".join(self.params) + ")->(" + ",".join(self.results) + ")"


@dataclass
class BlockType:
    kind: str  # "empty" | "valtype" | "typeidx"
    results: List[str]
    params: List[str]
    typeidx: Optional[int] = None


# Limits per the WebAssembly spec and common host restrictions.
LIMITS = {
    "max_types": 1_000_000,
    "max_functions": 1_000_000,
    "max_globals": 1_000_000,
    "max_tables": 100_000,
    "max_memories": 1,  # MVP: one memory (multi-memory is a proposal)
    "max_table_size": 0xFFFFFFFF,
    "max_memory_pages_u32": 0xFFFFFFFF,
    "wasm_page_size": 64 * 1024,
    "max_local_depth": 0xFFFFFFFF,
}
