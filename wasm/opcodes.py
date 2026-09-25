"""Opcode -> proposal capability table.

Known-but-disabled opcodes are reported as E030_CAPABILITY_MISSING with the
exact enabling proposal, never downgraded to E031_UNKNOWN_OPCODE.  Only bytes
unknown under every known proposal are unknown bytes.
"""
from __future__ import annotations

# opcode -> (mnemonic, proposal name or None for core MVP)
TABLE: dict[int, tuple[str, str | None]] = {
    0x00: ("unreachable", None),
    0x01: ("nop", None),
    0x02: ("block", None),
    0x03: ("loop", None),
    0x04: ("if", None),
    0x05: ("else", None),
    0x0B: ("end", None),
    0x0C: ("br", None),
    0x0D: ("br_if", None),
    0x0F: ("return", None),
    0x10: ("call", None),
    0x12: ("return_call", "tail-call"),
    0x1A: ("drop", None),
    0x1B: ("select", None),
    0x20: ("local.get", None),
    0x21: ("local.set", None),
    0x22: ("local.tee", None),
    0x28: ("i32.load", None),
    0x36: ("i32.store", None),
    0x41: ("i32.const", None),
    0x45: ("i32.eqz", None),
    0x46: ("i32.eq", None),
    0x6A: ("i32.add", None),
    0xD0: ("ref.null", "reference-types"),
    0xD2: ("ref.func", "reference-types"),
    0xFC: ("bulk-memory-prefix", "bulk-memory-operations"),
    0xFD: ("simd-prefix", "simd"),
}

BULK_SUB: dict[int, str] = {0x0A: "memory.copy", 0x0B: "memory.fill"}


def lookup(opcode: int) -> tuple[str, str | None]:
    return TABLE.get(opcode, (f"0x{opcode:02x}", None))


def is_known(opcode: int) -> bool:
    return opcode in TABLE
