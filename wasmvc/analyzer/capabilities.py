"""Proposal capabilities and opcode provenance registry.

Every decoded byte is classified into one provenance class:

* ``core``      - WebAssembly 1.0 MVP;
* ``gated``     - assigned by exactly one (proposal, feature flag) pair;
* ``candidate`` - cannot currently be pinned to one proposal; every legal
                  explanation is retained as a candidate (first-class data);
* ``unknown``   - the MVP assigned no meaning and no known proposal explains it.

Domain rule enforced here:

    未启用 proposal 的 opcode -> CAPABILITY_MISSING（带具体 feature/proposal），
    而不是 UNKNOWN_BYTE。

Only genuinely unassigned bytes (e.g. 0xC0..0xCF, the 0xFE threads prefix when
threads is not an enabled registry proposal) become ``UNKNOWN_BYTE``.
"""
from __future__ import annotations

from dataclasses import dataclass

PROPOSALS: dict[str, dict] = {
    "sign_extension": {"name": "Sign-extension operators", "version": "2.0"},
    "multivalue": {"name": "Multi-value", "version": "2.0"},
    "reference_types": {"name": "Reference types", "version": "2.0"},
    "bulk_memory": {"name": "Bulk memory operations", "version": "2.0"},
    "simd": {"name": "Fixed-width SIMD", "version": "2.0"},
    "multi_memory": {"name": "Multiple memories", "version": "draft"},
    "gc": {"name": "Garbage collection (typed references)", "version": "draft"},
}

DEFAULT_FEATURES = {key: True for key in PROPOSALS}
DEFAULT_FEATURES["multi_memory"] = False
DEFAULT_FEATURES["gc"] = False


@dataclass(frozen=True)
class OpInfo:
    cls: str  # core | gated | candidate | unknown
    feature: str | None = None
    proposal: str | None = None
    candidates: tuple[str, ...] = ()


def g(feature: str) -> OpInfo:
    return OpInfo("gated", feature=feature, proposal=PROPOSALS[feature]["name"])


def cand(*features: str) -> OpInfo:
    return OpInfo("candidate", candidates=tuple(features))


CORE = OpInfo("core")
UNKNOWN = OpInfo("unknown")

# value type bytes -> (stack type name, enabling feature or None for MVP)
VALTYPE = {
    0x7F: ("i32", None),
    0x7E: ("i64", None),
    0x7D: ("f32", None),
    0x7C: ("f64", None),
    0x7B: ("v128", "simd"),
    0x70: ("funcref", "reference_types"),
    0x6F: ("externref", "reference_types"),
    0x6E: ("anyref", "gc"),
    0x6D: ("eqref", "gc"),
    0x6C: ("structref", "gc"),
    0x6B: ("arrayref", "gc"),
}

SINGLE: dict[int, OpInfo] = {}

# control / parametric
for op in (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
           0x10, 0x11, 0x1A, 0x1B):
    SINGLE[op] = CORE
SINGLE[0x1C] = g("reference_types")  # select t*

# variable
for op in (0x20, 0x21, 0x22, 0x23, 0x24):
    SINGLE[op] = CORE
SINGLE[0x25] = g("reference_types")  # table.get
SINGLE[0x26] = g("reference_types")  # table.set

# memory MVP
for op in range(0x28, 0x41):
    SINGLE[op] = CORE

# constants and the full MVP numeric opcode surface
for op in range(0x41, 0xC0):
    SINGLE[op] = CORE

# 0xC0..0xCF are reserved/unused -> genuinely unknown bytes.
# reference types
SINGLE[0xD0] = g("reference_types")  # ref.null
SINGLE[0xD1] = g("reference_types")  # ref.is_null
SINGLE[0xD2] = g("reference_types")  # ref.func

# 0xFC prefix sub-opcodes: sign ext (0..7), bulk memory (8..11),
# reference types table/elem ops (12..17).
PREFIX_FC = {
    **{sub: g("sign_extension") for sub in range(0, 8)},
    8: g("bulk_memory"),     # memory.init
    9: g("bulk_memory"),     # data.drop
    10: g("bulk_memory"),    # memory.copy
    11: g("bulk_memory"),    # memory.fill
    12: g("reference_types"),  # table.init
    13: g("reference_types"),  # elem.drop
    14: g("reference_types"),  # table.copy
    15: g("reference_types"),  # table.grow
    16: g("reference_types"),  # table.size
    17: g("reference_types"),  # table.fill
}

# proposals that legitimately share the 0xFC prefix
FC_PREFIX_CANDIDATES = ("sign_extension", "bulk_memory", "reference_types")
FD_PREFIX = "simd"


def classify_single(opcode: int) -> OpInfo:
    return SINGLE.get(opcode, UNKNOWN)


def classify_fc(sub: int | None, sub_decodable: bool, features: dict[str, bool]) -> OpInfo:
    # If the sub-opcode itself cannot be decoded uniquely, the prefix is shared
    # by several proposals: retain every legal explanation.
    if not sub_decodable or sub is None:
        live = [f for f in FC_PREFIX_CANDIDATES if not features.get(f, False)]
        if not live:
            return OpInfo("unknown")
        if len(live) == 1:
            return g(live[0])
        return cand(*live)
    info = PREFIX_FC.get(sub, UNKNOWN)
    if info.cls == "gated" and features.get(info.feature, False):
        return CORE
    return info


def classify_fd(sub: int | None, sub_decodable: bool, features: dict[str, bool]) -> OpInfo:
    if not sub_decodable or sub is None:
        return UNKNOWN
    if features.get(FD_PREFIX, False):
        return CORE
    return g(FD_PREFIX)
