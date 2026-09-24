"""Proposal / capability model.

An opcode is *recognised* (we know its intended signature) independently of
whether the feature is enabled. A recognised-but-disabled opcode yields a
CAPABILITY_MISSING finding; a truly unknown byte yields UNKNOWN_OPCODE.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass(frozen=True)
class Proposal:
    key: str
    title: str
    enabled_by_default: bool = False


REGISTRY: Dict[str, Proposal] = {
    "mvp": Proposal("mvp", "WebAssembly 1.0 (MVP)", True),
    "multi_value": Proposal("multi_value", "Multi-value"),
    "sign_extension": Proposal("sign_extension", "Sign-extension operators"),
    "reference_types": Proposal("reference_types", "Reference types"),
    "saturating_float_to_int": Proposal(
        "saturating_float_to_int", "Non-trapping float-to-int conversions"),
    "bulk_memory": Proposal("bulk_memory", "Bulk memory operations"),
    "simd": Proposal("simd", "Fixed-width SIMD"),
    "multi_memory": Proposal("multi_memory", "Multiple memories"),
}


def default_set() -> Set[str]:
    return {k for k, p in REGISTRY.items() if p.enabled_by_default}


def all_set() -> Set[str]:
    return set(REGISTRY.keys())


@dataclass
class CapabilitySet:
    enabled: Set[str] = field(default_factory=default_set)

    def has(self, key: str) -> bool:
        return key in self.enabled

    def enable(self, key: str) -> None:
        if key in REGISTRY:
            self.enabled.add(key)

    def disable(self, key: str) -> None:
        self.enabled.discard(key)

    def fingerprint(self) -> List[str]:
        return sorted(self.enabled)


# Opcode -> proposal that introduces it. Prefix opcodes use (prefix, subopcode).
OPCODE_PROPOSAL: Dict[object, str] = {}


def gate(opcode: object) -> str:
    return OPCODE_PROPOSAL.get(opcode, "mvp")
