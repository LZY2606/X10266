"""WebAssembly value/function types and the proposal capability catalogue."""

from __future__ import annotations

from dataclasses import dataclass

# Value type encodings (including reference types, which are gated).
VALUE_TYPES: dict[int, str] = {
    0x7F: "i32",
    0x7E: "i64",
    0x7D: "f32",
    0x7C: "f64",
    0x7B: "v128",
    0x70: "funcref",
    0x6F: "externref",
}

# Value types that only exist when a proposal is enabled.
VALUE_TYPE_PROPOSALS: dict[int, str] = {
    0x7B: "simd",
    0x70: "reference-types",
    0x6F: "reference-types",
}

FUNC_TYPE_MARKER = 0x60


@dataclass(frozen=True)
class FuncType:
    params: tuple[str, ...]
    results: tuple[str, ...]

    def pretty(self) -> str:
        return f"({','.join(self.params)}) -> ({','.join(self.results)})"

    def as_dict(self) -> dict:
        return {"params": list(self.params), "results": list(self.results)}


# Every proposal the capability layer knows about. "multivalue" is special:
# it is needed both for multi-result function/block types and for block params.
ALL_PROPOSALS: tuple[str, ...] = (
    "multivalue",
    "reference-types",
    "bulk-memory",
    "simd",
    "sign-extension",
    "nontrapping-float-to-int",
    "tail-call",
    "gc",
    "threads",
    "exceptions",
)

DEFAULT_ENABLED: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Capabilities:
    enabled: frozenset[str]

    @classmethod
    def from_list(cls, names) -> "Capabilities":
        enabled = frozenset(n for n in names if n in ALL_PROPOSALS)
        return cls(enabled)

    def has(self, name: str) -> bool:
        return name in self.enabled

    def toggle(self, name: str) -> "Capabilities":
        if name not in ALL_PROPOSALS:
            return self
        if name in self.enabled:
            return Capabilities(self.enabled - {name})
        return Capabilities(self.enabled | {name})

    def fingerprint(self) -> str:
        import hashlib

        joined = ",".join(sorted(self.enabled))
        return hashlib.sha256(f"proposals:{joined}".encode()).hexdigest()[:16]

    def as_list(self) -> list[str]:
        return sorted(self.enabled)

    def as_catalogue(self) -> list[dict]:
        return [{"name": n, "enabled": n in self.enabled} for n in ALL_PROPOSALS]
