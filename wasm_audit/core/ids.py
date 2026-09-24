"""Stable identities, fingerprints and content hashing.

Every displayed value carries a stable identity. Identities are derived from
content + provenance so that an export -> wipe -> import round trip preserves
them byte for byte.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fingerprint(parts: Iterable[Any]) -> str:
    """Parameter fingerprint: stable hash of canonicalised inputs."""
    joined = canonical_json(list(parts))
    return "fp:" + hashlib.sha256(joined.encode("utf-8")).hexdigest()[:24]


def content_id(kind: str, payload: Any) -> str:
    """Deterministic stable id for a derived object (kind + content + provenance)."""
    raw = canonical_json({"kind": kind, "payload": payload})
    return kind + "_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def short(data: bytes, n: int = 12) -> str:
    return hashlib.sha256(data).hexdigest()[:n]
