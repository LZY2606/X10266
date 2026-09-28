from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import numpy as np

from .leb import LEBResult, decode_uleb128

KNOWN_SECTION_NAMES = {
    1: "type", 2: "import", 3: "function", 4: "table", 5: "memory",
    6: "global", 7: "export", 8: "start", 9: "element", 10: "code",
    11: "data", 12: "datacount",
}
VALUE_TYPES = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64"}


@dataclass
class Cursor:
    data: bytes
    pos: int = 0

    def leb(self, label: str, max_value: int = 0xFFFFFFFF) -> LEBResult:
        result = decode_uleb128(self.data, self.pos, max_value=max_value)
        self.pos = result.end
        return result

    def byte(self) -> int | None:
        if self.pos >= len(self.data):
            return None
        value = self.data[self.pos]
        self.pos += 1
        return value


def sha256_text(value: Any) -> str:
    import json
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def parameter_fingerprint(proposals: set[str], host_imports: list[dict[str, Any]]) -> str:
    return sha256_text({"proposals": sorted(proposals), "host_imports": host_imports})


def _node(
    stable_id: str,
    kind: str,
    title: str,
    status: str,
    source_refs: list[dict[str, Any]],
    start: int | None = None,
    end: int | None = None,
    value: Any = None,
    unit: str | None = None,
    candidates: list[dict[str, Any]] | None = None,
    rejection_reasons: list[dict[str, Any]] | None = None,
    evidence_codes: list[str] | None = None,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    node: dict[str, Any] = {
        "stable_id": stable_id,
        "kind": kind,
        "title": title,
        "status": status,
        "byte_range": None if start is None else {"start": start, "end": end, "unit": "byte", "base": "zero-based inclusive"},
        "value": value,
        "unit": unit,
        "source_refs": source_refs,
        "candidates": candidates or [],
        "rejection_reasons": rejection_reasons or [],
        "evidence_codes": evidence_codes or [],
        "detail": detail or {},
    }
    return node


def reason(code: str, message: str, start: int, end: int | None = None) -> dict[str, Any]:
    return {
        "code": code,
        "message": message,
        "minimal_byte_range": {"start": start, "end": end if end is not None else start, "unit": "byte"},
    }


def scan_sections(data: bytes) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    sections: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    pos = 8
    last_known = 0
    seen: set[int] = set()
    if data[:4] != b"\x00asm":
        events.append({"code": "magic_mismatch", "start": 0, "end": min(3, len(data) - 1), "message": "module does not begin with \\0asm"})
    if len(data) >= 8 and data[4:8] != b"\x01\x00\x00\x00":
        events.append({"code": "unsupported_version", "start": 4, "end": 7, "message": "only WebAssembly version 1 is enabled"})
    while pos < len(data):
        section_start = pos
        sid = data[pos]
        id_end = pos + 1
        size_result = decode_uleb128(data, pos + 1)
        if size_result.status != "accepted":
            events.append({"code": size_result.code, "start": size_result.start, "end": max(size_result.start, size_result.end - 1), "message": "section size LEB128 is invalid"})
            break
        size = size_result.value
        payload_start = size_result.end
        payload_end = payload_start + (size or 0)
        if payload_end > len(data):
            events.append({"code": "section_payload_truncated", "start": section_start, "end": len(data) - 1, "message": "declared section size exceeds module bytes"})
            break
        occurrence = sum(1 for item in sections if item["section_id"] == sid)
        stable_id = "sec.custom" if sid == 0 else f"sec.{KNOWN_SECTION_NAMES.get(sid, f'unknown{sid}')}"
        if sid == 0:
            stable_id = f"sec.custom#{occurrence}"
        record = {
            "stable_id": stable_id,
            "section_id": sid,
            "name": "custom" if sid == 0 else KNOWN_SECTION_NAMES.get(sid, "unknown"),
            "start": section_start,
            "id_end": id_end - 1,
            "size_start": size_result.start,
            "size_end": size_result.end - 1,
            "payload_start": payload_start,
            "payload_end": payload_end - 1,
            "size": size,
            "occurrence": occurrence,
            "size_leb": size_result.to_event(),
        }
        if sid == 0:
            name_result, custom_name, custom_payload_start = _read_custom_name(data, payload_start, payload_end)
            record["custom_name"] = custom_name
            record["custom_payload_start"] = custom_payload_start
            record["name_leb"] = name_result.to_event() if name_result else None
        sections.append(record)
        if sid != 0:
            if sid in seen:
                events.append({"code": "duplicate_known_section", "start": section_start, "end": id_end - 1, "section_id": sid, "message": f"section {sid} is repeated"})
            seen.add(sid)
            if sid < last_known:
                events.append({"code": "section_out_of_order", "start": section_start, "end": id_end - 1, "section_id": sid, "after": last_known, "message": f"section {sid} follows section {last_known}"})
            last_known = max(last_known, sid)
        pos = payload_end
    return sections, events


def _read_custom_name(data: bytes, start: int, end: int) -> tuple[LEBResult | None, str | None, int | None]:
    result = decode_uleb128(data, start)
    if result.status != "accepted" or result.end + (result.value or 0) > end:
        return result, None, None
    try:
        name = data[result.end:result.end + result.value].decode("utf-8")
    except UnicodeDecodeError:
        name = None
    return result, name, result.end + (result.value or 0)


def _take_count(cursor: Cursor, label: str, rejection: list[dict[str, Any]]) -> int | None:
    result = cursor.leb(label)
    if result.status != "accepted":
        rejection.append(reason(result.code, f"{label} count has invalid LEB128", result.start, result.end - 1))
        return None
    return result.value
