"""模块级解析：魔数/版本、section 地图、顺序与重复、自定义段保真。"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from .leb128 import LebResult, decode_u
from .quantities import byte_extent, byte_offset

SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "data-count",
}
WASM_MAGIC = b"\x00asm"
WASM_VERSION = 1


@dataclass
class Diagnostic:
    kind: str
    message: str
    offset: Optional[int] = None
    end: Optional[int] = None
    context: str = ""
    related: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "message": self.message,
            "byte_range": {
                "start": byte_offset(self.offset).to_dict() if self.offset is not None else None,
                "end": byte_offset(self.end).to_dict() if self.end is not None else None,
            },
            "context": self.context,
            "related": self.related,
        }


@dataclass
class Section:
    ordinal: int
    section_id: int
    name: str
    id_offset: int
    size_leb: LebResult
    content_offset: int
    end_offset: int
    declared_size: Optional[int]
    custom_name: Optional[str]
    custom_name_raw: Optional[bytes]
    sha256: str

    def to_dict(self) -> dict:
        return {
            "ordinal": self.ordinal,
            "section_id": self.section_id,
            "name": self.name,
            "id_offset": byte_offset(self.id_offset).to_dict(),
            "size_leb": {
                "offset": self.size_leb.offset,
                "end": self.size_leb.end,
                "raw_hex": self.size_leb.raw.hex(),
                "value": byte_extent(self.size_leb.value, self.size_leb.raw.hex()).to_dict(),
                "status": self.size_leb.status,
                "diagnostic": self.size_leb.diagnostic,
            },
            "content_offset": byte_offset(self.content_offset).to_dict(),
            "end_offset": byte_offset(self.end_offset).to_dict(),
            "declared_size": byte_extent(self.declared_size).to_dict()
            if self.declared_size is not None else byte_extent(None).to_dict(),
            "custom_name": self.custom_name,
            "custom_name_raw_hex": self.custom_name_raw.hex() if self.custom_name_raw else None,
            "content_sha256": self.sha256,
        }


@dataclass
class ModuleMap:
    data: bytes
    sha256: str
    sections: list
    diagnostics: list
    header_ok: bool

    def to_dict(self) -> dict:
        return {
            "module_sha256": self.sha256,
            "module_size": byte_extent(len(self.data)).to_dict(),
            "header_ok": self.header_ok,
            "sections": [s.to_dict() for s in self.sections],
            "diagnostics": [d.to_dict() for d in self.diagnostics],
        }


def parse_module(data: bytes, leb_log: Optional[list] = None) -> ModuleMap:
    sha = hashlib.sha256(data).hexdigest()
    diagnostics = []
    header_ok = True
    if len(data) < 4 or data[:4] != WASM_MAGIC:
        header_ok = False
        diagnostics.append(Diagnostic(
            "bad-magic", "module does not begin with b'\\x00asm'",
            0, min(4, len(data)), "header"))
    if len(data) < 8:
        header_ok = False
        diagnostics.append(Diagnostic(
            "truncated-header", "header shorter than 8 bytes",
            len(data), len(data), "header"))
    elif data[:4] == WASM_MAGIC:
        version = int.from_bytes(data[4:8], "little")
        if version != WASM_VERSION:
            header_ok = False
            diagnostics.append(Diagnostic(
                "unsupported-version", f"unsupported wasm version {version}",
                4, 8, "header", {"declared_version": version}))

    sections = []
    if not header_ok:
        return ModuleMap(data, sha, sections, diagnostics, header_ok)

    offset = 8
    last_known_id = 0
    seen_ids = set()
    ordinal = 0
    while offset < len(data):
        ordinal += 1
        id_offset = offset
        sid = data[offset]
        offset += 1
        ctx = f"section[{ordinal}].size(id={sid})"
        size_leb = decode_u(data, offset, 32, ctx)
        if leb_log is not None:
            leb_log.append(size_leb)
        if size_leb.value is None:
            diagnostics.append(Diagnostic(
                f"leb-{size_leb.status}",
                f"section {ordinal} size LEB128: {size_leb.diagnostic}",
                size_leb.offset, size_leb.end, ctx))
            break
        offset = size_leb.end
        declared = size_leb.value
        content_offset = offset
        end = offset + declared

        if sid != 0:
            if sid > 12:
                diagnostics.append(Diagnostic(
                    "unknown-section-id",
                    f"unknown known-section id {sid}",
                    id_offset, id_offset + 1,
                    f"section[{ordinal}]", {"section_id": sid}))
            if sid in seen_ids:
                diagnostics.append(Diagnostic(
                    "section-duplicate",
                    f"section id {sid} ({SECTION_NAMES.get(sid, '?')}) appears more than once",
                    id_offset, id_offset + 1, f"section[{ordinal}]",
                    {"section_id": sid}))
            if sid < last_known_id:
                diagnostics.append(Diagnostic(
                    "section-out-of-order",
                    f"section id {sid} ({SECTION_NAMES.get(sid, '?')}) follows section id {last_known_id}",
                    id_offset, id_offset + 1, f"section[{ordinal}]",
                    {"section_id": sid, "previous_section_id": last_known_id}))
            if sid <= 12:
                seen_ids.add(sid)
                last_known_id = max(last_known_id, sid)

        truncated_section = end > len(data)
        if truncated_section:
            diagnostics.append(Diagnostic(
                "section-size-mismatch",
                f"section {ordinal} declares {declared} content bytes but only "
                f"{len(data) - content_offset} remain",
                size_leb.offset, size_leb.end, f"section[{ordinal}]",
                {"declared_size": declared}))
            end = len(data)

        custom_name = None
        custom_name_raw = None
        if sid == 0 and not truncated_section:
            name_leb = decode_u(data, content_offset, 32,
                                f"section[{ordinal}].custom-name-length")
            if leb_log is not None:
                leb_log.append(name_leb)
            if name_leb.decodable:
                name_start = name_leb.end
                name_end = name_start + name_leb.value
                if name_end <= end:
                    raw = data[name_start:name_end]
                    custom_name_raw = raw
                    try:
                        custom_name = raw.decode("utf-8")
                    except UnicodeDecodeError:
                        custom_name = None
                        diagnostics.append(Diagnostic(
                            "custom-name-not-utf8",
                            "custom section name is not valid UTF-8",
                            name_start, name_end, f"section[{ordinal}].custom-name"))
                else:
                    diagnostics.append(Diagnostic(
                        "custom-name-out-of-bounds",
                        "custom section name length exceeds section content",
                        name_leb.offset, name_leb.end, f"section[{ordinal}].custom-name"))
            else:
                diagnostics.append(Diagnostic(
                    f"leb-{name_leb.status}",
                    f"custom name length LEB128: {name_leb.diagnostic}",
                    name_leb.offset, name_leb.end, f"section[{ordinal}].custom-name"))

        section_name = SECTION_NAMES.get(sid, f"unknown-{sid}")
        content_sha = hashlib.sha256(data[content_offset:end]).hexdigest()
        sections.append(Section(
            ordinal=ordinal, section_id=sid, name=section_name,
            id_offset=id_offset, size_leb=size_leb,
            content_offset=content_offset, end_offset=end,
            declared_size=declared, custom_name=custom_name,
            custom_name_raw=custom_name_raw, sha256=content_sha))
        offset = end

    return ModuleMap(data, sha, sections, diagnostics, header_ok)


def coverage_map(module: ModuleMap) -> np.ndarray:
    """用 NumPy 把每个字节归属到 section ordinal（0=头部），用于 SVG 地图。"""
    cover = np.zeros(len(module.data), dtype=np.int32)
    for sec in module.sections:
        cover[sec.id_offset:sec.end_offset] = sec.ordinal
    return cover


def section_boundaries(module: ModuleMap) -> list:
    cover = coverage_map(module)
    if cover.size == 0:
        return []
    change = np.flatnonzero(np.diff(cover)) + 1
    bounds = [0] + change.tolist() + [cover.size]
    return [{"ordinal": int(cover[a]), "start": int(a), "end": int(b)}
            for a, b in zip(bounds[:-1], bounds[1:])]
