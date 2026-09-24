"""WebAssembly binary structure parser.

Produces a section map with exact byte ranges, keeps the raw LEB128 encodings
of every size field, detects duplicate / out-of-order known sections, and
preserves custom section payloads byte-for-byte (fidelity is checkable against
the stored raw bytes at any later time).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .leb128 import Leb, LebError, decode_u32

SECTION_NAMES = {
    0: "custom",
    1: "type",
    2: "import",
    3: "function",
    4: "table",
    5: "memory",
    6: "global",
    7: "export",
    8: "start",
    9: "element",
    10: "code",
    11: "data",
    12: "datacount",
}

# Known (non-custom) sections must appear at most once and in ascending id order.
MAX_KNOWN_SECTION_ID = 12


@dataclass
class Diagnostic:
    code: str
    message: str
    span: tuple[int, int]
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "span": list(self.span),
            "data": self.data,
        }


@dataclass
class Section:
    sec_id: int
    name: str
    order: int  # appearance order in the file
    start: int  # offset of the id byte
    size_leb: Leb
    content_start: int
    end: int  # exclusive
    custom_name: str | None = None
    custom_name_leb: Leb | None = None

    @property
    def content(self) -> tuple[int, int]:
        return (self.content_start, self.end)

    def to_dict(self) -> dict:
        return {
            "id": self.sec_id,
            "name": self.name,
            "order": self.order,
            "span": [self.start, self.end],
            "declared_size": self.size_leb.value,
            "size_leb": self.size_leb.to_dict(),
            "content_span": [self.content_start, self.end],
            "custom_name": self.custom_name,
        }


@dataclass
class ParseResult:
    ok: bool
    sections: list[Section]
    diagnostics: list[Diagnostic]
    total_len: int
    trailing_bytes: int = 0

    def section_dicts(self) -> list[dict]:
        return [s.to_dict() for s in self.sections]


def parse_module(data: bytes) -> ParseResult:
    diags: list[Diagnostic] = []
    sections: list[Section] = []
    ok = True

    if len(data) < 8 or data[:4] != b"\x00asm":
        diags.append(Diagnostic("magic.mismatch", "bad magic header", (0, min(4, len(data)))))
        return ParseResult(False, sections, diags, len(data))
    if data[4:8] != b"\x01\x00\x00\x00":
        diags.append(
            Diagnostic("version.unsupported", "unsupported binary version", (4, 8),
                       {"raw_hex": data[4:8].hex()})
        )
        ok = False

    pos = 8
    order = 0
    last_known_id = 0
    seen_known: set[int] = set()

    while pos < len(data):
        sec_start = pos
        sec_id = data[pos]
        pos += 1
        try:
            size_leb = decode_u32(data, pos)
        except LebError as exc:
            diags.append(Diagnostic(exc.code, str(exc), exc.span))
            ok = False
            break
        pos = size_leb.end
        if not size_leb.canonical:
            diags.append(
                Diagnostic(
                    "leb.noncanonical",
                    "section size uses a non-canonical (overlong) LEB128 encoding",
                    (size_leb.start, size_leb.end),
                    {"raw_hex": size_leb.raw.hex(), "value": size_leb.value},
                )
            )
            ok = False
        content_start = pos
        end = pos + size_leb.value
        if end > len(data):
            diags.append(
                Diagnostic("section.truncated", "section body extends past end of file",
                           (content_start, len(data)))
            )
            ok = False
            end = len(data)

        name = SECTION_NAMES.get(sec_id)
        if name is None:
            diags.append(
                Diagnostic("section.unknown_id", f"unknown section id {sec_id}",
                           (sec_start, sec_start + 1), {"id": sec_id})
            )
            ok = False
            name = f"unknown-{sec_id}"

        custom_name = None
        custom_name_leb = None
        if sec_id == 0:
            name = "custom"
            try:
                name_leb = decode_u32(data, content_start)
                custom_name_leb = name_leb
                if not name_leb.canonical:
                    diags.append(Diagnostic("leb.noncanonical",
                                            "custom section name length is non-canonical",
                                            (name_leb.start, name_leb.end),
                                            {"raw_hex": name_leb.raw.hex()}))
                    ok = False
                nend = name_leb.end + name_leb.value
                if nend > end:
                    diags.append(Diagnostic("custom.name_truncated",
                                            "custom section name overruns section",
                                            (name_leb.end, end)))
                    ok = False
                else:
                    custom_name = data[name_leb.end:nend].decode("utf-8", "replace")
            except LebError as exc:
                diags.append(Diagnostic(exc.code, str(exc), exc.span))
                ok = False
        else:
            if sec_id in seen_known:
                diags.append(
                    Diagnostic("section.duplicate",
                               f"section '{SECTION_NAMES[sec_id]}' appears more than once",
                               (sec_start, sec_start + 1),
                               {"section": SECTION_NAMES[sec_id], "first_order": order})
                )
                ok = False
            if sec_id < last_known_id:
                diags.append(
                    Diagnostic("section.out_of_order",
                               f"section '{SECTION_NAMES[sec_id]}' appears after a later section",
                               (sec_start, sec_start + 1),
                               {"section": SECTION_NAMES[sec_id], "after_id": last_known_id})
                )
                ok = False
            seen_known.add(sec_id)
            last_known_id = max(last_known_id, sec_id)

        sections.append(
            Section(sec_id, name, order, sec_start, size_leb, content_start, end,
                    custom_name, custom_name_leb)
        )
        order += 1
        pos = end

    trailing = len(data) - pos if pos < len(data) else 0
    if trailing:
        diags.append(Diagnostic("module.trailing_bytes",
                                f"{trailing} trailing bytes after last section",
                                (pos, len(data))))
        ok = False
    return ParseResult(ok, sections, diags, len(data), trailing)


def custom_section_bytes(data: bytes, section: Section) -> bytes:
    """Raw payload of a custom section, byte-for-byte as imported."""
    return data[section.content_start:section.end]
