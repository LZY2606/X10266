"""Resilient Wasm binary parser.

Preserves, for every parsed artifact: original byte ranges, section
id/size, raw LEB128 encodings and custom-section bytes. Values that
cannot be converted (e.g. an overflowing size LEB) stay at their
original position with a diagnostic instead of being dropped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .leb128 import (LebValue, decode_unsigned,
                     ERR_NON_CANONICAL, ERR_OVERFLOW, ERR_TRUNCATED)

MAGIC = b"\x00asm\x01\x00\x00\x00"

SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "data-count",
}

VALTYPES = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64",
            0x70: "funcref", 0x6F: "externref", 0x7B: "v128"}

IMPORT_KINDS = {0: "func", 1: "table", 2: "memory", 3: "global"}


def diagnostic(rule: str, cls: str, start: int, end: int, message: str,
               severity: str = "error", candidates=None, details=None) -> dict:
    """A parse/validation finding. Byte ranges always carry their
    coordinate basis (module file offset) and unit (byte)."""
    return {
        "rule": rule,
        "cls": cls,
        "severity": severity,
        "byte_start": start,
        "byte_end": end,
        "unit": "byte",
        "basis": "module_file_offset",
        "message": message,
        "candidates": candidates or [],
        "details": details or {},
    }


@dataclass
class Section:
    order: int
    sid: int
    name: str
    size_leb: LebValue
    start: int
    payload_start: int
    end: int
    raw: bytes
    custom_name: Optional[str] = None


@dataclass
class FuncType:
    idx: int
    params: list
    results: list
    start: int
    end: int


@dataclass
class ImportEntry:
    idx: int
    module: str
    name: str
    kind: str
    type_idx: Optional[int]
    start: int
    end: int


@dataclass
class FuncDecl:
    idx: int
    type_idx: Optional[int]
    start: int
    end: int


@dataclass
class CodeBody:
    idx: int
    locals: list
    body_start: int
    body_end: int
    expr_start: int
    size_leb: LebValue


@dataclass
class GlobalDecl:
    idx: int
    valtype: str
    mutable: bool
    imported: bool
    start: int
    end: int


@dataclass
class ParsedModule:
    data: bytes
    sections: list = field(default_factory=list)
    types: list = field(default_factory=list)
    imports: list = field(default_factory=list)
    funcs: list = field(default_factory=list)
    codes: list = field(default_factory=list)
    globals_: list = field(default_factory=list)
    diagnostics: list = field(default_factory=list)
    fatal: bool = False

    def section_raws(self) -> bytes:
        return MAGIC + b"".join(s.raw for s in self.sections)


def _read_name(data: bytes, pos: int, diags: list):
    length = decode_unsigned(data, pos, 32)
    if length.error:
        diags.append(_leb_diag("parse.name", length))
        return None, length.end
    start = length.end
    end = start + (length.value or 0)
    if end > len(data):
        diags.append(diagnostic("parse.name", "TruncatedLEB", start, len(data),
                                "name bytes run past end of module"))
        return None, len(data)
    try:
        return data[start:end].decode("utf-8"), end
    except UnicodeDecodeError:
        diags.append(diagnostic("parse.name", "InvalidUTF8", start, end,
                                "name is not valid UTF-8; raw bytes kept"))
        return None, end


def _leb_diag(rule: str, lv: LebValue) -> dict:
    cls = {ERR_NON_CANONICAL: "NonCanonicalLEB",
           ERR_OVERFLOW: "NumericOverflow",
           ERR_TRUNCATED: "TruncatedLEB"}[lv.error]
    return diagnostic(rule, cls, lv.start, lv.end, lv.diagnostic or lv.error)


def _parse_limits(data, pos, diags):
    if pos >= len(data):
        return pos
    flags = data[pos]
    pos += 1
    lo = decode_unsigned(data, pos, 32)
    if lo.error:
        diags.append(_leb_diag("parse.limits", lo))
    pos = lo.end
    if flags & 0x01:
        hi = decode_unsigned(data, pos, 32)
        if hi.error:
            diags.append(_leb_diag("parse.limits", hi))
        pos = hi.end
    return pos


def parse_module(data: bytes) -> ParsedModule:
    pm = ParsedModule(data=data)
    diags = pm.diagnostics
    if len(data) < 8 or data[:8] != MAGIC:
        diags.append(diagnostic("parse.header", "BadMagic", 0,
                                min(8, len(data)),
                                "missing \\0asm magic or version 1 header"))
        pm.fatal = True
        return pm
    pos = 8
    order = 0
    while pos < len(data):
        start = pos
        sid = data[pos]
        pos += 1
        size_leb = decode_unsigned(data, pos, 32)
        pos = size_leb.end
        if size_leb.error:
            diags.append(_leb_diag("parse.section.size", size_leb))
        if size_leb.value is None:
            pm.sections.append(Section(order, sid, SECTION_NAMES.get(sid, "unknown"),
                                       size_leb, start, pos, len(data),
                                       data[start:len(data)]))
            diags.append(diagnostic(
                "parse.section.size", "SectionSizeUnknown", start, len(data),
                "section size could not be decoded; remaining bytes kept raw"))
            pm.fatal = True
            break
        end = pos + size_leb.value
        if end > len(data):
            diags.append(diagnostic(
                "parse.section.size", "SectionSizeOutOfBounds", start, len(data),
                f"declared size {size_leb.value} overruns module "
                f"({len(data) - pos} bytes available)"))
            end = len(data)
            pm.fatal = True
        raw = data[start:end]
        custom_name = None
        if sid == 0:
            custom_name, _ = _read_name(data, pos, diags)
        pm.sections.append(Section(order, sid, SECTION_NAMES.get(sid, "unknown"),
                                   size_leb, start, pos, end, raw, custom_name))
        pos = end
        order += 1
        if pm.fatal:
            break
    for sec in pm.sections:
        try:
            _parse_section_payload(pm, sec)
        except Exception as exc:
            diags.append(diagnostic(
                "parse.payload", "PayloadParseError", sec.payload_start, sec.end,
                f"payload of section {sec.name} kept raw: {exc}"))
    return pm


def _parse_section_payload(pm: ParsedModule, sec: Section) -> None:
    data = pm.data
    diags = pm.diagnostics
    base = sec.payload_start

    def u32(p):
        lv = decode_unsigned(data, p, 32)
        if lv.error:
            diags.append(_leb_diag(f"parse.{sec.name}", lv))
        return lv

    if sec.sid == 1:
        count = u32(base)
        pos = count.end
        for _ in range(count.value or 0):
            tstart = pos
            if pos >= sec.end or data[pos] != 0x60:
                diags.append(diagnostic("parse.type", "BadTypeForm", pos, pos + 1,
                                        "expected 0x60 func type form"))
                return
            pos += 1
            params, pos = _valtype_vec(data, pos, diags)
            results, pos = _valtype_vec(data, pos, diags)
            pm.types.append(FuncType(len(pm.types), params, results, tstart, pos))
    elif sec.sid == 2:
        count = u32(base)
        pos = count.end
        for _ in range(count.value or 0):
            istart = pos
            mod, pos = _read_name(data, pos, diags)
            nm, pos = _read_name(data, pos, diags)
            if pos >= sec.end:
                return
            kind_b = data[pos]
            pos += 1
            kind = IMPORT_KINDS.get(kind_b, "unknown")
            type_idx = None
            if kind == "func":
                tidx = u32(pos)
                type_idx = tidx.value
                pos = tidx.end
            elif kind == "table":
                pos += 1
                pos = _parse_limits(data, pos, diags)
            elif kind == "memory":
                pos = _parse_limits(data, pos, diags)
            elif kind == "global":
                vt = data[pos] if pos < sec.end else 0
                pos += 2
                pm.globals_.append(GlobalDecl(
                    len(pm.globals_), VALTYPES.get(vt, "unknown"),
                    bool(data[pos - 1] & 1), True, istart, pos))
            else:
                diags.append(diagnostic("parse.import", "UnsupportedImportKind",
                                        istart, pos,
                                        f"import kind byte {kind_b} kept raw"))
                return
            pm.imports.append(ImportEntry(len(pm.imports), mod or "", nm or "",
                                          kind, type_idx, istart, pos))
    elif sec.sid == 3:
        count = u32(base)
        pos = count.end
        for _ in range(count.value or 0):
            tidx = u32(pos)
            pm.funcs.append(FuncDecl(len(pm.funcs), tidx.value, tidx.start, tidx.end))
            pos = tidx.end
    elif sec.sid == 6:
        count = u32(base)
        pos = count.end
        for _ in range(count.value or 0):
            gstart = pos
            vt = data[pos] if pos < sec.end else 0
            mut = bool(data[pos + 1] & 1) if pos + 1 < sec.end else False
            pos += 2
            while pos < sec.end and data[pos] != 0x0B:
                pos += 1
            pos = min(pos + 1, sec.end)
            pm.globals_.append(GlobalDecl(len(pm.globals_),
                                          VALTYPES.get(vt, "unknown"), mut,
                                          False, gstart, pos))
    elif sec.sid == 10:
        count = u32(base)
        pos = count.end
        for _ in range(count.value or 0):
            size = u32(pos)
            pos = size.end
            body_start = pos
            body_end = body_start + (size.value or 0)
            if body_end > sec.end:
                diags.append(diagnostic("parse.code", "SectionSizeOutOfBounds",
                                        body_start, sec.end,
                                        "code body overruns section"))
                body_end = sec.end
            locals_, expr_start = _parse_locals(data, body_start, body_end, diags)
            pm.codes.append(CodeBody(len(pm.codes), locals_, body_start,
                                     body_end, expr_start, size))
            pos = body_end


def _valtype_vec(data, pos, diags):
    count = decode_unsigned(data, pos, 32)
    if count.error:
        diags.append(_leb_diag("parse.valtypes", count))
    out = []
    p = count.end
    for _ in range(count.value or 0):
        if p >= len(data):
            break
        out.append(VALTYPES.get(data[p], f"unknown(0x{data[p]:02x})"))
        p += 1
    return out, p


def _parse_locals(data, pos, end, diags):
    count = decode_unsigned(data, pos, 32)
    if count.error:
        diags.append(_leb_diag("parse.code.locals", count))
    p = count.end
    locals_ = []
    for _ in range(count.value or 0):
        n = decode_unsigned(data, p, 32)
        if n.error:
            diags.append(_leb_diag("parse.code.locals", n))
        p = n.end
        if p >= end:
            break
        vt = VALTYPES.get(data[p], "unknown")
        p += 1
        locals_.extend([vt] * (n.value or 0))
    return locals_, p
