"""Wasm binary parser: section map, index spaces, byte-range fidelity.

Every parsed item keeps its original byte range and raw encoding so the
review UI can read back the *minimal failing byte range* and custom sections
round-trip byte-for-byte.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .leb128 import LebError, read_uleb, read_sleb

WASM_MAGIC = b"\x00asm\x01\x00\x00\x00"

SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "data_count",
}
# Highest id the validator understands; ids above are malformed per spec.
MAX_SECTION_ID = 12

VALTYPES = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64",
            0x7B: "v128", 0x70: "funcref", 0x6F: "externref"}


@dataclass
class Section:
    ordinal: int
    section_id: int
    name: str
    id_offset: int
    size_leb: dict           # LebValue.to_dict() of the size field
    payload_range: tuple[int, int]
    total_range: tuple[int, int]
    raw: bytes

    def to_dict(self) -> dict:
        return {
            "ordinal": self.ordinal,
            "section_id": self.section_id,
            "name": self.name,
            "id_offset": self.id_offset,
            "size_leb": self.size_leb,
            "payload_range": list(self.payload_range),
            "total_range": list(self.total_range),
            "raw_hex": self.raw.hex(),
        }


@dataclass
class FuncType:
    index: int
    params: list
    results: list
    byte_range: tuple[int, int]

    def to_dict(self):
        return {"index": self.index, "params": self.params,
                "results": self.results, "byte_range": list(self.byte_range)}


@dataclass
class Import:
    index: int
    module: str
    name: str
    kind: str
    type_index: int | None
    byte_range: tuple[int, int]

    def to_dict(self):
        return {"index": self.index, "module": self.module, "name": self.name,
                "kind": self.kind, "type_index": self.type_index,
                "byte_range": list(self.byte_range)}


@dataclass
class FunctionBody:
    func_index: int          # index in the *function* index space (imports offset)
    type_index: int
    body_range: tuple[int, int]
    code_offset: int         # offset of locals vec
    raw: bytes

    def to_dict(self):
        return {"func_index": self.func_index, "type_index": self.type_index,
                "body_range": list(self.body_range), "code_offset": self.code_offset,
                "raw_hex": self.raw.hex()}


@dataclass
class ParsedModule:
    sections: list = field(default_factory=list)
    types: list = field(default_factory=list)          # list[FuncType]
    imports: list = field(default_factory=list)        # list[Import]
    func_type_indices: list = field(default_factory=list)  # function section
    bodies: list = field(default_factory=list)         # list[FunctionBody]
    custom_sections: list = field(default_factory=list)    # list[dict name+raw]
    diagnostics: list = field(default_factory=list)    # structural findings
    leb_encodings: list = field(default_factory=list)  # every LEB seen, w/ ranges

    def to_dict(self):
        return {
            "sections": [s.to_dict() for s in self.sections],
            "types": [t.to_dict() for t in self.types],
            "imports": [i.to_dict() for i in self.imports],
            "func_type_indices": self.func_type_indices,
            "bodies": [b.to_dict() for b in self.bodies],
            "custom_sections": self.custom_sections,
            "diagnostics": self.diagnostics,
            "leb_encodings": self.leb_encodings,
        }


def _diag(kind: str, offset: int, byte_range, detail: str, **extra) -> dict:
    d = {"kind": kind, "offset": offset,
         "byte_range": [byte_range[0], byte_range[1]], "detail": detail}
    d.update(extra)
    return d


def parse_module(data: bytes, proposals: set[str] | None = None) -> ParsedModule:
    proposals = proposals or set()
    mod = ParsedModule()
    if data[:4] != b"\x00asm":
        mod.diagnostics.append(_diag("bad_magic", 0, (0, min(4, len(data))),
                                     "missing \\0asm magic header"))
        return mod
    if data[4:8] != b"\x01\x00\x00\x00":
        mod.diagnostics.append(_diag("bad_version", 4, (4, 8),
                                     f"unsupported version bytes {data[4:8].hex()}"))
        return mod
    pos = 8
    seen_known: list[int] = []
    ordinal = 0
    while pos < len(data):
        id_offset = pos
        section_id = data[pos]
        pos += 1
        name = SECTION_NAMES.get(section_id, f"unknown_{section_id}")
        try:
            size = read_uleb(data, pos, 32)
        except LebError as e:
            mod.diagnostics.append(e.event())
            return mod
        mod.leb_encodings.append({**size.to_dict(), "role": "section_size",
                                  "section": name})
        for d in size.diagnostics:
            mod.diagnostics.append({**d, "section": name})
        pos = size.byte_range[1]
        end = pos + size.value
        if end > len(data):
            mod.diagnostics.append(_diag(
                "section_size_overrun", id_offset, (id_offset, len(data)),
                f"section {name} declares {size.value} payload bytes but only "
                f"{len(data) - pos} remain"))
            return mod
        payload = data[pos:end]
        sec = Section(ordinal, section_id, name, id_offset, size.to_dict(),
                      (pos, end), (id_offset, end), data[id_offset:end])
        mod.sections.append(sec)
        ordinal += 1
        if section_id > MAX_SECTION_ID:
            mod.diagnostics.append(_diag(
                "unknown_section_id", id_offset, (id_offset, end),
                f"section id {section_id} is not a known core section id"))
        elif section_id != 0:
            if section_id in seen_known:
                mod.diagnostics.append(_diag(
                    "section_duplicate", id_offset, (id_offset, end),
                    f"section {name} appears more than once", section=name))
            elif seen_known and section_id < seen_known[-1]:
                mod.diagnostics.append(_diag(
                    "section_out_of_order", id_offset, (id_offset, end),
                    f"section {name} (id {section_id}) follows id "
                    f"{seen_known[-1]}; known sections must be ordered",
                    section=name))
            seen_known.append(section_id)
        if section_id == 0:
            _parse_custom(mod, sec, payload, pos)
        elif section_id == 1:
            _parse_types(mod, sec, payload, pos, proposals)
        elif section_id == 2:
            _parse_imports(mod, sec, payload, pos)
        elif section_id == 3:
            _parse_functions(mod, sec, payload, pos)
        elif section_id == 10:
            _parse_code(mod, sec, payload, pos)
        pos = end
    n_declared = len(mod.func_type_indices)
    n_bodies = len(mod.bodies)
    if n_declared != n_bodies:
        mod.diagnostics.append(_diag(
            "function_code_count_mismatch", len(data), (len(data), len(data)),
            f"function section declares {n_declared} functions but code section "
            f"has {n_bodies} bodies"))
    return mod


def _parse_custom(mod: ParsedModule, sec: Section, payload: bytes, base: int):
    try:
        name_len = read_uleb(payload, 0, 32)
    except LebError as e:
        mod.diagnostics.append(e.event())
        return
    mod.leb_encodings.append({**name_len.to_dict(), "role": "custom_name_len",
                              "section": "custom"})
    for d in name_len.diagnostics:
        mod.diagnostics.append(d)
    nstart = name_len.byte_range[1]
    name = payload[nstart:nstart + name_len.value].decode("utf-8", "replace")
    content = payload[nstart + name_len.value:]
    mod.custom_sections.append({
        "name": name,
        "byte_range": [base, base + len(payload)],
        "content_hex": content.hex(),
        "content_sha256": __import__("hashlib").sha256(content).hexdigest(),
        "size": len(content),
    })


def _parse_types(mod: ParsedModule, sec: Section, payload: bytes, base: int,
                 proposals: set[str]):
    try:
        count = read_uleb(payload, 0, 32)
    except LebError as e:
        mod.diagnostics.append(e.event())
        return
    mod.leb_encodings.append({**count.to_dict(), "role": "type_count",
                              "section": "type"})
    pos = count.byte_range[1]
    for i in range(count.value):
        start = pos
        if pos >= len(payload) or payload[pos] != 0x60:
            mod.diagnostics.append(_diag(
                "malformed_type", base + pos, (base + pos, base + pos + 1),
                f"type {i}: expected 0x60 functype marker"))
            return
        pos += 1
        try:
            nparams = read_uleb(payload, pos, 32)
            pos = nparams.byte_range[1]
            params = []
            for _ in range(nparams.value):
                vt = payload[pos]; pos += 1
                params.append(VALTYPES.get(vt, f"unknown_0x{vt:02x}"))
            nresults = read_uleb(payload, pos, 32)
            pos = nresults.byte_range[1]
            results = []
            for _ in range(nresults.value):
                vt = payload[pos]; pos += 1
                results.append(VALTYPES.get(vt, f"unknown_0x{vt:02x}"))
        except (LebError, IndexError) as e:
            mod.diagnostics.append(
                e.event() if isinstance(e, LebError) else
                _diag("truncated_type", base + pos, (base + pos, base + pos),
                      "type entry truncated"))
            return
        if len(results) > 1 and "multi-value" not in proposals:
            mod.diagnostics.append(_diag(
                "capability_missing", base + start, (base + start, base + pos),
                f"type {i} has {len(results)} results; requires proposal "
                f"'multi-value' which is not enabled",
                feature="multi-value-results", proposal="multi-value"))
        mod.types.append(FuncType(i, params, results, (base + start, base + pos)))


def _parse_imports(mod: ParsedModule, sec: Section, payload: bytes, base: int):
    try:
        count = read_uleb(payload, 0, 32)
    except LebError as e:
        mod.diagnostics.append(e.event())
        return
    mod.leb_encodings.append({**count.to_dict(), "role": "import_count",
                              "section": "import"})
    pos = count.byte_range[1]
    for i in range(count.value):
        start = pos
        try:
            mlen = read_uleb(payload, pos, 32); pos = mlen.byte_range[1]
            module = payload[pos:pos + mlen.value].decode("utf-8", "replace")
            pos += mlen.value
            nlen = read_uleb(payload, pos, 32); pos = nlen.byte_range[1]
            name = payload[pos:pos + nlen.value].decode("utf-8", "replace")
            pos += nlen.value
            kind_byte = payload[pos]; pos += 1
        except (LebError, IndexError) as e:
            mod.diagnostics.append(
                e.event() if isinstance(e, LebError) else
                _diag("truncated_import", base + pos, (base + pos, base + pos),
                      "import entry truncated"))
            return
        kind = {0: "func", 1: "table", 2: "memory", 3: "global"}.get(
            kind_byte, f"unknown_{kind_byte}")
        type_index = None
        if kind == "func":
            try:
                tidx = read_uleb(payload, pos, 32)
                pos = tidx.byte_range[1]
                type_index = tidx.value
            except LebError as e:
                mod.diagnostics.append(e.event())
                return
        elif kind == "global":
            pos += 2  # valtype + mutability
        elif kind in ("table", "memory"):
            # limits: flags, min, [max]
            pos += 1
            try:
                lim = read_uleb(payload, pos, 32); pos = lim.byte_range[1]
            except LebError as e:
                mod.diagnostics.append(e.event())
                return
        mod.imports.append(Import(i, module, name, kind, type_index,
                                  (base + start, base + pos)))


def _parse_functions(mod: ParsedModule, sec: Section, payload: bytes, base: int):
    try:
        count = read_uleb(payload, 0, 32)
    except LebError as e:
        mod.diagnostics.append(e.event())
        return
    mod.leb_encodings.append({**count.to_dict(), "role": "function_count",
                              "section": "function"})
    pos = count.byte_range[1]
    for _ in range(count.value):
        try:
            tidx = read_uleb(payload, pos, 32)
        except LebError as e:
            mod.diagnostics.append(e.event())
            return
        mod.leb_encodings.append({**tidx.to_dict(), "role": "func_type_index",
                                  "section": "function"})
        for d in tidx.diagnostics:
            mod.diagnostics.append(d)
        mod.func_type_indices.append(tidx.value)
        pos = tidx.byte_range[1]


def _parse_code(mod: ParsedModule, sec: Section, payload: bytes, base: int):
    try:
        count = read_uleb(payload, 0, 32)
    except LebError as e:
        mod.diagnostics.append(e.event())
        return
    mod.leb_encodings.append({**count.to_dict(), "role": "code_count",
                              "section": "code"})
    pos = count.byte_range[1]
    n_imported_funcs = sum(1 for i in mod.imports if i.kind == "func")
    for i in range(count.value):
        try:
            size = read_uleb(payload, pos, 32)
        except LebError as e:
            mod.diagnostics.append(e.event())
            return
        mod.leb_encodings.append({**size.to_dict(), "role": "body_size",
                                  "section": "code"})
        for d in size.diagnostics:
            mod.diagnostics.append(d)
        body_start = size.byte_range[1]
        body_end = body_start + size.value
        if body_end > len(payload):
            mod.diagnostics.append(_diag(
                "body_size_overrun", base + pos, (base + pos, base + len(payload)),
                f"code body {i} overruns code section"))
            return
        type_index = (mod.func_type_indices[i]
                      if i < len(mod.func_type_indices) else -1)
        mod.bodies.append(FunctionBody(
            func_index=n_imported_funcs + i,
            type_index=type_index,
            body_range=(base + body_start, base + body_end),
            code_offset=base + body_start,
            raw=payload[body_start:body_end]))
        pos = body_end
