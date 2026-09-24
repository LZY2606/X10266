"""Copyable, tiny WebAssembly sample modules and single-source mutators.

Each mutator changes exactly one direct source (one byte range, one section,
one feature) while leaving every other source byte untouched - the foundation
for "局部输入变化只使依赖它的结果过期".
"""
from __future__ import annotations

from .leb128 import decode_uleb

I32, I64, F32, F64, FUNCREF = 0x7F, 0x7E, 0x7D, 0x7C, 0x70


def uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(value: int) -> bytes:
    out = bytearray()
    more = True
    while more:
        b = value & 0x7F
        value >>= 7
        sign_bit = b & 0x40
        if (value == 0 and not sign_bit) or (value == -1 and sign_bit):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)


def vec(items: list[bytes]) -> bytes:
    return uleb(len(items)) + b"".join(items)


def name(s: str) -> bytes:
    raw = s.encode("utf-8")
    return uleb(len(raw)) + raw


def section(sid: int, payload: bytes) -> bytes:
    return bytes([sid]) + uleb(len(payload)) + payload


def section_raw(sid: int, payload: bytes, size_leb: bytes) -> bytes:
    return bytes([sid]) + size_leb + payload


def custom_section(cname: str, payload: bytes = b"") -> bytes:
    return section(0, name(cname) + payload)


def functype(params: list[int], results: list[int]) -> bytes:
    return b"\x60" + vec([bytes([t]) for t in params]) + vec([bytes([t]) for t in results])


def limits(min_pages: int, max_pages: int | None = None) -> bytes:
    if max_pages is None:
        return b"\x00" + uleb(min_pages)
    return b"\x01" + uleb(min_pages) + uleb(max_pages)


def blocktype_void() -> bytes:
    return b"\x40"


def blocktype_multivalue(typeidx: int) -> bytes:
    return sleb(typeidx)


def const_expr_i32(v: int) -> bytes:
    return b"\x41" + sleb(v) + b"\x0b"


def locals_decl(groups: list[tuple[int, int]]) -> bytes:
    return vec([uleb(n) + bytes([t]) for n, t in groups])


def func_body(locals_groups: list[tuple[int, int]], instructions: bytes) -> bytes:
    body = locals_decl(locals_groups) + instructions + b"\x0b"
    return uleb(len(body)) + body


class Builder:
    def __init__(self) -> None:
        self.types: list[bytes] = []
        self.imports: list[bytes] = []
        self.functions: list[int] = []
        self.tables: list[bytes] = []
        self.memories: list[bytes] = []
        self.globals: list[bytes] = []
        self.exports: list[bytes] = []
        self.start: int | None = None
        self.elements: list[bytes] = []
        self.datacount: int | None = None
        self.codes: list[bytes] = []
        self.data: list[bytes] = []
        self.customs: list[tuple[str, bytes]] = []

    def add_type(self, params, results) -> int:
        self.types.append(functype(params, results))
        return len(self.types) - 1

    def add_import_func(self, mod: str, field: str, typeidx: int) -> None:
        self.imports.append(name(mod) + name(field) + b"\x00" + uleb(typeidx))

    def add_import_memory(self, mod: str, field: str, lo: int, hi: int | None) -> None:
        self.imports.append(name(mod) + name(field) + b"\x02" + limits(lo, hi))

    def add_func(self, typeidx: int, body: bytes) -> int:
        self.functions.append(typeidx)
        self.codes.append(body)
        return len(self.functions) - 1

    def add_export(self, nm: str, kind: int, idx: int) -> None:
        self.exports.append(name(nm) + bytes([kind]) + uleb(idx))

    def add_memory(self, lo: int, hi: int | None = None) -> None:
        self.memories.append(limits(lo, hi))

    def add_global_i32(self, mutable: bool, init: int) -> None:
        self.globals.append(bytes([I32, 1 if mutable else 0]) + const_expr_i32(init))

    def add_data_active(self, offset: int, blob: bytes) -> None:
        self.data.append(b"\x00" + const_expr_i32(offset) + vec([bytes([b]) for b in blob]))
        self.datacount = len(self.data)

    def sections(self) -> list[bytes]:
        secs: list[tuple[int, bytes]] = []
        if self.types:
            secs.append((1, vec(self.types)))
        if self.imports:
            secs.append((2, vec(self.imports)))
        if self.functions:
            secs.append((3, vec([uleb(t) for t in self.functions])))
        if self.tables:
            secs.append((4, vec(self.tables)))
        if self.memories:
            secs.append((5, vec(self.memories)))
        if self.globals:
            secs.append((6, vec(self.globals)))
        if self.exports:
            secs.append((7, vec(self.exports)))
        if self.start is not None:
            secs.append((8, uleb(self.start)))
        if self.elements:
            secs.append((9, vec(self.elements)))
        if self.datacount is not None:
            secs.append((12, uleb(self.datacount)))
        if self.codes:
            secs.append((10, vec(self.codes)))
        if self.data:
            secs.append((11, vec(self.data)))
        out = [section(sid, payload) for sid, payload in secs]
        for cname, payload in self.customs:
            out.append(custom_section(cname, payload))
        return out

    def build(self) -> bytes:
        return b"\x00asm\x01\x00\x00\x00" + b"".join(self.sections())


HOST_CONTRACT = {
    "functions": [
        {"module": "env", "name": "log_i32", "params": ["i32"], "results": []},
        {"module": "abort", "name": "abort", "params": [], "results": []},
    ],
    "memories": [
        {"module": "env", "name": "memory", "min_pages": 1, "max_pages": None},
    ],
}


def baseline() -> bytes:
    """Valid module exercising imports, multi-value types, unreachable
    polymorphism and the enabled proposals."""
    b = Builder()
    t_log = b.add_type([I32], [])
    t_main = b.add_type([], [I32])
    t_void = b.add_type([], [])
    t_pair = b.add_type([I32, I32], [I32, I32])  # multi-value
    t_abort = b.add_type([], [])

    b.add_import_func("env", "log_i32", t_log)
    b.add_import_memory("env", "memory", 1, None)
    b.add_func(t_abort, func_body([], b""))  # func idx 2
    code_main = (
        b"\x00"                       # unreachable
        + b"\x41" + sleb(1)           # i32.const 1 (polymorphic push ok)
        + b"\x1a"                     # drop under unreachable (pop is free)
        + b"\x0b"                     # end of unreachable region
        + b"\x41" + sleb(7)
        + b"\x0b"
    )
    b.add_func(t_main, func_body([], code_main))  # func idx 3
    code_pair = b"\x20" + uleb(0) + b"\x20" + uleb(1) + b"\x0b"
    b.add_func(t_pair, func_body([(2, I32)], code_pair))  # func idx 4
    code_ext = b"\x41" + sleb(0) + b"\xfc" + b"\x00" + b"\x1a" + b"\x0b"
    b.add_func(t_void, func_body([], code_ext))  # func idx 5

    b.add_export("main", 0, 2)
    b.add_export("pair", 0, 3)
    b.add_data_active(0, bytes([1, 2, 3]))
    b.customs.append(("provenance", b"pairwise-gsb/baseline"))
    b.customs.append(("review.note", name("z") + b"kept"))
    return b.build()


# ---------------------------------------------------------------------------
# Single-source mutators: each changes exactly one direct source.
# ---------------------------------------------------------------------------

def _find_section_span(raw: bytes, sid: int) -> tuple[int, int]:
    pos = 8
    while pos < len(raw):
        head = raw[pos]
        size_res = decode_uleb(raw, pos + 1)
        end = size_res.end + size_res.value
        if head == sid:
            return pos, end
        pos = end
    raise ValueError(f"section {sid} not found")


def m_duplicate_section(raw: bytes, sid: int = 1) -> bytes:
    """Append an exact duplicate of section ``sid`` right after itself."""
    start, end = _find_section_span(raw, sid)
    return raw[:end] + raw[start:end] + raw[end:]


def m_reorder_section(raw: bytes, sid: int = 11) -> bytes:
    """Move the data section before the code section (order violation)."""
    start, end = _find_section_span(raw, sid)
    sec = raw[start:end]
    rest = raw[:start] + raw[end:]
    cstart, _ = _find_section_span(rest, 10)
    return rest[:cstart] + sec + rest[cstart:]


def m_noncanonical_uleb(raw: bytes, sid: int = 3) -> bytes:
    """Re-encode one section size as a legal-but-non-canonical LEB128.
    Only the encoding bytes change; the numeric value and payload are kept."""
    start, end = _find_section_span(raw, sid)
    size_res = decode_uleb(raw, start + 1)
    value = size_res.value
    if value < 0x40:
        new_size_leb = bytes([0x80 | value, 0x00])
    else:
        new_size_leb = size_res.raw[:-1] + bytes([size_res.raw[-1] | 0x80, 0x00])
    return raw[: start + 1] + new_size_leb + raw[size_res.end:]


def m_value_overflow(raw: bytes) -> bytes:
    """Forge a 5-byte u32 with forbidden high bits (integer too large).
    Distinct from non-canonical encoding: the representation length is legal
    but the magnitude overflows u32."""
    start, _end = _find_section_span(raw, 1)
    size_res = decode_uleb(raw, start + 1)
    count_res = decode_uleb(raw, size_res.end)
    forged = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0x1F])  # > u32 max
    return raw[: count_res.start] + forged + raw[count_res.end:]


def m_unreachable_polymorphism(raw: bytes) -> bytes:
    """Replace the `end` closing the unreachable region with `nop`: everything
    after stays polymorphic; the failure is the unterminated function, not a
    stack-type mismatch inside the unreachable region."""
    idx = raw.index(b"\x00\x41\x01\x1a\x0b")
    return raw[: idx + 4] + b"\x01" + raw[idx + 5:]


def m_stack_mismatch_outside_unreachable(raw: bytes) -> bytes:
    """Insert an i32 drop against an empty value stack *outside* any
    unreachable region - polymorphic freedom must NOT apply there."""
    marker = b"\x41\x07\x0b"
    idx = raw.index(marker)
    return raw[:idx] + b"\x1a" + raw[idx:]


def m_unknown_byte(raw: bytes) -> bytes:
    """Replace an opcode with the genuinely unused byte 0xC5."""
    marker = b"\xfc\x00"
    idx = raw.index(marker)
    return raw[:idx] + b"\xc5" + raw[idx + 2:]


def m_simd_body(raw: bytes) -> bytes:
    """Rewrite the extension void function to use i8x16.splat (0xFD prefix),
    which is CAPABILITY_MISSING when simd is disabled."""
    marker = b"\xfc\x00"
    idx = raw.index(marker)
    return raw[:idx] + b"\xfd\x0f" + raw[idx + 2:]


def m_prefix_ambiguous(raw: bytes) -> bytes:
    """Corrupt the 0xFC sub-opcode byte so the sub-opcode cannot be decoded to
    a known instruction while the prefix is shared by several proposals."""
    marker = b"\xfc\x00"
    idx = raw.index(marker)
    return raw[: idx + 1] + b"\xff" + raw[idx + 2:]


def m_import_mismatch(raw: bytes) -> bytes:
    """Rename the imported function field so the host contract cannot match."""
    return raw.replace(b"log_i32", b"log_i99", 1)


def m_custom_tamper(raw: bytes) -> bytes:
    """Flip one payload byte inside the first custom section (fidelity)."""
    start, end = _find_section_span(raw, 0)
    mid = end - 2
    return raw[:mid] + bytes([raw[mid] ^ 0xFF]) + raw[mid + 1:]


def m_local_only_change(raw: bytes) -> bytes:
    """Change one instruction inside the `pair` function only: swap the order
    of the two local.get operands. Everything else byte-identical."""
    marker = b"\x20\x00\x20\x01\x0b"
    idx = raw.index(marker)
    return raw[:idx] + b"\x20\x01\x20\x00\x0b" + raw[idx + len(marker):]
