"""Tiny Wasm binary builder used by the offline case pack and tests."""
from __future__ import annotations

VALTYPE = {"i32": 0x7F, "i64": 0x7E, "f32": 0x7D, "f64": 0x7C,
           "v128": 0x7B, "funcref": 0x70, "externref": 0x6F}


def u32(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def u32_overlong(v: int, extra: int = 1) -> bytes:
    """Non-canonical (overlong but in-range) u32 LEB128 encoding."""
    base = bytearray(u32(v))
    base[-1] |= 0x80
    return bytes(base) + b"\x00" * extra


def s32(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if (v == 0 and not (b & 0x40)) or (v == -1 and (b & 0x40)):
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def section(sec_id: int, payload: bytes, size_bytes: bytes | None = None) -> bytes:
    size = size_bytes if size_bytes is not None else u32(len(payload))
    return bytes([sec_id]) + size + payload


def module(*secs: bytes) -> bytes:
    return b"\x00asm\x01\x00\x00\x00" + b"".join(secs)


def vec(items: list[bytes]) -> bytes:
    return u32(len(items)) + b"".join(items)


def name(s: str) -> bytes:
    b = s.encode("utf-8")
    return u32(len(b)) + b


def functype(params: list[str], results: list[str]) -> bytes:
    return (b"\x60"
            + vec([bytes([VALTYPE[t]]) for t in params])
            + vec([bytes([VALTYPE[t]]) for t in results]))


def type_section(types: list[bytes]) -> bytes:
    return section(1, vec(types))


def import_section(entries: list[bytes]) -> bytes:
    return section(2, vec(entries))


def import_func(mod: str, nm: str, type_idx: int) -> bytes:
    return name(mod) + name(nm) + b"\x00" + u32(type_idx)


def function_section(type_indices: list[int]) -> bytes:
    return section(3, vec([u32(i) for i in type_indices]))


def code_section(bodies: list[bytes]) -> bytes:
    return section(10, vec([u32(len(b)) + b for b in bodies]))


def body(locals_: list[tuple[int, str]], expr: bytes) -> bytes:
    loc = vec([u32(n) + bytes([VALTYPE[t]]) for n, t in locals_])
    return loc + expr


def custom_section(nm: str, data: bytes) -> bytes:
    return section(0, name(nm) + data)
