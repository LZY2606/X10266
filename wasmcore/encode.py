"""Deterministic Wasm binary builders used by the offline case package,
the bundled samples and the tests. No randomness, no I/O."""

from __future__ import annotations

VT = {"i32": 0x7F, "i64": 0x7E, "f32": 0x7D, "f64": 0x7C,
      "funcref": 0x70, "externref": 0x6F}


def leb_u(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def leb_s(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if (n == 0 and not (b & 0x40)) or (n == -1 and (b & 0x40)):
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def vec(*items: bytes) -> bytes:
    return leb_u(len(items)) + b"".join(items)


def name(s: str) -> bytes:
    raw = s.encode("utf-8")
    return leb_u(len(raw)) + raw


def sec(sid: int, payload: bytes) -> bytes:
    return bytes([sid]) + leb_u(len(payload)) + payload


def sec_raw_size(sid: int, payload: bytes, raw_size_leb: bytes) -> bytes:
    """Section whose size LEB is supplied verbatim (for LEB mutants)."""
    return bytes([sid]) + raw_size_leb + payload


def functype(params, results) -> bytes:
    return (b"\x60" + vec(*[bytes([VT[p]]) for p in params])
            + vec(*[bytes([VT[r]]) for r in results]))


def module(*sections: bytes) -> bytes:
    return b"\x00asm\x01\x00\x00\x00" + b"".join(sections)


def code_section(bodies) -> bytes:
    """bodies: list of expression byte strings (locals vec excluded)."""
    entries = []
    for expr in bodies:
        content = b"\x00" + expr  # zero local declarations
        entries.append(leb_u(len(content)) + content)
    return sec(10, vec(*entries))
