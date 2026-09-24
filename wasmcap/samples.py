from __future__ import annotations


def u32(value: int) -> bytes:
    out = bytearray()
    while True:
        chunk = value & 0x7F
        value >>= 7
        if value:
            out.append(chunk | 0x80)
        else:
            out.append(chunk)
            return bytes(out)


def name(value: str) -> bytes:
    raw = value.encode("utf-8")
    return u32(len(raw)) + raw


def section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + u32(len(payload)) + payload


def custom_section(section_name: str, payload: bytes) -> bytes:
    return section(0, name(section_name) + payload)


def func_type(params: list[int], results: list[int]) -> bytes:
    return bytes([0x60]) + u32(len(params)) + bytes(params) + u32(len(results)) + bytes(results)


def type_section(types: list[bytes], count_override: bytes | None = None) -> bytes:
    payload = bytearray()
    payload += count_override if count_override is not None else u32(len(types))
    for item in types:
        payload += item
    return section(1, bytes(payload))


def import_entry(module: str, field: str, function_type: int) -> bytes:
    return name(module) + name(field) + bytes([0x00]) + u32(function_type)


def import_section(entries: list[bytes]) -> bytes:
    return section(2, u32(len(entries)) + b"".join(entries))


def function_section(type_indices: list[int]) -> bytes:
    return section(3, u32(len(type_indices)) + b"".join(u32(i) for i in type_indices))


def export_entry(export_name: str, kind: int, index: int) -> bytes:
    return name(export_name) + bytes([kind]) + u32(index)


def export_section(entries: list[bytes]) -> bytes:
    return section(7, u32(len(entries)) + b"".join(entries))


def code_body(locals_: bytes, instructions: bytes) -> bytes:
    body = u32(0) + locals_ + instructions + b"\x0b"
    return u32(len(body)) + body


def code_section(bodies: list[bytes]) -> bytes:
    return section(10, u32(len(bodies)) + b"".join(bodies))


HEADER = b"\x00asm\x01\x00\x00\x00"
I32 = 0x7F
I64 = 0x7E


def baseline() -> bytes:
    types = type_section([func_type([], [I32]), func_type([], [])])
    imports = import_section([import_entry("env", "answer", 0)])
    functions = function_section([1])
    exports = export_section([export_entry("run", 0, 1)])
    body = code_body(b"", b"\x10\x00\x1a")
    metadata = custom_section("court-metadata", b"baseline-v1")
    return HEADER + types + imports + functions + exports + code_section([body]) + metadata


def custom_revision() -> bytes:
    types = type_section([func_type([], [I32]), func_type([], [])])
    imports = import_section([import_entry("env", "answer", 0)])
    functions = function_section([1])
    exports = export_section([export_entry("run", 0, 1)])
    body = code_body(b"", b"\x10\x00\x1a")
    metadata = custom_section("court-metadata", b"baseline-v2-payload")
    return HEADER + types + imports + functions + exports + code_section([body]) + metadata


def multi_value() -> bytes:
    types = type_section([func_type([I32, I32], [I32, I32])])
    functions = function_section([0])
    body = code_body(b"", b"\x20\x00\x20\x01")
    return HEADER + types + functions + code_section([body])


def tail_call() -> bytes:
    types = type_section([func_type([], []), func_type([], [])])
    imports = import_section([import_entry("env", "loop", 0)])
    functions = function_section([1])
    body = code_body(b"", b"\x12\x00")
    return HEADER + types + imports + functions + code_section([body])


def import_mismatch() -> bytes:
    types = type_section([func_type([], [I32]), func_type([], [])])
    imports = import_section([import_entry("env", "mismatch", 0)])
    functions = function_section([1])
    body = code_body(b"", b"")
    return HEADER + types + imports + functions + code_section([body])


def unreachable_valid() -> bytes:
    types = type_section([func_type([], [])])
    functions = function_section([0])
    body = code_body(b"", b"\x00\x6a")
    return HEADER + types + functions + code_section([body])


def underflow_outside_unreachable() -> bytes:
    types = type_section([func_type([], [])])
    functions = function_section([0])
    body = code_body(b"", b"\x01\x40\x00\x0b\x6a")
    return HEADER + types + functions + code_section([body])


def noncanonical_leb() -> bytes:
    # The type-vector count is 2, encoded as 0x80 0x01 rather than 0x02.
    types = type_section(
        [func_type([], []), func_type([I32], [I32])],
        count_override=b"\x80\x01",
    )
    functions = function_section([0, 1])
    bodies = code_section([code_body(b"", b""), code_body(b"", b"\x20\x00")])
    return HEADER + types + functions + code_section([bodies])


def numeric_overflow_leb() -> bytes:
    # 2^32 in a u32 field: the fifth LEB byte has a bit outside 32 bits.
    return HEADER + section(1, b"\x80\x80\x80\x80\x10\x60\x00\x00")


def duplicate_unordered_sections() -> bytes:
    first_type = type_section([func_type([], [])])
    functions = function_section([0])
    code = code_section([code_body(b"", b"")])
    duplicate_type = type_section([func_type([I32], [I32])])
    return HEADER + first_type + functions + code + duplicate_type


def unknown_opcode() -> bytes:
    types = type_section([func_type([], [])])
    functions = function_section([0])
    body = code_body(b"", b"\xff")
    return HEADER + types + functions + code_section([body])


SAMPLES = {
    "baseline": baseline,
    "custom_revision": custom_revision,
    "multi_value": multi_value,
    "tail_call": tail_call,
    "import_mismatch": import_mismatch,
    "unreachable_valid": unreachable_valid,
    "underflow_outside_unreachable": underflow_outside_unreachable,
    "noncanonical_leb": noncanonical_leb,
    "numeric_overflow_leb": numeric_overflow_leb,
    "duplicate_unordered_sections": duplicate_unordered_sections,
    "unknown_opcode": unknown_opcode,
}

