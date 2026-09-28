from __future__ import annotations


def uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + uleb(len(payload)) + payload


def vec(items: list[bytes]) -> bytes:
    return uleb(len(items)) + b"".join(items)


def functype(params: list[int], results: list[int]) -> bytes:
    return b"\x60" + uleb(len(params)) + bytes(params) + uleb(len(results)) + bytes(results)


def limits(minimum: int, maximum: int | None = None) -> bytes:
    if maximum is None:
        return b"\x00" + uleb(minimum)
    return b"\x01" + uleb(minimum) + uleb(maximum)


I32 = 0x7F
I64 = 0x7E
FUNC = 0x00


def baseline_module() -> bytes:
    type_sec = section(1, vec([functype([I32], []), functype([I32], [I32])]))
    imp = (
        b"\x03env"
        + b"\x09host_abort"
        + bytes([FUNC])
        + uleb(0)
    )
    import_sec = section(2, vec([imp]))
    function_sec = section(3, vec([uleb(1)]))
    memory_sec = section(5, vec([limits(1)]))
    export_entry = b"\x05memory" + b"\x02" + uleb(0)
    export_sec = section(7, vec([export_entry]))
    body = b"\x00" + bytes([0x20, 0x00, 0x1A, 0x0B])
    code_sec = section(10, vec([uleb(len(body)) + body]))
    custom_sec = section(0, b"\x0dboundary.note" + b"initial-raw-record")
    return b"\x00asm\x01\x00\x00\x00" + type_sec + import_sec + function_sec + memory_sec + export_sec + code_sec + custom_sec


def duplicate_sections_module() -> bytes:
    module = baseline_module()
    type_payload = vec([functype([I32], [])])
    marker = section(10, vec([]))
    inserted = section(1, type_payload)
    return module.replace(marker, inserted + marker, 1)


def out_of_order_module() -> bytes:
    prefix = b"\x00asm\x01\x00\x00\x00"
    type_sec = section(1, vec([functype([I32], [])]))
    memory_sec = section(5, vec([limits(1)]))
    function_sec = section(3, vec([]))
    custom_sec = section(0, b"\x05order")
    return prefix + type_sec + memory_sec + function_sec + custom_sec


def noncanonical_leb_module() -> bytes:
    payload = b"\x01\x60\x01\x7f\x00\x80\x00"
    return b"\x00asm\x01\x00\x00\x00" + section(1, payload)


def numeric_overflow_leb_module() -> bytes:
    payload = b"\x81\x80\x80\x80\x10"
    return b"\x00asm\x01\x00\x00\x00" + section(1, payload)


def unreachable_module() -> bytes:
    type_sec = section(1, vec([functype([I32], [])]))
    imp = b"\x03env" + b"\x09host_abort" + bytes([FUNC]) + uleb(0)
    import_sec = section(2, vec([imp]))
    function_sec = section(3, vec([uleb(0)]))
    body = b"\x00" + bytes([0x00, 0x20, 0x00, 0x6A, 0x1A, 0x0B, 0x20, 0x00, 0x0B])
    code_sec = section(10, vec([uleb(len(body)) + body]))
    return b"\x00asm\x01\x00\x00\x00" + type_sec + import_sec + function_sec + code_sec


def multivalue_module(enabled: bool = False) -> bytes:
    type_sec = section(1, vec([functype([], [I32, I32])]))
    function_sec = section(3, vec([uleb(0)]))
    body = b"\x00" + bytes([0x41, 0x01, 0x41, 0x02, 0x0B])
    code_sec = section(10, vec([uleb(len(body)) + body]))
    module = b"\x00asm\x01\x00\x00\x00" + type_sec + function_sec + code_sec
    return module


def proposal_closed_module() -> bytes:
    type_sec = section(1, vec([functype([], [])]))
    function_sec = section(3, vec([uleb(0)]))
    body = b"\x00" + bytes([0x12, 0x00, 0x0B])
    code_sec = section(10, vec([uleb(len(body)) + body]))
    return b"\x00asm\x01\x00\x00\x00" + type_sec + function_sec + code_sec


def import_mismatch_module() -> bytes:
    type_sec = section(1, vec([functype([I64], []), functype([I32], [])]))
    imp = b"\x03env" + b"\x09host_abort" + bytes([FUNC]) + uleb(0)
    import_sec = section(2, vec([imp]))
    return b"\x00asm\x01\x00\x00\x00" + type_sec + import_sec


def custom_preserved_module() -> bytes:
    return baseline_module().replace(b"initial-raw-record", b"custom-preserved-v2", 1)
