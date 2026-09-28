from __future__ import annotations

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
    12: "data_count",
}

KNOWN_SECTIONS = tuple(range(1, 13))

VALUE_TYPES = {
    0x7F: ("i32", "mvp"),
    0x7E: ("i64", "mvp"),
    0x7D: ("f32", "mvp"),
    0x7C: ("f64", "mvp"),
    0x7B: ("v128", "simd"),
    0x70: ("funcref", "reference_types"),
    0x6F: ("externref", "reference_types"),
}

IMPORT_KINDS = {0: "func", 1: "table", 2: "mem", 3: "global"}
EXPORT_KINDS = {0: "func", 1: "table", 2: "mem", 3: "global"}


def section_name(section_id: int) -> str:
    return SECTION_NAMES.get(section_id, f"unknown_{section_id}")


def value_type(code: int) -> tuple[str, str | None]:
    item = VALUE_TYPES.get(code)
    if item is None:
        return f"unknown_type_0x{code:02x}", None
    return item
