"""WebAssembly 模块验证 / 提案能力 / 版本能力领域内核。

所有派生结果都携带算法版本 (ALGO_VERSION) 与直接来源引用，
便于长期复查时判断某条结论是由哪版规则计算出来的。
"""

ALGO_VERSION = "wasm-verify-1.0.0"
MAGIC = b"\x00asm"
VERSION_1 = b"\x01\x00\x00\x00"

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

KNOWN_SECTION_IDS = set(SECTION_NAMES)
