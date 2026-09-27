"""WebAssembly 模块解析与验证核心。

判断规则（机器可读、一等数据）：
- 非规范 LEB128 与数值越界分开报告；
- polymorphic stack 只在 unreachable 区域生效；
- 未启用 proposal 的 opcode 报 capability_missing 而非 unknown_opcode。
"""
from .leb128 import read_uleb, read_sleb, diag
from .parser import parse_module, SECTION_NAMES, custom_section_hashes
from .validator import validate_module, param_fingerprint, KNOWN_PROPOSALS
from .judgments import judgments_from_report

ALGO_VERSION = "wasmcore/1.0.0"

__all__ = [
    "read_uleb", "read_sleb", "diag",
    "parse_module", "SECTION_NAMES", "custom_section_hashes",
    "validate_module", "param_fingerprint", "KNOWN_PROPOSALS",
    "judgments_from_report", "ALGO_VERSION",
]
