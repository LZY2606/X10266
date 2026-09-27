"""LEB128 编解码。

设计约束（领域规则）：
- 非规范 LEB128（编码非最短）与数值越界（值超出目标位宽）是两类独立诊断，
  必须分开报告：编码可以非最短但值在范围内，值也可以越界但编码已最短。
"""
from __future__ import annotations

from dataclasses import dataclass, field

NON_CANONICAL_LEB128 = "NON_CANONICAL_LEB128"
LEB128_VALUE_OVERFLOW = "LEB128_VALUE_OVERFLOW"
LEB128_TOO_LONG = "LEB128_TOO_LONG"
LEB128_TRUNCATED = "LEB128_TRUNCATED"


class LebError(Exception):
    """无法继续解码的 LEB128 错误（截断 / 字节数超限）。"""

    def __init__(self, kind: str, offset: int, end: int, detail: str = ""):
        super().__init__(f"{kind} at [{offset},{end}): {detail}")
        self.kind = kind
        self.offset = offset
        self.end = end
        self.detail = detail


@dataclass
class LebValue:
    value: int
    offset: int
    end: int
    raw: bytes
    signed: bool
    max_bits: int
    diagnostics: list = field(default_factory=list)

    @property
    def canonical(self) -> bool:
        return NON_CANONICAL_LEB128 not in self.diagnostics

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "range": [self.offset, self.end],
            "raw_hex": self.raw.hex(),
            "signed": self.signed,
            "max_bits": self.max_bits,
            "canonical": self.canonical,
            "diagnostics": list(self.diagnostics),
        }


def _min_uleb_bytes(value: int) -> int:
    n = 1
    while value >> (7 * n):
        n += 1
    return n


def _min_sleb_bytes(value: int) -> int:
    n = 1
    while True:
        bits = 7 * n
        low = value & ((1 << bits) - 1)
        ext = low - (1 << bits) if low & (1 << (bits - 1)) else low
        if ext == value:
            return n
        n += 1


def decode_uleb128(data: bytes, offset: int, max_bits: int = 32) -> LebValue:
    max_bytes = (max_bits + 6) // 7
    result = 0
    shift = 0
    pos = offset
    while True:
        if pos >= len(data):
            raise LebError(LEB128_TRUNCATED, offset, pos, "uleb128 在输入末尾被截断")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            break
        if pos - offset >= max_bytes:
            raise LebError(
                LEB128_TOO_LONG, offset, pos,
                f"u{max_bits} LEB128 超过 {max_bytes} 字节上限",
            )
    raw = data[offset:pos]
    diagnostics = []
    if result >= (1 << max_bits):
        diagnostics.append(LEB128_VALUE_OVERFLOW)
    if len(raw) > _min_uleb_bytes(result):
        diagnostics.append(NON_CANONICAL_LEB128)
    return LebValue(result, offset, pos, raw, False, max_bits, diagnostics)


def decode_sleb128(data: bytes, offset: int, max_bits: int = 32) -> LebValue:
    max_bytes = (max_bits + 6) // 7
    result = 0
    shift = 0
    pos = offset
    while True:
        if pos >= len(data):
            raise LebError(LEB128_TRUNCATED, offset, pos, "sleb128 在输入末尾被截断")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            if byte & 0x40:
                result -= 1 << shift
            break
        if pos - offset >= max_bytes:
            raise LebError(
                LEB128_TOO_LONG, offset, pos,
                f"s{max_bits} LEB128 超过 {max_bytes} 字节上限",
            )
    raw = data[offset:pos]
    diagnostics = []
    if not (-(1 << (max_bits - 1)) <= result < (1 << (max_bits - 1))):
        diagnostics.append(LEB128_VALUE_OVERFLOW)
    if len(raw) > _min_sleb_bytes(result):
        diagnostics.append(NON_CANONICAL_LEB128)
    return LebValue(result, offset, pos, raw, True, max_bits, diagnostics)


def encode_uleb128(value: int) -> bytes:
    if value < 0:
        raise ValueError("uleb128 不能编码负数")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def encode_sleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        done = (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40)
        out.append(byte if done else byte | 0x80)
        if done:
            return bytes(out)
