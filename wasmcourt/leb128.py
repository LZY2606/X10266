"""LEB128 解码：严格区分四类结果。

- ``ok``：值在范围内且为最短（规范）编码。
- ``non-canonical``：值可解码且未越界，但编码长度超过最短表示。
  与“数值越界”是两件事：值仍然合法，是否接受由人工/规则裁定。
- ``representation-too-long``：占用字节数超过 ceil(bits/7)（非规范长度，硬错误）。
- ``value-overflow``：字节数合法但末字节高位超出 bits（数值越界，硬错误）。
- ``truncated``：输入在续位仍为 1 时结束（无法解码，值保留为 None）。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

OK = "ok"
NONCANONICAL = "non-canonical"
TOO_LONG = "representation-too-long"
OVERFLOW = "value-overflow"
TRUNCATED = "truncated"

STATUSES = (OK, NONCANONICAL, TOO_LONG, OVERFLOW, TRUNCATED)


@dataclass
class LebResult:
    offset: int
    raw: bytes
    value: Optional[int]
    status: str
    bits: int
    signed: bool
    context: str = ""
    diagnostic: Optional[str] = None

    @property
    def end(self) -> int:
        return self.offset + len(self.raw)

    @property
    def decodable(self) -> bool:
        return self.value is not None

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "end": self.end,
            "raw_hex": self.raw.hex(),
            "value": self.value,
            "status": self.status,
            "bits": self.bits,
            "signed": self.signed,
            "context": self.context,
            "diagnostic": self.diagnostic,
        }


def _minimal_u_length(value: int) -> int:
    return max(1, (value.bit_length() + 6) // 7)


def _minimal_s_length(value: int) -> int:
    n = 1
    while not (-(1 << (7 * n - 1)) <= value < (1 << (7 * n - 1))):
        n += 1
    return n


def decode_u(data: bytes, offset: int, bits: int = 32,
             context: str = "") -> LebResult:
    max_bytes = (bits + 6) // 7
    value = 0
    shift = 0
    n = 0
    while True:
        if offset + n >= len(data):
            return LebResult(offset, bytes(data[offset:offset + n]), None,
                             TRUNCATED, bits, False, context,
                             "truncated LEB128: continuation bit set at end of input")
        b = data[offset + n]
        n += 1
        if n > max_bytes:
            return LebResult(offset, bytes(data[offset:offset + n]), None,
                             TOO_LONG, bits, False, context,
                             f"integer representation too long: exceeds {max_bytes} bytes for u{bits}")
        low = b & 0x7F
        if n == max_bytes:
            rem = bits - 7 * (max_bytes - 1)
            if b & 0x80:
                return LebResult(offset, bytes(data[offset:offset + n]), None,
                                 TOO_LONG, bits, False, context,
                                 f"integer representation too long: continuation bit on {max_bytes}th byte for u{bits}")
            if low & (0x7F & ~((1 << rem) - 1)):
                return LebResult(offset, bytes(data[offset:offset + n]), None,
                                 OVERFLOW, bits, False, context,
                                 f"integer too large: value exceeds u{bits} range")
        value |= low << shift
        shift += 7
        if not (b & 0x80):
            status = OK if n == _minimal_u_length(value) else NONCANONICAL
            diag = None if status == OK else (
                f"non-canonical u{bits} encoding: value {value} needs "
                f"{_minimal_u_length(value)} byte(s) but uses {n}")
            return LebResult(offset, bytes(data[offset:offset + n]), value,
                             status, bits, False, context, diag)


def decode_s(data: bytes, offset: int, bits: int = 32,
             context: str = "") -> LebResult:
    max_bytes = (bits + 6) // 7
    value = 0
    shift = 0
    n = 0
    while True:
        if offset + n >= len(data):
            return LebResult(offset, bytes(data[offset:offset + n]), None,
                             TRUNCATED, bits, True, context,
                             "truncated signed LEB128")
        b = data[offset + n]
        n += 1
        if n > max_bytes:
            return LebResult(offset, bytes(data[offset:offset + n]), None,
                             TOO_LONG, bits, True, context,
                             f"integer representation too long: exceeds {max_bytes} bytes for s{bits}")
        low = b & 0x7F
        if n == max_bytes:
            rem = bits - 7 * (max_bytes - 1)
            if b & 0x80:
                return LebResult(offset, bytes(data[offset:offset + n]), None,
                                 TOO_LONG, bits, True, context,
                                 f"integer representation too long: continuation bit on {max_bytes}th byte for s{bits}")
            ext_mask = 0x7F & ~((1 << rem) - 1)
            extra = low & ext_mask
            if extra not in (0, ext_mask):
                return LebResult(offset, bytes(data[offset:offset + n]), None,
                                 OVERFLOW, bits, True, context,
                                 f"integer too large: sign-extended bits invalid for s{bits}")
            value |= (low & ((1 << rem) - 1)) << shift
            sign_bit = 1 << (rem - 1)
            if low & sign_bit:
                value -= 1 << bits
            status = OK if n == _minimal_s_length(value) else NONCANONICAL
            diag = None if status == OK else (
                f"non-canonical s{bits} encoding: value {value} needs "
                f"{_minimal_s_length(value)} byte(s) but uses {n}")
            return LebResult(offset, bytes(data[offset:offset + n]), value,
                             status, bits, True, context, diag)
        value |= low << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                value -= 1 << shift
            status = OK if n == _minimal_s_length(value) else NONCANONICAL
            diag = None if status == OK else (
                f"non-canonical s{bits} encoding: value {value} needs "
                f"{_minimal_s_length(value)} byte(s) but uses {n}")
            return LebResult(offset, bytes(data[offset:offset + n]), value,
                             status, bits, True, context, diag)


def encode_u(value: int) -> bytes:
    if value < 0:
        raise ValueError("encode_u requires non-negative value")
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)
