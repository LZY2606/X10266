"""LEB128 解码。

需求硬性约束：
* 非规范编码（NON_CANONICAL）与数值越界（OUT_OF_RANGE）是两个独立诊断，分别上报。
* 出错时尽量恢复 value，给出候选，并保留精确字节范围。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class LebDiag:
    code: str            # NON_CANONICAL | OUT_OF_RANGE | UNEXPECTED_END | INTEGER_TOO_LONG
    message: str
    byte_range: tuple
    bit: Optional[int] = None


@dataclass
class LebResult:
    value: int
    start: int
    end: int
    signed: bool
    canonical: bool = True
    in_range: bool = True
    diags: List[LebDiag] = field(default_factory=list)
    candidates: List[dict] = field(default_factory=list)

    @property
    def byte_range(self) -> tuple:
        return (self.start, self.end)


def _finish(res: LebResult, raw_ok: bool) -> LebResult:
    if not res.canonical:
        res.candidates.append({"kind": "strict", "accepted": False,
                               "reject_reason": "NON_CANONICAL",
                               "byte_range": list(res.byte_range)})
        res.candidates.append({"kind": "lenient_value", "accepted": raw_ok,
                               "value": res.value, "byte_range": list(res.byte_range)})
    else:
        res.candidates.append({"kind": "value", "accepted": res.in_range,
                               "value": res.value, "byte_range": list(res.byte_range)})
    return res


def decode_uleb(data: bytes, pos: int, max_bits: int = 32) -> LebResult:
    start = pos
    result = 0
    shift = 0
    count = 0
    diags: List[LebDiag] = []
    canonical = True
    in_range = True
    while True:
        if pos >= len(data):
            diags.append(LebDiag("UNEXPECTED_END", "无符号 LEB128 提前结束",
                                 (start, len(data))))
            return _finish(LebResult(result, start, len(data), False, canonical,
                                     in_range, diags), False)
        byte = data[pos]
        pos += 1
        count += 1
        payload = byte & 0x7F
        # 越界：超出 max_bits 的位必须为 0
        if shift >= max_bits:
            if payload != 0:
                in_range = False
                diags.append(LebDiag("OUT_OF_RANGE",
                                     f"无符号 LEB128 超出 {max_bits} 位",
                                     (pos - 1, pos), shift))
        elif shift + 7 > max_bits:
            allowed = max_bits - shift
            if payload >> allowed:
                in_range = False
                diags.append(LebDiag("OUT_OF_RANGE",
                                     f"无符号 LEB128 第 {count} 字节溢出",
                                     (pos - 1, pos), shift + allowed))
        if shift < 64:
            result |= payload << shift
        if (byte & 0x80) == 0:
            # 规范性：除首字节外，末字节不允许为 0（多余续字节）
            if count > 1 and payload == 0:
                canonical = False
                diags.append(LebDiag("NON_CANONICAL",
                                     "非规范无符号 LEB128：末尾冗余 0x00",
                                     (pos - 1, pos)))
            break
        shift += 7
        if count > 5:
            diags.append(LebDiag("INTEGER_TOO_LONG", "u32 LEB128 超过 5 字节",
                                 (start, pos)))
            while pos < len(data) and data[pos] & 0x80:
                pos += 1
            if pos < len(data):
                pos += 1
            break
    masked = result & ((1 << max_bits) - 1)
    return _finish(LebResult(masked, start, pos, False, canonical, in_range, diags),
                   in_range)


def decode_sleb(data: bytes, pos: int, max_bits: int = 32) -> LebResult:
    start = pos
    result = 0
    shift = 0
    count = 0
    diags: List[LebDiag] = []
    canonical = True
    in_range = True
    last_payload = 0
    while True:
        if pos >= len(data):
            diags.append(LebDiag("UNEXPECTED_END", "有符号 LEB128 提前结束",
                                 (start, len(data))))
            return _finish(LebResult(result, start, len(data), True, canonical,
                                     in_range, diags), False)
        byte = data[pos]
        pos += 1
        count += 1
        payload = byte & 0x7F
        last_payload = payload
        if shift < 64:
            result |= payload << shift
        if (byte & 0x80) == 0:
            # 末字节。sign_bit_pos = 符号位在本字节载荷中的下标
            if shift + 7 >= max_bits:
                sign_bit_pos = max_bits - shift - 1
            else:
                sign_bit_pos = 6
            sign = (payload >> sign_bit_pos) & 1
            # 越界：高于符号位的位必须全部等于符号位
            if sign_bit_pos < 6:
                top_mask = 0x7F ^ ((1 << (sign_bit_pos + 1)) - 1)
                top = payload & top_mask
                expected_top = (sign * 0x7F) & top_mask
                if top != expected_top:
                    in_range = False
                    diags.append(LebDiag("OUT_OF_RANGE",
                                         f"有符号 LEB128 第 {count} 字节越界",
                                         (pos - 1, pos), sign_bit_pos + 1))
                # 非规范：符号位之下一位若与符号位相同，则本可少一个字节
                if sign_bit_pos >= 1 and in_range:
                    if ((payload >> (sign_bit_pos - 1)) & 1) == sign:
                        canonical = False
                        diags.append(LebDiag(
                            "NON_CANONICAL",
                            "非规范有符号 LEB128：末尾含多余符号扩展位",
                            (pos - 1, pos), sign_bit_pos - 1))
            # 符号扩展
            if sign and shift < max_bits:
                result |= -(1 << min(shift + 7, max_bits))
            break
        shift += 7
        if count > 5:
            diags.append(LebDiag("INTEGER_TOO_LONG", "s32 LEB128 超过 5 字节",
                                 (start, pos)))
            while pos < len(data) and data[pos] & 0x80:
                pos += 1
            if pos < len(data):
                pos += 1
            break
    value = result
    if in_range:
        value &= (1 << max_bits) - 1
        if value & (1 << (max_bits - 1)):
            value -= 1 << max_bits
    return _finish(LebResult(value, start, pos, True, canonical, in_range, diags),
                   in_range)
