"""LEB128 解码与候选枚举。

核心原则 (反例档案的机器可读判断依据):
- "非规范 LEB128"(NONCANONICAL_LEB) 与 "数值越界"(INT_OUT_OF_RANGE)
  是两类互相独立的诊断: 可单独出现, 也可同时出现。
- 非规范 = 不是最短编码 (终止字节 0x00/0x7F 冗余, 即多余前导 0x80)。
- 越界 = 解码数学值超出目标位宽 (u32/s32/s33/u64/s64)。
- 截断 (TRUNCATED) / 过长 (LEB_TOO_LONG) 也分别标记。
- 非规范时额外给出 "最短编码候选"(canonical alternative), 保留全部解释。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

MAX_BYTES = {32: 5, 64: 10, 33: 5}


@dataclass
class LebCandidate:
    label: str          # accepted | canonical_alternative
    end: int            # 终止偏移 (exclusive, 相对整个 buffer)
    value: Optional[int]
    signed: Optional[int]
    canonical: bool
    overflow: bool
    status: str         # accepted | rejected
    reject_reason: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "label": self.label,
            "end": self.end,
            "value": self.value,
            "signed": self.signed,
            "canonical": self.canonical,
            "overflow": self.overflow,
            "status": self.status,
            "reject_reason": self.reject_reason,
        }


@dataclass
class LebToken:
    kind: str
    offset: int
    raw: bytes
    value: Optional[int]      # 无符号数学值
    signed: Optional[int]     # 有符号解释
    canonical: bool
    overflow: bool
    truncated: bool
    too_long: bool
    candidates: List[LebCandidate] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "offset": self.offset,
            "end": self.offset + len(self.raw),
            "raw_hex": self.raw.hex(),
            "raw_bytes": list(self.raw),
            "value": self.value,
            "signed": self.signed,
            "canonical": self.canonical,
            "overflow": self.overflow,
            "truncated": self.truncated,
            "too_long": self.too_long,
            "candidates": [c.as_dict() for c in self.candidates],
        }


def _twos_complement(value: int, bits: int) -> int:
    value &= (1 << bits) - 1
    if value >= 1 << (bits - 1):
        value -= 1 << bits
    return value


def decode_leb(buf: bytes, start: int, kind: str) -> LebToken:
    bits = {"u32": 32, "u64": 64, "s32": 32, "s33": 33, "s64": 64}[kind]
    signed = kind[0] == "s"
    max_bytes = MAX_BYTES[bits]

    value = 0
    shift = 0
    i = start
    terminated = False
    too_long = False
    while True:
        if i - start >= max_bytes:
            # 已读完最大允许字节数; 若最后一个仍是 continuation, 即过长。
            if buf[i - 1] & 0x80:
                too_long = True
            break
        if i >= len(buf):
            break  # truncated
        b = buf[i]
        value |= (b & 0x7F) << shift
        i += 1
        if not (b & 0x80):
            terminated = True
            break
        shift += 7

    length = i - start
    raw = buf[start:i]
    if not terminated:
        # 截断或过长: 值不可信
        cands = [LebCandidate("accepted", i, None, None,
                              False, False, "rejected",
                              "leb_too_long" if too_long else "truncated")]
        return LebToken(kind, start, raw, None, None, False, False,
                        not too_long, too_long, cands)

    # 有符号: 按实际终止位做符号扩展 (最高有效负载位即符号位)。
    if signed:
        sign_pos = shift + 6  # 终止字节 payload 最高位的位置
        if (value >> sign_pos) & 1:
            value |= -(1 << (sign_pos + 1))
        sv = value
        overflow = not _signed_in_range(sv, bits)
    else:
        overflow = value >= (1 << bits)
        sv = None

    # 非规范 (最短编码) 判定: 与该值的最短编码长度比较, 独立于越界。
    # 终止字节冗余: 正数多一个 0x00, 负数多一个 0x7F。
    if length > 1:
        if signed:
            canonical = len(encode_signed(sv)) == length
        else:
            canonical = len(encode_unsigned(value)) == length
    else:
        canonical = True
    cands: List[LebCandidate] = [
        LebCandidate("accepted", i, value, sv, canonical, overflow,
                     "accepted", None)
    ]
    if not canonical and not overflow and signed:
        alt_end = start + len(encode_signed(sv))
        cands.append(LebCandidate("canonical_alternative", alt_end, None, sv,
                                  True, False, "rejected", "noncanonical_redundant"))
    elif not canonical and not overflow:
        alt_end = start + len(encode_unsigned(value))
        cands.append(LebCandidate("canonical_alternative", alt_end, value, None,
                                  True, False, "rejected", "noncanonical_redundant"))

    return LebToken(kind, start, raw, value, sv, canonical, overflow,
                    False, False, cands)


def _signed_in_range(v: int, bits: int) -> bool:
    return -(1 << (bits - 1)) <= v < (1 << (bits - 1))


def encode_unsigned(value: int) -> bytes:
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def encode_signed(value: int) -> bytes:
    out = bytearray()
    more = True
    while more:
        b = value & 0x7F
        value >>= 7
        sign_bit = b & 0x40
        if (value == 0 and not sign_bit) or (value == -1 and sign_bit):
            more = False
        out.append(b | (0x80 if more else 0))
    return bytes(out)


# 便捷别名 (validator 使用)
encode_u32 = encode_unsigned
encode_s32 = encode_signed
