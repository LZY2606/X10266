"""严格 LEB128（无符号 u32）解码。

两类问题严格分离（验收硬要求）：
  noncanonical —— 编码不规范（冗余：最小长度条件是最高 7 位组非零；
                  或表示超长：u32 最多 5 个 7 位组），属编码类问题；
  out_of_range —— 数值超出 u32（integer too large），属数值类问题。
二者可以独立出现：2 字节写 0 是 noncanonical 但数值合法；5 字节写 2^32
数值越界但字节长度合法；6 字节写 0 是 noncanonical(representation too
long) 但数值仍在范围内。
截断（终止字节前输入结束）单独报 truncated，不猜测候选值。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

U32_MAX = 0xFFFFFFFF
MAX_GROUPS = 5


@dataclass
class LebResult:
    value: Optional[int]
    width: int
    raw: list[int]
    noncanonical: bool = False
    out_of_range: bool = False
    truncated: bool = False
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "value": self.value,
            "width": self.width,
            "raw7": self.raw,
            "noncanonical": self.noncanonical,
            "out_of_range": self.out_of_range,
            "truncated": self.truncated,
            "note": self.note,
        }


def decode_u32(data: bytes, pos: int = 0) -> LebResult:
    groups: list[int] = []
    raw: list[int] = []
    start = pos
    i = pos
    while True:
        if i >= len(data):
            return LebResult(None, i - start, raw, truncated=True,
                             note="continuation byte expected, end of input")
        byte = data[i]
        groups.append(byte & 0x7F)
        raw.append(byte & 0x7F)
        i += 1
        if byte & 0x80 == 0:
            break
        if len(groups) >= MAX_GROUPS:
            # 终止字节仍带继续位 -> representation too long：
            # 先精确定位终止字节，宽度才可以作“最小失败字节范围”。
            terminated = False
            while i < len(data):
                b = data[i]
                groups.append(b & 0x7F)
                raw.append(b & 0x7F)
                i += 1
                if b & 0x80 == 0:
                    terminated = True
                    break
            value = _join(groups)
            if not terminated:
                return LebResult(None, i - start, raw, noncanonical=True,
                                 truncated=True,
                                 note="representation too long and input ended")
            return LebResult(None if value > U32_MAX else value, i - start, raw,
                             noncanonical=True, out_of_range=value > U32_MAX,
                             note="integer representation too long for u32 "
                                  "(max 5 groups)")
    return _assemble(groups, raw, i - start)


def _join(groups: list[int]) -> int:
    value = 0
    for shift, group in enumerate(groups):
        value |= group << (7 * shift)
    return value


def _assemble(groups: list[int], raw: list[int], width: int) -> LebResult:
    value = _join(groups)
    n = len(groups)
    used = 32 - 7 * (n - 1)
    last = groups[-1]
    if last & ~((1 << used) - 1):
        return LebResult(None, width, raw, out_of_range=True,
                         note=f"integer too large for u32: {value} > {U32_MAX}")
    if n > 1 and last == 0:
        return LebResult(value, width, raw, noncanonical=True,
                         note="overlong encoding: highest group is zero "
                              "(value is uniquely decodable)")
    return LebResult(value, width, raw)
