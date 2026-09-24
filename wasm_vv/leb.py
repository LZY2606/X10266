"""LEB128 编解码：区分 非规范编码(noncanonical_leb) 与 数值越界(value_overflow)。"""
from __future__ import annotations


def encode_uleb(value: int) -> bytes:
    if value < 0:
        raise ValueError("uleb requires non-negative")
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def encode_sleb(value: int) -> bytes:
    out = bytearray()
    more = True
    while more:
        b = value & 0x7F
        value >>= 7
        if (value == 0 and not (b & 0x40)) or (value == -1 and (b & 0x40)):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)


class LebError(Exception):
    def __init__(self, code: str, start: int, end: int, raw: bytes):
        super().__init__(code)
        self.code = code            # truncated_leb | value_overflow
        self.start = start
        self.end = end
        self.raw = raw


def read_uleb(data: bytes, pos: int, max_bits: int) -> tuple[int, bytes, bool, int]:
    """返回 (value, raw, canonical, new_pos)。越界/截断抛 LebError。

    非规范编码不抛错：返回 canonical=False，由调用方记录 noncanonical_leb 诊断，
    与 value_overflow 严格分开。
    """
    start = pos
    nbytes = (max_bits + 6) // 7
    result = 0
    shift = 0
    for i in range(nbytes):
        if pos >= len(data):
            raise LebError("truncated_leb", start, pos, data[start:pos])
        b = data[pos]
        pos += 1
        if i == nbytes - 1:
            allowed = max_bits - 7 * i
            if (b & 0x80) or (b & 0x7F) >> allowed:
                raise LebError("value_overflow", start, pos, data[start:pos])
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            raw = data[start:pos]
            return result, raw, raw == encode_uleb(result), pos
    raise LebError("value_overflow", start, pos, data[start:pos])


def read_sleb(data: bytes, pos: int, max_bits: int) -> tuple[int, bytes, bool, int]:
    start = pos
    nbytes = (max_bits + 6) // 7
    result = 0
    shift = 0
    for _ in range(nbytes):
        if pos >= len(data):
            raise LebError("truncated_leb", start, pos, data[start:pos])
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if shift < max_bits and (b & 0x40):
                result |= -(1 << shift)
            raw = data[start:pos]
            if result < -(1 << (max_bits - 1)) or result > (1 << (max_bits - 1)) - 1:
                raise LebError("value_overflow", start, pos, raw)
            return result, raw, raw == encode_sleb(result), pos
    raise LebError("value_overflow", start, pos, data[start:pos])
