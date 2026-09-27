"""LEB128 解码，区分编码不规范与数值越界。"""
from __future__ import annotations


def diag(code, message, offset=None, length=None, **details):
    d = {"code": code, "message": message}
    if offset is not None:
        d["offset"] = offset
        d["length"] = max(1, length or 1)
    d.update(details)
    return d


def _min_uleb_len(value):
    n = 1
    while value >> (7 * n):
        n += 1
    return n


def _min_sleb_len(value):
    count = 0
    v = value
    while True:
        byte = v & 0x7F
        v >>= 7
        count += 1
        if (v == 0 and not (byte & 0x40)) or (v == -1 and (byte & 0x40)):
            return count


def read_uleb(data, pos, max_bits=32):
    """读取无符号 LEB128。返回 (value, start, length, diag|None)。

    - leb_truncated: 字节流提前结束；
    - leb_value_overflow: 编码出的数值超过 max_bits（数值越界）；
    - leb_noncanonical: 数值合法但编码长于最短形式（编码不规范）。
    """
    start = pos
    result = 0
    shift = 0
    count = 0
    max_bytes = (max_bits + 6) // 7
    last_payload_bits = max_bits - 7 * (max_bytes - 1)
    while True:
        if pos >= len(data):
            return None, start, max(1, pos - start), diag(
                "leb_truncated", f"LEB128 truncated at byte {start}",
                start, max(1, pos - start))
        b = data[pos]
        pos += 1
        count += 1
        payload = b & 0x7F
        if count == max_bytes and (payload >> last_payload_bits):
            return None, start, count, diag(
                "leb_value_overflow",
                f"u{max_bits} LEB128 value exceeds {max_bits} bits",
                start, count, max_bits=max_bits)
        result |= payload << shift
        shift += 7
        if not (b & 0x80):
            break
        if count == max_bytes:
            return None, start, count, diag(
                "leb_value_overflow",
                f"u{max_bits} LEB128 continues past {max_bytes} bytes",
                start, count, max_bits=max_bits)
    if count > _min_uleb_len(result):
        return result, start, count, diag(
            "leb_noncanonical",
            f"non-canonical LEB128: value {result} encoded in {count} bytes",
            start, count, value=result, max_bits=max_bits)
    return result, start, count, None


def read_sleb(data, pos, max_bits=32):
    """读取有符号 LEB128，返回 (value, start, length, diag|None)。"""
    start = pos
    result = 0
    shift = 0
    count = 0
    max_bytes = (max_bits + 6) // 7
    while True:
        if pos >= len(data):
            return None, start, max(1, pos - start), diag(
                "leb_truncated", f"signed LEB128 truncated at byte {start}",
                start, max(1, pos - start))
        b = data[pos]
        pos += 1
        count += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if shift < max_bits and (b & 0x40):
                result |= -(1 << shift)
            break
        if count == max_bytes:
            return None, start, count, diag(
                "leb_value_overflow",
                f"s{max_bits} LEB128 continues past {max_bytes} bytes",
                start, count, max_bits=max_bits)
    lo, hi = -(1 << (max_bits - 1)), (1 << (max_bits - 1)) - 1
    if not (lo <= result <= hi):
        return None, start, count, diag(
            "leb_value_overflow",
            f"s{max_bits} LEB128 value {result} out of range",
            start, count, max_bits=max_bits)
    if count > _min_sleb_len(result):
        return result, start, count, diag(
            "leb_noncanonical",
            f"non-canonical signed LEB128: value {result} in {count} bytes",
            start, count, value=result, max_bits=max_bits)
    return result, start, count, None
