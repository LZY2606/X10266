"""LEB128 decoding that keeps the raw encoding and separates
non-canonical (overlong) encodings from genuine out-of-range values."""
from __future__ import annotations

from dataclasses import dataclass


class LebError(Exception):
    def __init__(self, kind: str, start: int, end: int, message: str):
        super().__init__(message)
        self.kind = kind  # truncated_leb | integer_out_of_range
        self.start = start
        self.end = end


@dataclass
class Leb:
    value: int
    start: int
    end: int
    raw: bytes
    canonical: bool


def _min_u_len(value: int) -> int:
    n = 1
    v = value >> 7
    while v:
        n += 1
        v >>= 7
    return n


def _min_s_len(value: int) -> int:
    n = 0
    v = value
    while True:
        byte = v & 0x7F
        v >>= 7
        n += 1
        if (v == 0 and not (byte & 0x40)) or (v == -1 and (byte & 0x40)):
            return n


def decode_unsigned(data: bytes, pos: int, max_bits: int = 32) -> Leb:
    start = pos
    value = 0
    shift = 0
    max_bytes = (max_bits + 6) // 7
    while True:
        if pos >= len(data):
            raise LebError("truncated_leb", start, pos, "truncated LEB128")
        byte = data[pos]
        pos += 1
        index = pos - start
        if index > max_bytes:
            raise LebError(
                "integer_out_of_range", start, pos,
                f"LEB128 longer than {max_bytes} bytes for u{max_bits}",
            )
        payload = byte & 0x7F
        if index == max_bytes:
            extra_bits = 7 * max_bytes - max_bits
            if payload >> (7 - extra_bits):
                raise LebError(
                    "integer_out_of_range", start, pos,
                    f"LEB128 value does not fit u{max_bits}",
                )
            if byte & 0x80:
                raise LebError(
                    "integer_out_of_range", start, pos,
                    f"LEB128 continuation beyond {max_bytes} bytes for u{max_bits}",
                )
        value |= payload << shift
        shift += 7
        if not (byte & 0x80):
            break
    raw = bytes(data[start:pos])
    return Leb(value, start, pos, raw, len(raw) == _min_u_len(value))


def decode_signed(data: bytes, pos: int, max_bits: int = 64) -> Leb:
    start = pos
    value = 0
    shift = 0
    max_bytes = (max_bits + 6) // 7
    while True:
        if pos >= len(data):
            raise LebError("truncated_leb", start, pos, "truncated LEB128")
        byte = data[pos]
        pos += 1
        index = pos - start
        if index > max_bytes:
            raise LebError(
                "integer_out_of_range", start, pos,
                f"LEB128 longer than {max_bytes} bytes for s{max_bits}",
            )
        value |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            if shift < max_bits and (byte & 0x40):
                value |= -(1 << shift)
            lo = -(1 << (max_bits - 1))
            hi = (1 << (max_bits - 1)) - 1
            if not (lo <= value <= hi):
                raise LebError(
                    "integer_out_of_range", start, pos,
                    f"signed LEB128 value does not fit s{max_bits}",
                )
            raw = bytes(data[start:pos])
            return Leb(value, start, pos, raw, len(raw) == _min_s_len(value))
