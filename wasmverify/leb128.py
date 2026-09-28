"""LEB128 codec that records exact byte spans and keeps diagnostics separate.

Two independent failure dimensions are reported:

* ``non_canonical`` - the integer is decodable but uses a redundant terminal
  byte (unsigned terminal payload 0x00, signed terminal 0x00/0x7F).
* ``overflow``        - payload bits exceed the target bit width.

``truncated`` records an unterminated encoding.  The value is always returned
(so callers can continue parsing) together with the exact consumed span.
"""
from __future__ import annotations

from dataclasses import dataclass

CONTINUATION = 0x80
PAYLOAD_MASK = 0x7F
SIGN_BIT = 0x40


@dataclass(frozen=True)
class Span:
    start: int
    end: int  # exclusive

    @property
    def length(self) -> int:
        return self.end - self.start

    def as_dict(self) -> dict:
        return {"start": self.start, "end": self.end, "length": self.length}


@dataclass(frozen=True)
class LebResult:
    value: int
    span: Span
    non_canonical: bool = False
    overflow: bool = False
    truncated: bool = False
    bytes_: tuple[int, ...] = ()

    @property
    def terminal_byte(self) -> int:
        return self.bytes_[-1] if self.bytes_ else 0

    def as_dict(self) -> dict:
        return {
            "value": self.value,
            "span": self.span.as_dict(),
            "non_canonical": self.non_canonical,
            "overflow": self.overflow,
            "truncated": self.truncated,
            "bytes": list(self.bytes_),
        }


def _max_bytes(bits: int) -> int:
    return (bits + 6) // 7


def encode_u(value: int, bits: int = 32) -> bytes:
    if value < 0:
        raise ValueError("unsigned LEB cannot encode a negative value")
    if value >= (1 << bits):
        raise ValueError(f"value {value} exceeds u{bits}")
    out = bytearray()
    while True:
        byte = value & PAYLOAD_MASK
        value >>= 7
        if value:
            out.append(byte | CONTINUATION)
        else:
            out.append(byte)
            return bytes(out)


def encode_s(value: int, bits: int = 32) -> bytes:
    if not (-(1 << (bits - 1)) <= value < (1 << (bits - 1))):
        raise ValueError(f"value {value} exceeds s{bits}")
    out = bytearray()
    while True:
        byte = value & PAYLOAD_MASK
        value >>= 7
        sign_bit_set = bool(byte & SIGN_BIT)
        if (value == 0 and not sign_bit_set) or (value == -1 and sign_bit_set):
            out.append(byte)
            return bytes(out)
        out.append(byte | CONTINUATION)


def decode_u(data: bytes, start: int, bits: int = 32) -> LebResult:
    max_bytes = _max_bytes(bits)
    result = 0
    shift = 0
    consumed = tuple()
    pos = start
    overflow = False
    truncated = False
    non_canonical = False
    while True:
        if pos >= len(data):
            truncated = True
            break
        byte = data[pos]
        consumed += (byte,)
        pos += 1
        payload = byte & PAYLOAD_MASK
        result |= payload << shift
        shift += 7
        if not (byte & CONTINUATION):
            break
        if len(consumed) == max_bytes:
            # Keep consuming the over-long encoding so the span covers it.
            overflow = True
        if len(consumed) >= max_bytes + 5:
            # Safety cap: clearly malformed stream, stop runaway consumption.
            truncated = True
            break
    if consumed:
        terminal = consumed[-1] & PAYLOAD_MASK
        if len(consumed) > max_bytes:
            overflow = True
        elif len(consumed) == max_bytes:
            allowed_bits = bits - 7 * (max_bytes - 1)
            if terminal >= (1 << allowed_bits):
                overflow = True
        if len(consumed) > 1 and terminal == 0:
            non_canonical = True
    return LebResult(
        value=result,
        span=Span(start, pos),
        non_canonical=non_canonical,
        overflow=overflow,
        truncated=truncated,
        bytes_=consumed,
    )


def decode_s(data: bytes, start: int, bits: int = 32) -> LebResult:
    max_bytes = _max_bytes(bits)
    result = 0
    shift = 0
    consumed = tuple()
    pos = start
    overflow = False
    truncated = False
    non_canonical = False
    while True:
        if pos >= len(data):
            truncated = True
            break
        byte = data[pos]
        consumed += (byte,)
        pos += 1
        payload = byte & PAYLOAD_MASK
        result |= payload << shift
        shift += 7
        if not (byte & CONTINUATION):
            break
        if len(consumed) >= max_bytes + 5:
            truncated = True
            break
    value = result
    if consumed and (consumed[-1] & SIGN_BIT):
        value |= -(1 << shift)
    if consumed:
        terminal = consumed[-1] & PAYLOAD_MASK
        n = len(consumed)
        if n > max_bytes:
            overflow = True
        elif n == max_bytes:
            remaining = bits - 7 * (max_bytes - 1)
            sign = (terminal >> (remaining - 1)) & 1
            upper = terminal >> remaining
            expected_upper = 0 if sign == 0 else (PAYLOAD_MASK >> remaining)
            if upper != expected_upper:
                overflow = True
        if n > 1 and terminal in (0x00, 0x7F):
            non_canonical = True
    return LebResult(
        value=value,
        span=Span(start, pos),
        non_canonical=non_canonical,
        overflow=overflow,
        truncated=truncated,
        bytes_=consumed,
    )
