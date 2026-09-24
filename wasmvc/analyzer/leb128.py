"""Canonical-aware LEB128 decoding.

The verifier distinguishes three independent failure kinds required by the
domain rules:

* ``TRUNCATED``        - the byte stream ends before the integer terminates
                         (spec name: "unexpected end");
* ``REP_TOO_LONG``     - the integer representation uses more bytes than
                         permitted for its width (spec name:
                         "integer representation too long");
* ``NONCANONICAL``     - the representation is length-legal but a sign/value
                         bit forces extra bytes (spec name: "integer too
                         long");
* ``VALUE_OUT_OF_RANGE`` - decoded magnitude cannot fit the target width
                          (spec name: "integer too large").

"非规范 LEB128 与数值越界分开" is therefore represented by two separate,
independent flags (``noncanonical`` and ``out_of_range``) that can both occur
on the same decode and never collapse into one generic error.
"""
from __future__ import annotations

from dataclasses import dataclass


TRUNCATED = "TRUNCATED"
REP_TOO_LONG = "REP_TOO_LONG"
NONCANONICAL = "NONCANONICAL"
VALUE_OUT_OF_RANGE = "VALUE_OUT_OF_RANGE"

MAX_BYTES = {32: 5, 33: 5, 64: 10}


@dataclass
class LebResult:
    value: int
    start: int
    end: int
    raw: bytes
    signed: bool
    width: int
    truncated: bool
    rep_too_long: bool
    noncanonical: bool
    out_of_range: bool

    @property
    def ok(self) -> bool:
        return not (
            self.truncated or self.rep_too_long or self.noncanonical or self.out_of_range
        )

    def diagnoses(self) -> list[str]:
        out: list[str] = []
        if self.truncated:
            out.append(TRUNCATED)
        if self.rep_too_long:
            out.append(REP_TOO_LONG)
        if self.noncanonical:
            out.append(NONCANONICAL)
        if self.out_of_range:
            out.append(VALUE_OUT_OF_RANGE)
        return out

    def as_dict(self) -> dict:
        return {
            "value": self.value,
            "start": self.start,
            "end": self.end,
            "raw_hex": self.raw.hex(),
            "signed": self.signed,
            "width": self.width,
            "truncated": self.truncated,
            "rep_too_long": self.rep_too_long,
            "noncanonical": self.noncanonical,
            "out_of_range": self.out_of_range,
            "diagnoses": self.diagnoses(),
        }


def _min_uleb_bytes(value: int) -> int:
    if value == 0:
        return 1
    n = 0
    while value > 0:
        value >>= 7
        n += 1
    return n


def _min_sleb_bytes(value: int, width: int) -> int:
    n = 1
    while True:
        limit = 1 << (7 * n - 1)
        if -limit <= value < limit:
            return n
        n += 1
        if n > MAX_BYTES[width]:
            return MAX_BYTES[width]


def decode_uleb(data: bytes, start: int, width: int = 32) -> LebResult:
    max_bytes = MAX_BYTES[width]
    result = 0
    shift = 0
    count = 0
    pos = start
    truncated = False
    rep_too_long = False
    while True:
        if pos >= len(data):
            truncated = True
            break
        byte = data[pos]
        count += 1
        payload = byte & 0x7F
        result |= payload << shift
        pos += 1
        if byte & 0x80 == 0:
            break
        # another byte follows
        if count >= max_bytes:
            # continuation bit on the last permitted byte, or stream end
            rep_too_long = True
            if pos >= len(data):
                truncated = True
            else:
                # consume one byte so the caller does not rescan it
                pass
            break
        shift += 7
    raw = data[start:pos]
    noncanonical = False
    out_of_range = False
    if not truncated and not rep_too_long:
        noncanonical = count > _min_uleb_bytes(result)
        limit = 1 << width
        out_of_range = result >= limit
    return LebResult(
        value=result,
        start=start,
        end=pos,
        raw=raw,
        signed=False,
        width=width,
        truncated=truncated,
        rep_too_long=rep_too_long,
        noncanonical=noncanonical,
        out_of_range=out_of_range,
    )


def decode_sleb(data: bytes, start: int, width: int = 32) -> LebResult:
    max_bytes = MAX_BYTES[width]
    result = 0
    shift = 0
    count = 0
    pos = start
    truncated = False
    rep_too_long = False
    last_payload = 0
    while True:
        if pos >= len(data):
            truncated = True
            break
        byte = data[pos]
        count += 1
        last_payload = byte & 0x7F
        result |= last_payload << shift
        pos += 1
        shift += 7
        if byte & 0x80 == 0:
            break
        if count >= max_bytes:
            rep_too_long = True
            if pos >= len(data):
                truncated = True
            break
    raw = data[start:pos]
    noncanonical = False
    out_of_range = False
    value = result
    if not truncated and not rep_too_long:
        signed_bits = 7 * count
        if last_payload & 0x40:
            value = result - (1 << signed_bits)
        if count == max_bytes:
            # high-bit group: every bit outside the signed width must be a
            # copy of the sign bit, otherwise magnitude overflows.
            sign_bit = (last_payload >> 6) & 1
            allowed_high = (0x7F if sign_bit else 0x00)
            low_group_bits = width - 7 * (max_bytes - 1)  # 4 for 32/33, 1 for 64
            mask = (1 << low_group_bits) - 1
            required = (allowed_high & ~mask) | (last_payload & mask)
            if required != last_payload:
                out_of_range = True
        if not out_of_range and width < 64:
            if value >= (1 << (width - 1)) or value < -(1 << (width - 1)):
                out_of_range = True
        if not out_of_range:
            noncanonical = count > _min_sleb_bytes(value, width)
    return LebResult(
        value=value,
        start=start,
        end=pos,
        raw=raw,
        signed=True,
        width=width,
        truncated=truncated,
        rep_too_long=rep_too_long,
        noncanonical=noncanonical,
        out_of_range=out_of_range,
    )


def decode(data: bytes, start: int, signed: bool, width: int = 32) -> LebResult:
    return decode_sleb(data, start, width) if signed else decode_uleb(data, start, width)
