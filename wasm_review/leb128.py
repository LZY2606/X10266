"""LEB128 decoding with *separated* diagnostics.

Three distinct failures are reported as separate codes (they must never be
collapsed into one "bad LEB"):

* ``leb_truncated``    the byte stream ends before the terminating byte
* ``leb_overflow``     the represented value does not fit the target width
* ``leb_noncanonical`` the value fit, but the encoding used extra bytes

A noncanonical encoding is a representation problem; overflow is a numeric
range problem. They are independently detectable and independently stored.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class LebValue:
    """A decoded LEB128 integer keeping its original representation."""

    value: int
    kind: str          # "u32" | "u64" | "s32" | "s64"
    start: int
    end: int
    raw: bytes
    status: str        # "ok" | "noncanonical" | "overflow" | "truncated"
    code: str | None = None

    def to_diag(self) -> dict:
        return {
            "value": self.value,
            "kind": self.kind,
            "byte_start": self.start,
            "byte_end": self.end,
            "raw_hex": self.raw.hex(),
            "encoding_status": self.status,
            "diagnostic_code": self.code,
        }


def _bits_signed(kind: str) -> tuple[int, bool]:
    return {
        "u32": (32, False),
        "u64": (64, False),
        "s32": (32, True),
        "s64": (64, True),
    }[kind]


def _sign_extend(raw_value: int, used_bits: int) -> int:
    sign = 1 << (used_bits - 1)
    return (raw_value & ((1 << used_bits) - 1) ^ sign) - sign


def read_leb(buf: bytes, pos: int, kind: str = "u32") -> LebValue:
    bits, signed = _bits_signed(kind)
    max_bytes = (bits + 6) // 7
    start = pos
    result = 0
    shift = 0
    count = 0
    terminated = False
    while count < max_bytes:
        if pos >= len(buf):
            return LebValue(result, kind, start, pos, buf[start:pos],
                            "truncated", "leb_truncated")
        byte = buf[pos]
        pos += 1
        count += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if byte & 0x80 == 0:
            terminated = True
            break

    if not terminated:
        # All max-length bytes still continue. End of buffer is truncation;
        # another continuation byte present means the integer is too long.
        code = "leb_truncated" if pos >= len(buf) else "leb_overflow"
        return LebValue(result, kind, start, pos, buf[start:pos],
                        "truncated" if code == "leb_truncated" else "overflow",
                        code)

    raw = buf[start:pos]
    last_payload = raw[-1] & 0x7F

    if not signed:
        value = result
        # Numeric range: bits contributed by the final payload above `bits`.
        if shift > bits and last_payload >> (bits - (shift - 7)):
            return LebValue(value, kind, start, pos, raw,
                            "overflow", "leb_overflow")
        if count > 1 and last_payload == 0:
            return LebValue(value, kind, start, pos, raw,
                            "noncanonical", "leb_noncanonical")
        return LebValue(value, kind, start, pos, raw, "ok", None)

    value = _sign_extend(result, shift)
    lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    if not (lo <= value <= hi):
        return LebValue(value, kind, start, pos, raw,
                        "overflow", "leb_overflow")
    # Canonical-ness: dropping the last byte must change the sign-extended
    # value, otherwise that byte was pure redundant sign extension.
    if count > 1:
        truncated = _sign_extend(result & ((1 << (shift - 7)) - 1),
                                 shift - 7)
        if truncated == value:
            return LebValue(value, kind, start, pos, raw,
                            "noncanonical", "leb_noncanonical")
    return LebValue(value, kind, start, pos, raw, "ok", None)


def enc_u(value: int) -> bytes:
    """Canonical unsigned LEB128 (used by the case-pack sample builders)."""
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def enc_s(value: int) -> bytes:
    """Canonical signed LEB128."""
    out = bytearray()
    more = True
    while more:
        b = value & 0x7F
        value >>= 7
        sign = b & 0x40
        if (value == 0 and not sign) or (value == -1 and sign):
            more = False
            out.append(b)
        else:
            out.append(b | 0x80)
    return bytes(out)
