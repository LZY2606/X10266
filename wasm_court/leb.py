from dataclasses import dataclass


@dataclass(frozen=True)
class LebResult:
    value: int | None
    start: int
    end: int
    bytes_hex: str
    canonical: bool
    status: str
    diagnostic: str | None = None

    def as_event(self, leb_id: str, signed: bool, width: int, purpose: str) -> dict:
        return {
            "id": leb_id,
            "kind": "leb128",
            "lebId": leb_id,
            "value": self.value,
            "unit": "unsigned-integer" if not signed else "signed-integer",
            "coordinateBasis": "zero-based-half-open-byte-offset",
            "byteRange": {"start": self.start, "end": self.end, "unit": "byte"},
            "rawBytesHex": self.bytes_hex,
            "signed": signed,
            "width": width,
            "canonical": self.canonical,
            "status": self.status,
            "diagnostic": self.diagnostic,
            "purpose": purpose,
        }


def _canonical_unsigned(data: bytes, value: int) -> bool:
    if not data:
        return False
    if len(data) == 1:
        return True
    had_penultimate_continuation = data[-2] & 0x80 != 0
    needs_extra_byte = value >= 1 << (7 * (len(data) - 1))
    return had_penultimate_continuation and needs_extra_byte


def _canonical_signed(data: bytes, value: int) -> bool:
    if not data:
        return False
    if len(data) == 1:
        return True
    last = data[-1] & 0x7F
    if last & 0x40:
        return last != 0x7F or data[-2] & 0x80 == 0
    return last != 0x00 or data[-2] & 0x80 == 0


def read_u32_leb(data: bytes, start: int) -> tuple[LebResult, int]:
    max_bytes = 5
    raw = bytearray()
    value = 0
    shift = 0
    pos = start
    while pos < len(data) and len(raw) < max_bytes:
        byte = data[pos]
        raw.append(byte)
        pos += 1
        chunk = byte & 0x7F
        if len(raw) == max_bytes and chunk > 0x0F:
            return (
                LebResult(None, start, pos, raw.hex(), False, "range_error",
                          "LEB128 numeric value exceeds u32; this is distinct from non-canonical padding"),
                pos,
            )
        value |= chunk << shift
        if byte & 0x80 == 0:
            canonical = _canonical_unsigned(bytes(raw), value)
            status = "ok" if canonical else "noncanonical"
            diagnostic = None if canonical else "LEB128 has unnecessary continuation bytes"
            return LebResult(value, start, pos, raw.hex(), canonical, status, diagnostic), pos
        shift += 7
    if pos >= len(data):
        return LebResult(None, start, pos, raw.hex(), False, "truncated",
                         "LEB128 ends before its terminator"), pos
    return LebResult(None, start, pos, raw.hex(), False, "malformed",
                     "LEB128 continuation is too long"), pos


def read_s32_leb(data: bytes, start: int) -> tuple[LebResult, int]:
    max_bytes = 5
    raw = bytearray()
    value = 0
    shift = 0
    pos = start
    while pos < len(data) and len(raw) < max_bytes:
        byte = data[pos]
        raw.append(byte)
        pos += 1
        chunk = byte & 0x7F
        value |= chunk << shift
        shift += 7
        if byte & 0x80 == 0:
            if len(raw) == max_bytes and chunk & 0x70:
                value -= 1 << shift
            elif chunk & 0x40:
                value -= 1 << shift
            canonical = _canonical_signed(bytes(raw), value)
            return LebResult(value, start, pos, raw.hex(), canonical,
                             "ok" if canonical else "noncanonical"), pos
    return LebResult(None, start, pos, raw.hex(), False, "truncated"), pos
