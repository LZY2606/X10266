"""LEB128 decoding that keeps the raw encoding and separates
non-canonical encodings from numeric overflow.

Judgment rules (machine-readable via `diagnostics`):
- `leb128.noncanonical`: value fits, but the encoding is not the minimal one
  (trailing 0x00/0x7F padding bytes or a redundant final sign byte).
- `leb128.overflow`: the encoded magnitude exceeds the target bit width.
  This is reported independently of canonicality.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LebResult:
    ok: bool
    value: int
    offset: int            # absolute offset of first byte
    size: int              # number of bytes consumed
    raw: bytes             # original encoding bytes, preserved verbatim
    diagnostics: list[dict] = field(default_factory=list)

    @property
    def byte_range(self) -> tuple[int, int]:
        return (self.offset, self.size)


def _diag(kind: str, offset: int, size: int, **extra) -> dict:
    d = {"kind": kind, "byte_range": [offset, size]}
    d.update(extra)
    return d


def decode_u(data: bytes, offset: int, max_bits: int = 32) -> LebResult:
    """Decode unsigned LEB128 at `offset` bounded to `max_bits`."""
    result = 0
    shift = 0
    pos = offset
    diags: list[dict] = []
    max_bytes = (max_bits + 6) // 7
    while True:
        if pos >= len(data):
            return LebResult(False, 0, offset, pos - offset,
                             data[offset:pos],
                             [_diag("leb128.truncated", offset, pos - offset)])
        byte = data[pos]
        pos += 1
        payload = byte & 0x7F
        result |= payload << shift
        nbytes = pos - offset
        if byte & 0x80 == 0:
            # terminal byte
            if nbytes > max_bytes:
                diags.append(_diag("leb128.overflow", offset, nbytes,
                                   max_bits=max_bits, value=result))
            elif nbytes == max_bytes and payload >= (1 << (max_bits - shift)):
                diags.append(_diag("leb128.overflow", offset, nbytes,
                                   max_bits=max_bits, value=result))
            if result >= (1 << max_bits):
                if not any(d["kind"] == "leb128.overflow" for d in diags):
                    diags.append(_diag("leb128.overflow", offset, nbytes,
                                       max_bits=max_bits, value=result))
            # canonicality: minimal encoding check
            if nbytes > 1 and payload == 0:
                diags.append(_diag("leb128.noncanonical", offset, nbytes,
                                   reason="zero-padding", value=result))
            elif nbytes > 1 and result < (1 << (7 * (nbytes - 1))):
                diags.append(_diag("leb128.noncanonical", offset, nbytes,
                                   reason="not-minimal", value=result))
            return LebResult(True, result, offset, nbytes,
                             data[offset:pos], diags)
        shift += 7
        if nbytes >= max_bytes + 1:
            diags.append(_diag("leb128.overflow", offset, nbytes,
                               max_bits=max_bits, value=result))
            return LebResult(False, result, offset, nbytes,
                             data[offset:pos], diags)


def decode_s(data: bytes, offset: int, max_bits: int = 32) -> LebResult:
    """Decode signed LEB128 at `offset` bounded to `max_bits`."""
    result = 0
    shift = 0
    pos = offset
    diags: list[dict] = []
    max_bytes = (max_bits + 6) // 7
    while True:
        if pos >= len(data):
            return LebResult(False, 0, offset, pos - offset,
                             data[offset:pos],
                             [_diag("leb128.truncated", offset, pos - offset)])
        byte = data[pos]
        pos += 1
        payload = byte & 0x7F
        result |= payload << shift
        shift += 7
        nbytes = pos - offset
        if byte & 0x80 == 0:
            if shift < 64 and (byte & 0x40):
                result |= -(1 << shift)
            lo = -(1 << (max_bits - 1))
            hi = (1 << (max_bits - 1)) - 1
            if result < lo or result > hi or nbytes > max_bytes:
                diags.append(_diag("leb128.overflow", offset, nbytes,
                                   max_bits=max_bits, value=result))
            if nbytes > 1:
                # canonical: a shorter encoding exists?
                minimal = _signed_min_size(result, max_bits)
                if minimal < nbytes_greater(nbytes, minimal):
                    diags.append(_diag("leb128.noncanonical", offset, nbytes,
                                       reason="not-minimal", value=result))
            return LebResult(True, result, offset, nbytes,
                             data[offset:pos], diags)
        if nbytes >= max_bytes + 1:
            diags.append(_diag("leb128.overflow", offset, nbytes,
                               max_bits=max_bits, value=result))
            return LebResult(False, result, offset, nbytes,
                             data[offset:pos], diags)


def nbytes_greater(a: int, b: int) -> bool:
    return a > b


def _signed_min_size(value: int, max_bits: int) -> int:
    for n in range(1, (max_bits + 6) // 7 + 1):
        bits = 7 * n
        lo = -(1 << (bits - 1))
        hi = (1 << (bits - 1)) - 1
        if lo <= value <= hi:
            return n
    return (max_bits + 6) // 7
