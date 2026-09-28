from __future__ import annotations

from typing import Any

import numpy as np


def encode_uleb(value: int) -> bytes:
    if value < 0:
        raise ValueError("ULEB value must be non-negative")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def encode_sleb(value: int, max_bits: int) -> bytes:
    if max_bits <= 0:
        raise ValueError("max_bits must be positive")
    out = bytearray()
    more = True
    while more:
        byte = value & 0x7F
        value >>= 7
        sign = byte & 0x40
        done_positive = value == 0 and sign == 0
        done_negative = value == -1 and sign != 0
        if done_positive or done_negative:
            more = False
            out.append(byte)
        else:
            out.append(byte | 0x80)
    return bytes(out)


def decode_leb(data: bytes, offset: int, max_bits: int, signed: bool) -> dict[str, Any]:
    """Decode one bounded LEB128 token without treating non-canonical padding as a value overflow."""
    max_bytes = int(np.ceil(np.int64(max_bits) / np.int64(7)))
    start = offset
    result = np.int64(0)
    shift = 0
    consumed = 0
    terminated = False
    termination_index = None
    raw = bytearray()

    while consumed < max_bytes:
        if offset >= len(data):
            return {
                "kind": "truncated",
                "start": start,
                "end": offset,
                "raw": bytes(raw),
                "max_bytes": max_bytes,
                "candidates": [],
            }
        byte = data[offset]
        raw.append(byte)
        payload = byte & 0x7F

        usable_bits = min(7, max_bits - shift)
        kept_payload = payload & ((1 << usable_bits) - 1)
        dropped = payload ^ kept_payload

        if signed:
            if shift + 7 < 64:
                result = np.int64(np.int64(result) | np.int64(kept_payload << shift))
            sign_bit = bool(kept_payload & (1 << (usable_bits - 1)))
            if sign_bit and shift + usable_bits < 64:
                result = np.int64(
                    int(result) | (-1 << (shift + usable_bits))
                )
        else:
            result = np.int64(np.int64(result) | np.int64(kept_payload << shift))

        offset += 1
        consumed += 1

        if not (byte & 0x80):
            terminated = True
            termination_index = consumed - 1
            break
        shift += 7

    if not terminated:
        return {
            "kind": "truncated",
            "start": start,
            "end": offset,
            "raw": bytes(raw),
            "max_bytes": max_bytes,
            "candidates": [],
        }

    overflow = False
    overflow_basis = None
    if signed:
        min_value = -(1 << (max_bits - 1))
        max_value = (1 << (max_bits - 1)) - 1
        overflow = not (min_value <= int(result) <= max_value)
        overflow_basis = {"min": min_value, "max": max_value, "bits": max_bits}
    else:
        max_value = (1 << max_bits) - 1
        overflow = dropped != 0 or int(result) < 0 or int(result) > max_value
        overflow_basis = {"min": 0, "max": max_value, "bits": max_bits}

    canonical_raw = encode_sleb(int(result), max_bits) if signed else encode_uleb(int(result))
    canonical = bytes(raw) == canonical_raw and not overflow
    noncanonical = not overflow and not canonical

    candidates = [
        {
            "value": int(result),
            "encoding": "non-canonical" if noncanonical else "canonical",
            "raw": bytes(raw).hex(),
            "source_range": [start, offset],
        }
    ]
    if noncanonical and termination_index is not None:
        # The same bytes uniquely decode to one arithmetic value; the rejected
        # candidate is their canonical re-encoding, making the boundary explicit.
        candidates.append(
            {
                "value": int(result),
                "encoding": "canonical",
                "raw": canonical_raw.hex(),
                "source_range": [start, start + len(canonical_raw)],
            }
        )

    kind = "ok"
    if noncanonical:
        kind = "noncanonical"
    if overflow:
        kind = "out_of_range"

    return {
        "kind": kind,
        "start": start,
        "end": offset,
        "raw": bytes(raw),
        "value": int(result),
        "canonical_raw": canonical_raw.hex(),
        "canonical": canonical,
        "overflow": overflow,
        "overflow_basis": overflow_basis,
        "max_bytes": max_bytes,
        "termination_index": termination_index,
        "candidates": candidates,
    }
