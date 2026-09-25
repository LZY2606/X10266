"""Wasm module parsing and validation core.

Domain rules enforced here (kept as separate, machine-readable classes):
  * non-canonical LEB128 encodings are reported apart from numeric overflow
  * the polymorphic stack only applies inside unreachable regions
  * an opcode from a disabled proposal reports capability-missing,
    never unknown-byte
"""

from . import leb128, parser, proposals, validate, encode  # noqa: F401
