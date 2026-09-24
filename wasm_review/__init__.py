"""Module boundary court: WebAssembly section/index/type-stack/proposal validation.

Domain units & coordinate bases (all offsets are byte coordinates in the
immutable source blob, inclusive start, exclusive end):
  * byte offset: integer, unit = byte, origin = 0 at first byte of source
  * every domain number preserves its original LEB128 representation;
    normalisation to an integer happens only in the derived layer.
"""

ALGORITHM_VERSION_PARSE = "parse:2026.1.0"
ALGORITHM_VERSION_VALIDATE = "validate:2026.1.0"
ALGORITHM_VERSION_DERIVE = "derive:2026.1.0"

WASM_MAGIC = b"\x00asm"
WASM_VERSION = b"\x01\x00\x00\x00"
