"""领域量的单位 / 坐标基准。

所有领域量在系统里都带坐标基准：字节偏移以 module byte 0 为原点，
LEB 宽度以 byte 计，数值以 u32/s33 位宽表示，栈深度以 operand slot 计。
"""
from __future__ import annotations

UNIT_BYTE_OFFSET = "byte@module[0]"
UNIT_BYTE_RANGE = "byte@module[0]:len"
UNIT_U32 = "u32"
UNIT_S33 = "s33"
UNIT_SLOTS = "operand_slot@vstack"
UNIT_FRAMES = "frame@cstack"
UNIT_SEQ = "ordinal@1"
UNIT_OPCODE = "opcode@instr_stream"


def byte_range(start: int, end: int) -> dict:
    """半开区间 [start, end)，坐标原点为模块第 0 字节。"""
    return {"start": int(start), "end": int(end), "unit": UNIT_BYTE_OFFSET}
