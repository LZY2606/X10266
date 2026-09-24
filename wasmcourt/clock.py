"""虚拟时间。

测试与离线案例包使用固定起点 + 单调序号的虚拟时钟（不依赖墙上时钟）；
正常运行时使用真实时钟。两种时钟给出同形状的时间戳对象。
"""
from __future__ import annotations

import time

VIRTUAL_EPOCH_MS = 1_700_000_000_000  # 2023-11-14T22:13:20Z，固定虚拟起点
STEP_MS = 1000


class Clock:
    def __init__(self, virtual: bool = False, epoch_ms: int = VIRTUAL_EPOCH_MS):
        self.virtual = virtual
        self._epoch = epoch_ms
        self._tick = 0

    def now_ms(self) -> int:
        if self.virtual:
            value = self._epoch + self._tick * STEP_MS
            self._tick += 1
            return value
        return int(time.time() * 1000)

    def now_iso(self) -> str:
        return _iso(self.now_ms())


def _iso(ms: int) -> str:
    sec, rem = divmod(ms, 1000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(sec)) + f".{rem:03d}Z"
