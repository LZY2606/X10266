"""虚拟时间与固定 seed 工具。

所有持久化时间戳都经过这里。测试通过环境变量 WASM_REVIEW_CLOCK
或 set_clock() 设置确定性时钟; 默认使用真实 UTC。
系统不使用随机数生成身份; seed 仅用于可复现的展示布局抖动。
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Callable, Optional

FIXED_SEED = 20260924
_clock: Optional[Callable[[], datetime]] = None


def set_clock(fn: Optional[Callable[[], datetime]]) -> None:
    global _clock
    _clock = fn


def now_iso() -> str:
    if _clock is not None:
        dt = _clock()
    else:
        override = os.environ.get("WASM_REVIEW_CLOCK")
        if override:
            dt = datetime.fromisoformat(override)
        else:
            dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def epoch_us(iso: str) -> int:
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1_000_000)
