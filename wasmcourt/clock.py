from __future__ import annotations

from datetime import datetime, timedelta, timezone


class VirtualClock:
    """确定性虚拟时钟：固定起点 + 固定步长，保证测试可复放。"""

    def __init__(self, start: str = "2026-01-01T00:00:00Z", step_seconds: float = 1.0):
        self._now = datetime.fromisoformat(start.replace("Z", "+00:00"))
        if self._now.tzinfo is None:
            self._now = self._now.replace(tzinfo=timezone.utc)
        self._step = timedelta(seconds=step_seconds)

    def now(self) -> str:
        ts = self._now.isoformat().replace("+00:00", "Z")
        self._now += self._step
        return ts


class SystemClock:
    def now(self) -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
