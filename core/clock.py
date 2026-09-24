"""Deterministic clock abstraction to keep tests free of wall-clock time."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


class Clock:
    def now(self) -> str:
        raise NotImplementedError


class SystemClock(Clock):
    def now(self) -> str:
        return datetime.now(timezone.utc).isoformat()


class VirtualClock(Clock):
    """Fixed-start, fixed-step clock. Every call advances one step."""

    def __init__(self, start: str = "2026-01-01T00:00:00+00:00", step_seconds: int = 1):
        self._t = datetime.fromisoformat(start)
        self._step = timedelta(seconds=step_seconds)

    def now(self) -> str:
        value = self._t.isoformat()
        self._t += self._step
        return value
