from datetime import datetime, timedelta, timezone


class Clock:
    """Real-time clock (production default)."""

    def now(self) -> str:
        return datetime.now(timezone.utc).isoformat()


class FixedClock(Clock):
    """Deterministic virtual clock for tests and replay."""

    def __init__(self, start: str = "2026-01-01T00:00:00+00:00", step_seconds: int = 1):
        self._t = datetime.fromisoformat(start)
        self._step = timedelta(seconds=step_seconds)

    def now(self) -> str:
        t = self._t
        self._t += self._step
        return t.isoformat()
