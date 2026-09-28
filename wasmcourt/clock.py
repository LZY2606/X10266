"""Deterministic virtual clock.

Production code uses a real clock; the replay engine and tests inject a fixed
seed-driven clock so every event timestamp is reproducible offline.
"""
from __future__ import annotations

import time
from dataclasses import dataclass


class Clock:
    def now_ms(self) -> int:
        return int(time.time() * 1000)


@dataclass
class VirtualClock:
    """Monotonic, seed-derived clock. No wall clock, no network."""

    epoch_ms: int = 1_700_000_000_000
    step_ms: int = 7
    _ticks: int = 0

    def now_ms(self) -> int:
        value = self.epoch_ms + self._ticks * self.step_ms
        self._ticks += 1
        return value
