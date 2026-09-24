"""Deterministic virtual time and fixed-seed randomness for replay/tests."""
from __future__ import annotations

import numpy as np


class VirtualClock:
    """Monotonic, controllable clock. Tests pin a base epoch and step it."""

    def __init__(self, epoch_ms: int = 0, step_ms: int = 1):
        self._now = int(epoch_ms)
        self._step = int(step_ms)

    def now_ms(self) -> int:
        return self._now

    def tick(self) -> int:
        self._now += self._step
        return self._now


def seeded_rng(seed: int) -> np.random.Generator:
    return np.random.default_rng(seed)


# Fixed seed mandated for the offline case pack / tests.
FIXED_SEED = 20260919
