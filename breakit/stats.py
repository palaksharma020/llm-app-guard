"""Small statistics helpers for attack success rates."""

from __future__ import annotations

import math


def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a proportion (95% by default).

    Better than p ± z·sqrt(p(1-p)/n) at small n and at 0% or 100%: 0/30 gives (0, 0.114), not (0, 0).
    """
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))
