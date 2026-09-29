"""
RansomShield AI — Transport Retry & Exponential Backoff
Phase 3C: Agent ↔ Backend Real-Time Communication

Calculates bounded exponential backoff delays with jitter for resilient network retries.
Distinguishes between retriable server/network errors and permanent client errors.
"""

import random
from typing import Set

RETRIABLE_STATUS_CODES: Set[int] = {408, 429, 500, 502, 503, 504}


def compute_backoff_delay(
    attempt: int,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    jitter: bool = True,
) -> float:
    """
    Computes exponential backoff delay: base_delay * (2 ** attempt), capped at max_delay.
    Optionally applies uniform jitter (+/- 20%) to avoid thundering herd.
    """
    attempt = max(0, attempt)
    delay = min(max_delay, base_delay * (2 ** attempt))
    if jitter:
        jitter_factor = random.uniform(0.8, 1.2)
        delay = min(max_delay, delay * jitter_factor)
    return round(max(0.1, delay), 3)


def is_retriable_status(status_code: int) -> bool:
    """Returns True if the HTTP response status code indicates a temporary retriable failure."""
    return status_code in RETRIABLE_STATUS_CODES
