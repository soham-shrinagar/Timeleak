"""
Core timing measurement engine for TimeLeak.

Uses time.perf_counter() (monotonic, high-resolution) — never time.time().
"""

import time
from typing import Optional

import numpy as np
import requests


def measure_timing(
    base_url: str,
    endpoint: str,
    token: str,
    samples: int = 300,
    warmup: int = 10,
    timeout: float = 10.0,
    session: Optional[requests.Session] = None,
) -> np.ndarray:
    """
    Measure response latency for repeated POST requests with the same token guess.

    Returns an array of timings in milliseconds (one per sample).
    Warm-up requests are sent first (untimed) to avoid cold-start contamination
    from DNS, TCP handshake, and server JIT warm-up.

    Pass a shared `session` when comparing candidates at the same position so
    TCP state does not skew relative rankings.
    """
    url = base_url.rstrip('/') + endpoint
    payload = {'token': token}
    own_session = session is None
    if own_session:
        session = requests.Session()

    for _ in range(warmup):
        try:
            session.post(url, json=payload, timeout=timeout)
        except requests.RequestException:
            pass

    timings = []
    for _ in range(samples):
        start = time.perf_counter()
        try:
            session.post(url, json=payload, timeout=timeout)
        except requests.RequestException:
            pass
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        timings.append(elapsed_ms)

    return np.array(timings, dtype=np.float64)


def measure_with_adaptive_samples(
    base_url: str,
    endpoint: str,
    token: str,
    initial_samples: int = 300,
    max_samples: int = 2000,
    warmup: int = 10,
    batch_size: int = 100,
) -> np.ndarray:
    """
    Collect samples in batches up to max_samples (used by stats_engine adaptive logic).
  """
    url = base_url.rstrip('/') + endpoint
    payload = {'token': token}
    session = requests.Session()

    for _ in range(warmup):
        try:
            session.post(url, json=payload, timeout=10.0)
        except requests.RequestException:
            pass

    timings = []
    while len(timings) < max_samples:
        n = min(batch_size, max_samples - len(timings))
        if len(timings) == 0 and initial_samples > 0:
            n = min(initial_samples, max_samples)

        for _ in range(n):
            start = time.perf_counter()
            try:
                session.post(url, json=payload, timeout=10.0)
            except requests.RequestException:
                pass
            timings.append((time.perf_counter() - start) * 1000.0)

        if len(timings) >= initial_samples:
            break

    return np.array(timings, dtype=np.float64)
