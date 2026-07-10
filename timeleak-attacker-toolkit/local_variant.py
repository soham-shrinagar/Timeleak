"""
Local (in-process) timing attack — no HTTP, no network jitter.

Re-implements the naive char-by-char comparison in Python to isolate
pure CPU-level timing signal. Useful as a sanity check before network attacks.
"""

import csv
import os
import random
import string
import time
from datetime import datetime, timezone

import numpy as np

from stats_engine import (
    compare_top_two,
    confidence_interval,
    rank_candidates,
    std_dev,
    trimmed_mean,
)

ALPHABET = string.ascii_letters + string.digits


def naive_compare_loop(guess: str, secret: str) -> bool:
    """
    Vulnerable comparison: early exit on first mismatch.
    Comparison time scales with matching prefix length — the exploitable signal.
    """
    if len(guess) != len(secret):
        return False
    for i in range(len(secret)):
        if guess[i] != secret[i]:
            return False
    return True


def measure_local(
    guess: str,
    secret: str,
    samples: int = 200,
    warmup: int = 50,
    iterations: int = 50000,
) -> np.ndarray:
    """
    Time in-process comparison calls using perf_counter.

    Each sample repeats the comparison `iterations` times to amplify the
    sub-microsecond per-byte timing difference into a measurable signal.
    Without this amplification, OS scheduler noise dominates at CPU scale.
    """
    for _ in range(warmup):
        for _ in range(iterations):
            naive_compare_loop(guess, secret)

    timings = []
    for _ in range(samples):
        start = time.perf_counter()
        for _ in range(iterations):
            naive_compare_loop(guess, secret)
        timings.append((time.perf_counter() - start) * 1e6)  # microseconds
    return np.array(timings, dtype=np.float64)


def build_guess(prefix: str, candidate: str, total_length: int) -> str:
    remaining = total_length - len(prefix) - 1
    padding = ''.join(random.choices(ALPHABET, k=remaining)) if remaining > 0 else ''
    return prefix + candidate + padding


def run_local_attack(
    secret: str,
    samples: int = 200,
    warmup: int = 50,
    p_threshold: float = 0.05,
    results_dir: str = 'results',
    verbose: bool = True,
) -> tuple[str, str]:
    """
    Recover secret byte-by-byte using local in-process timing only.
    For sanity checks — secret must be known to set up the test, but recovery
    is blind (algorithm doesn't use secret except in measure_local compare).
    """
    os.makedirs(results_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    csv_path = os.path.join(results_dir, f'local_attack_{timestamp}.csv')

    secret_length = len(secret)
    prefix = ''
    rows = []

    if verbose:
        print('TimeLeak LOCAL attack (in-process, no network)')
        print(f'Target secret length: {secret_length}')
        print('-' * 50)

    for pos in range(secret_length):
        candidate_samples = {}
        for candidate in ALPHABET:
            guess = build_guess(prefix, candidate, secret_length)
            candidate_samples[candidate] = measure_local(
                guess, secret, samples=samples, warmup=warmup
            )

        ranked = rank_candidates(candidate_samples)
        winner, p_value, conclusive = compare_top_two(
            ranked, candidate_samples, p_threshold
        )
        prefix += winner or '?'

        if verbose:
            top_us = trimmed_mean(candidate_samples[winner]) if winner else 0
            print(
                f"Position {pos}: '{winner}' "
                f"(mean={top_us:.2f}µs, p={p_value:.4f}) "
                f"{'[OK]' if conclusive else '[INCONCLUSIVE]'}"
            )

        for candidate, samples_arr in candidate_samples.items():
            rows.append({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'endpoint': 'local',
                'position': pos,
                'candidate': candidate,
                'mean_us': trimmed_mean(samples_arr),
                'stdev_us': std_dev(samples_arr),
                'n_samples': len(samples_arr),
                'p_value': p_value if candidate == winner else '',
                'winner': candidate == winner,
                'conclusive': conclusive,
                'recovered_so_far': prefix,
            })

    fieldnames = list(rows[0].keys()) if rows else []
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    if verbose:
        print('-' * 50)
        print(f'Recovered: {prefix}')
        print(f'Actual:    {secret}')
        print(f'Match: {prefix == secret}')
        print(f'Results: {csv_path}')

    return prefix, csv_path
