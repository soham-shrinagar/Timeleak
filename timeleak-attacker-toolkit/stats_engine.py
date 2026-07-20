"""
Statistical analysis engine for timing side-channel attacks.

Network timing distributions are right-skewed with occasional outliers from
OS scheduling. We use robust estimators (trimmed mean, median) and Welch's
t-test rather than naive mean comparison.
"""

from typing import Optional, Tuple

import numpy as np
from scipy import stats


def trimmed_mean(samples: np.ndarray, proportion: float = 0.1) -> float:
    """Mean after trimming proportion/2 from each tail."""
    if len(samples) == 0:
        return 0.0
    n = len(samples)
    k = int(n * proportion / 2)
    if k == 0:
        return float(np.mean(samples))
    sorted_s = np.sort(samples)
    trimmed = sorted_s[k : n - k] if n > 2 * k else sorted_s
    return float(np.mean(trimmed))


def median(samples: np.ndarray) -> float:
    return float(np.median(samples)) if len(samples) > 0 else 0.0


def std_dev(samples: np.ndarray) -> float:
    return float(np.std(samples, ddof=1)) if len(samples) > 1 else 0.0


def interquartile_range(samples: np.ndarray) -> float:
    if len(samples) < 4:
        return 0.0
    q1, q3 = np.percentile(samples, [25, 75])
    return float(q3 - q1)


def welch_ttest(samples_a: np.ndarray, samples_b: np.ndarray) -> Tuple[float, float]:
    """
    Welch's t-test (unequal variances) comparing two timing distributions.
    Returns (t_statistic, p_value).
    """
    if len(samples_a) < 2 or len(samples_b) < 2:
        return 0.0, 1.0
    result = stats.ttest_ind(samples_a, samples_b, equal_var=False)
    return float(result.statistic), float(result.pvalue)


def confidence_interval(
    samples: np.ndarray, confidence: float = 0.99
) -> Tuple[float, float, float]:
    """
    Confidence interval for the mean using t-distribution.
    Returns (mean, lower_bound, upper_bound).
    """
    n = len(samples)
    if n < 2:
        m = float(np.mean(samples)) if n else 0.0
        return m, m, m

    mean = float(np.mean(samples))
    se = stats.sem(samples)
    t_crit = stats.t.ppf((1 + confidence) / 2, df=n - 1)
    margin = t_crit * se
    return mean, mean - margin, mean + margin


def rank_candidates(
    candidate_samples: dict,
    use_trimmed_mean: bool = True,
) -> list:
    """
    Rank candidates by robust mean timing (higher = more prefix matches = likely correct).
    Returns list of (candidate, mean, std, n_samples) sorted descending by mean.
    """
    ranked = []
    for candidate, samples in candidate_samples.items():
        arr = np.asarray(samples, dtype=np.float64)
        m = trimmed_mean(arr) if use_trimmed_mean else median(arr)
        ranked.append((candidate, m, std_dev(arr), len(arr)))
    ranked.sort(key=lambda x: x[1], reverse=True)
    return ranked


def adaptive_distinguish(
    samples_a: np.ndarray,
    samples_b: np.ndarray,
    collect_more_a,
    collect_more_b,
    initial_samples: int = 300,
    max_samples: int = 2000,
    p_threshold: float = 0.05,
    batch_size: int = 100,
) -> Tuple[np.ndarray, np.ndarray, float, bool]:
    """
    Adaptively increase sample size until two timing distributions are
    statistically distinguishable (p < p_threshold) or max_samples is reached.

    collect_more_a(n) / collect_more_b(n) -> additional sample arrays of size n.

    Returns (final_a, final_b, p_value, conclusive).
    """
    a = np.asarray(samples_a, dtype=np.float64).copy()
    b = np.asarray(samples_b, dtype=np.float64).copy()

    while len(a) < max_samples and len(b) < max_samples:
        _, p = welch_ttest(a, b)
        if p < p_threshold and len(a) >= initial_samples:
            return a, b, p, True

        need = min(batch_size, max_samples - len(a), max_samples - len(b))
        if need <= 0:
            break

        extra_a = np.asarray(collect_more_a(need), dtype=np.float64)
        extra_b = np.asarray(collect_more_b(need), dtype=np.float64)
        if len(extra_a) > 0:
            a = np.concatenate([a, extra_a])
        if len(extra_b) > 0:
            b = np.concatenate([b, extra_b])

    _, p = welch_ttest(a, b)
    conclusive = p < p_threshold
    return a, b, p, conclusive


def compare_top_two(
    ranked: list,
    candidate_samples: dict,
    p_threshold: float = 0.05,
) -> Tuple[Optional[str], float, bool]:
    """
    Compare the top two ranked candidates via Welch's t-test.
    Returns (winner, p_value, conclusive).
    """
    if len(ranked) < 2:
        if ranked:
            return ranked[0][0], 0.0, True
        return None, 1.0, False

    top_char, _, _, _ = ranked[0]
    second_char, _, _, _ = ranked[1]
    samples_top = np.asarray(candidate_samples[top_char], dtype=np.float64)
    samples_second = np.asarray(candidate_samples[second_char], dtype=np.float64)
    _, p = welch_ttest(samples_top, samples_second)
    conclusive = p < p_threshold
    return top_char, p, conclusive
