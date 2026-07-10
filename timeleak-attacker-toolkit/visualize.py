"""
Matplotlib visualizations for TimeLeak attack results.
"""

import os
from typing import List, Optional

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def plot_candidate_bars(
    csv_path: str,
    position: int,
    output_path: Optional[str] = None,
    title: Optional[str] = None,
) -> str:
    """
    (1) Bar chart of mean timing per candidate at one byte position with error bars.
    """
    df = pd.read_csv(csv_path)
    pos_df = df[df['position'] == position].copy()

    if pos_df.empty:
        raise ValueError(f'No data for position {position} in {csv_path}')

    mean_col = 'mean_ms' if 'mean_ms' in pos_df.columns else 'mean_us'
    std_col = 'stdev_ms' if 'stdev_ms' in pos_df.columns else 'stdev_us'
    unit = 'ms' if mean_col == 'mean_ms' else 'µs'

    pos_df = pos_df.sort_values(mean_col, ascending=False)
    winners = pos_df[pos_df['winner'] == True]  # noqa: E712

    fig, ax = plt.subplots(figsize=(14, 6))
    colors = ['#e74c3c' if w else '#3498db' for w in pos_df['winner']]
    ax.bar(
        pos_df['candidate'],
        pos_df[mean_col],
        yerr=pos_df[std_col],
        capsize=3,
        color=colors,
        edgecolor='black',
        linewidth=0.5,
    )
    ax.set_xlabel('Candidate character')
    ax.set_ylabel(f'Mean response time ({unit})')
    ax.set_title(title or f'Timing per candidate at position {position}')
    if not winners.empty:
        w = winners.iloc[0]
        ax.axhline(w[mean_col], color='red', linestyle='--', alpha=0.5, label='Winner')
    ax.legend()
    plt.tight_layout()

    if not output_path:
        base = os.path.splitext(csv_path)[0]
        output_path = f'{base}_pos{position}_candidates.png'
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    return output_path


def plot_attack_timeline(
    csv_path: str,
    output_path: Optional[str] = None,
) -> str:
    """
    (2) Recovered byte and confidence (1 - p_value) at each position.
    """
    df = pd.read_csv(csv_path)
    winners = df[df['winner'] == True].copy()  # noqa: E712
    if winners.empty:
        raise ValueError('No winner rows in CSV')

    winners = winners.drop_duplicates('position').sort_values('position')
    positions = winners['position'].values
    chars = winners['candidate'].values
    pvals = winners['p_value'].replace('', np.nan).astype(float).fillna(1.0)
    confidence = 1.0 - pvals

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8), sharex=True)

    ax1.bar(positions, [ord(c) for c in chars], color='#2ecc71', edgecolor='black')
    ax1.set_ylabel('Recovered char (ASCII)')
    ax1.set_title('Recovered secret by position')
    for pos, c in zip(positions, chars):
        ax1.text(pos, ord(c) + 1, c, ha='center', fontsize=10)

    ax2.bar(positions, confidence * 100, color='#9b59b6', edgecolor='black')
    ax2.axhline(95, color='gray', linestyle='--', label='95% confidence')
    ax2.set_xlabel('Byte position')
    ax2.set_ylabel('Confidence (%)')
    ax2.set_title('Statistical confidence per byte (1 − p-value)')
    ax2.legend()
    plt.tight_layout()

    if not output_path:
        output_path = os.path.splitext(csv_path)[0] + '_timeline.png'
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    return output_path


def plot_naive_vs_safe(
    naive_csv: str,
    safe_csv: str,
    position: int,
    output_path: Optional[str] = None,
) -> str:
    """
    (3) Side-by-side timing distributions: naive shows outlier, safe is flat.
    """
    df_naive = pd.read_csv(naive_csv)
    df_safe = pd.read_csv(safe_csv)
    n_pos = df_naive[df_naive['position'] == position]
    s_pos = df_safe[df_safe['position'] == position]

    mean_col = 'mean_ms' if 'mean_ms' in n_pos.columns else 'mean_us'
    std_col = 'stdev_ms' if 'stdev_ms' in n_pos.columns else 'stdev_us'
    unit = 'ms' if mean_col == 'mean_ms' else 'µs'

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6), sharey=True)

    for ax, data, label in [
        (ax1, n_pos, 'Naive (/verify/naive)'),
        (ax2, s_pos, 'Safe (/verify/safe)'),
    ]:
        data = data.sort_values(mean_col, ascending=False)
        colors = ['#e74c3c' if w else '#95a5a6' for w in data['winner']]
        ax.bar(data['candidate'], data[mean_col], yerr=data[std_col], capsize=2, color=colors)
        ax.set_title(label)
        ax.set_xlabel('Candidate')
        ax.tick_params(axis='x', rotation=90)

    ax1.set_ylabel(f'Mean timing ({unit})')
    fig.suptitle(f'Naive vs Safe comparison at position {position}')
    plt.tight_layout()

    if not output_path:
        output_path = os.path.splitext(naive_csv)[0] + f'_naive_vs_safe_pos{position}.png'
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    return output_path


def plot_noise_sensitivity(
    csv_paths: List[str],
    jitter_labels: List[str],
    output_path: Optional[str] = None,
) -> str:
    """
    (4) Samples required vs injected jitter level from multiple attack CSV runs.
    """
    if len(csv_paths) != len(jitter_labels):
        raise ValueError('csv_paths and jitter_labels must have same length')

    jitter_vals = []
    sample_counts = []
    recovery_rates = []

    for path, label in zip(csv_paths, jitter_labels):
        df = pd.read_csv(path)
        winners = df[df['winner'] == True]  # noqa: E712
        avg_samples = winners['n_samples'].mean() if 'n_samples' in winners.columns else 0
        conclusive = winners['conclusive'].sum() / max(len(winners), 1)
        try:
            jitter_vals.append(float(label))
        except ValueError:
            jitter_vals.append(len(jitter_vals))
        sample_counts.append(avg_samples)
        recovery_rates.append(conclusive * 100)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    ax1.plot(jitter_vals, sample_counts, 'o-', color='#e67e22', linewidth=2, markersize=8)
    ax1.set_xlabel('Injected jitter max (ms)')
    ax1.set_ylabel('Mean samples per winning candidate')
    ax1.set_title('Sample count vs network jitter')

    ax2.plot(jitter_vals, recovery_rates, 's-', color='#1abc9c', linewidth=2, markersize=8)
    ax2.set_xlabel('Injected jitter max (ms)')
    ax2.set_ylabel('Conclusive bytes (%)')
    ax2.set_title('Attack success vs network jitter')
    ax2.set_ylim(0, 105)
    plt.tight_layout()

    if not output_path:
        output_path = os.path.join(os.path.dirname(csv_paths[0]), 'noise_sensitivity.png')
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    return output_path


def generate_all_plots(
    csv_path: str,
    position: int = 0,
    naive_csv: Optional[str] = None,
    safe_csv: Optional[str] = None,
    noise_csvs: Optional[List[str]] = None,
    noise_labels: Optional[List[str]] = None,
    output_dir: Optional[str] = None,
) -> List[str]:
    """Generate all available plots from result CSVs."""
    out_dir = output_dir or os.path.dirname(csv_path) or 'results'
    os.makedirs(out_dir, exist_ok=True)
    paths = []

    paths.append(
        plot_candidate_bars(
            csv_path, position,
            output_path=os.path.join(out_dir, f'candidates_pos{position}.png'),
        )
    )
    paths.append(
        plot_attack_timeline(
            csv_path,
            output_path=os.path.join(out_dir, 'attack_timeline.png'),
        )
    )

    if naive_csv and safe_csv:
        paths.append(
            plot_naive_vs_safe(
                naive_csv, safe_csv, position,
                output_path=os.path.join(out_dir, f'naive_vs_safe_pos{position}.png'),
            )
        )

    if noise_csvs and noise_labels:
        paths.append(
            plot_noise_sensitivity(
                noise_csvs, noise_labels,
                output_path=os.path.join(out_dir, 'noise_sensitivity.png'),
            )
        )

    return paths
