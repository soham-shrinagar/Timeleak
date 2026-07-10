#!/usr/bin/env python3
"""
TimeLeak Attacker Toolkit — CLI entrypoint.
"""

import argparse
import sys


def cmd_attack(args):
    from attack import run_attack

    run_attack(
        base_url=args.url,
        endpoint=args.endpoint,
        secret_length=args.length,
        samples=args.samples,
        max_samples=args.max_samples,
        warmup=args.warmup,
        p_threshold=args.p_threshold,
        results_dir=args.output,
        verbose=not args.quiet,
    )


def cmd_local(args):
    from local_variant import run_local_attack

    if not args.secret:
        print('Error: --secret is required for local attack (test harness only).')
        print('Use a known short secret e.g. --secret Abc1 for sanity check.')
        sys.exit(1)

    run_local_attack(
        secret=args.secret,
        samples=args.samples,
        warmup=args.warmup,
        p_threshold=args.p_threshold,
        results_dir=args.output,
        verbose=not args.quiet,
    )


def cmd_plot(args):
    from visualize import generate_all_plots

    paths = generate_all_plots(
        csv_path=args.csv,
        position=args.position,
        naive_csv=args.naive_csv,
        safe_csv=args.safe_csv,
        noise_csvs=args.noise_csvs,
        noise_labels=args.noise_labels,
        output_dir=args.output,
    )
    print('Generated plots:')
    for p in paths:
        print(f'  {p}')


def main():
    parser = argparse.ArgumentParser(
        description='TimeLeak — timing side-channel attack demonstration toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Local sanity check (4-char secret, no network)
  python main.py local --secret Xy9z --samples 150

  # Network attack against naive endpoint
  python main.py attack --endpoint /verify/naive --samples 200 --length 8

  # Same attack against patched endpoint (should fail to recover)
  python main.py attack --endpoint /verify/safe --samples 200 --length 8

  # Generate plots from results
  python main.py plot --csv results/attack_verify_naive_*.csv --position 0 \\
    --naive-csv results/naive.csv --safe-csv results/safe.csv
        """,
    )
    sub = parser.add_subparsers(dest='command', required=True)

    # attack
    p_attack = sub.add_parser('attack', help='Run network-based byte-by-byte attack')
    p_attack.add_argument('--url', default='http://localhost:3000', help='Victim server base URL')
    p_attack.add_argument(
        '--endpoint', default='/verify/naive',
        choices=['/verify/naive', '/verify/safe'],
        help='Target endpoint',
    )
    p_attack.add_argument('--length', type=int, default=8, help='Assumed secret length (use 8 for faster demo)')
    p_attack.add_argument('--samples', type=int, default=200, help='Initial samples per candidate')
    p_attack.add_argument('--max-samples', type=int, default=2000, help='Max samples with adaptive collection')
    p_attack.add_argument('--warmup', type=int, default=10, help='Warm-up requests per candidate')
    p_attack.add_argument('--p-threshold', type=float, default=0.05, help='Welch t-test significance threshold')
    p_attack.add_argument('--output', default='results', help='Results output directory')
    p_attack.add_argument('--quiet', action='store_true', help='Suppress progress output')
    p_attack.set_defaults(func=cmd_attack)

    # local
    p_local = sub.add_parser('local', help='Run in-process local attack (no HTTP)')
    p_local.add_argument('--secret', required=True, help='Known secret for local test harness')
    p_local.add_argument('--samples', type=int, default=200, help='Samples per candidate')
    p_local.add_argument('--warmup', type=int, default=50, help='Warm-up iterations')
    p_local.add_argument('--p-threshold', type=float, default=0.05, help='Welch t-test threshold')
    p_local.add_argument('--output', default='results', help='Results output directory')
    p_local.add_argument('--quiet', action='store_true')
    p_local.set_defaults(func=cmd_local)

    # plot
    p_plot = sub.add_parser('plot', help='Generate visualization plots from CSV results')
    p_plot.add_argument('--csv', required=True, help='Primary attack results CSV')
    p_plot.add_argument('--position', type=int, default=0, help='Byte position for candidate bar chart')
    p_plot.add_argument('--naive-csv', help='Naive endpoint CSV for comparison plot')
    p_plot.add_argument('--safe-csv', help='Safe endpoint CSV for comparison plot')
    p_plot.add_argument('--noise-csvs', nargs='+', help='Multiple CSVs at different jitter levels')
    p_plot.add_argument('--noise-labels', nargs='+', help='Jitter labels matching --noise-csvs')
    p_plot.add_argument('--output', default='results', help='Plot output directory')
    p_plot.set_defaults(func=cmd_plot)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
