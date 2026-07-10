# TimeLeak Attacker Toolkit

Python toolkit for demonstrating **timing side-channel attacks** against naive string comparison, with statistical analysis robust to network jitter.

## Setup

```bash
cd timeleak-attacker-toolkit
pip install -r requirements.txt
```

## Commands

### 1. Local attack (sanity check — no network)

Isolates CPU-level timing signal by calling a vulnerable comparison function in-process:

```bash
python main.py local --secret Xy9z --samples 150
```

### 2. Network attack (naive endpoint)

Start the victim server first (`npm start` in `timeleak-victim-server`). **Do not** read the server console secret during a blind demo.

```bash
python main.py attack --endpoint /verify/naive --length 8 --samples 150
```

Compare recovered secret against the server console output afterward.

### 3. Network attack (safe endpoint — should fail)

```bash
python main.py attack --endpoint /verify/safe --length 8 --samples 150
```

Timing distributions should be flat; recovery should be at chance level.

### 4. Generate plots

```bash
python main.py plot --csv results/attack_verify_naive_TIMESTAMP.csv --position 0 \
  --naive-csv results/attack_verify_naive_TIMESTAMP.csv \
  --safe-csv results/attack_verify_safe_TIMESTAMP.csv
```

Noise sensitivity plot (after running attacks at different jitter levels):

```bash
python main.py plot --csv results/jitter0.csv \
  --noise-csvs results/jitter0.csv results/jitter3.csv results/jitter5.csv \
  --noise-labels 0 3 5
```

## Output

- **CSV files** in `results/` — every candidate measurement with mean, stdev, p-value, winner flag
- **PNG plots** — candidate bar charts, attack timeline, naive vs safe comparison, noise sensitivity

## Statistical Approach

1. **Many repeated samples** per guess (`time.perf_counter()`, never `time.time()`)
2. **Warm-up requests** before timed batches (avoid TCP/JIT cold-start)
3. **Trimmed mean** for robust central tendency (outlier-resistant)
4. **Welch's t-test** (`scipy.stats.ttest_ind`, `equal_var=False`) to compare top two candidates
5. **Adaptive sampling** — if p > 0.05, collect more samples up to 2000
6. **99% confidence intervals** on winning candidate timing

The attack exploits the fact that a char-by-char comparison with early exit takes longer when more prefix bytes match. The candidate with statistically higher mean latency at each position is the correct byte.

## CLI Reference

```
python main.py attack --help
python main.py local --help
python main.py plot --help
```

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | `http://localhost:3000` | Victim server |
| `--endpoint` | `/verify/naive` | `/verify/naive` or `/verify/safe` |
| `--length` | `8` | Assumed secret length |
| `--samples` | `200` | Initial samples per candidate |
| `--max-samples` | `2000` | Adaptive sampling cap |
| `--p-threshold` | `0.05` | Significance threshold |

**Note:** Full 16-char recovery with 62 candidates × 200 samples ≈ 198,400 HTTP requests. Start with `--length 4` or `6` for quick tests.
