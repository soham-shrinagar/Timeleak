# TimeLeak

Educational security research project demonstrating a **timing side-channel attack** against naive string comparison in an authentication endpoint, and the fix using constant-time comparison.

Two independent sub-projects communicate over local HTTP:

| Folder | Stack | Role |
|--------|-------|------|
| [`timeleak-victim-server/`](timeleak-victim-server/) | Node.js, Express | Vulnerable + patched verify endpoints |
| [`timeleak-attacker-toolkit/`](timeleak-attacker-toolkit/) | Python | Statistical timing attack + plots |
| [`report/`](report/) | Markdown | Full writeup with methodology and results |

## Quick start

### 1. Victim server

```bash
cd timeleak-victim-server
npm install
npm start
```

The server prints a random secret to the console at boot (for verification only — do not use it during a blind attack demo).

### 2. Attacker toolkit

```bash
cd timeleak-attacker-toolkit
pip install -r requirements.txt
```

**Local sanity check (no network):**

```bash
python main.py local --secret Demo1 --samples 150
```

**Network attack — naive endpoint (should recover secret):**

```bash
python main.py attack --endpoint /verify/naive --length 8 --samples 150
```

**Network attack — safe endpoint (should fail at chance level):**

```bash
python main.py attack --endpoint /verify/safe --length 8 --samples 150
```

**Generate plots:**

```bash
python main.py plot --csv results/attack_verify_naive_TIMESTAMP.csv --position 0 \
  --naive-csv results/attack_verify_naive_TIMESTAMP.csv \
  --safe-csv results/attack_verify_safe_TIMESTAMP.csv
```

## What this proves

- **Naive comparison** (`===` or early-exit loop) leaks secret bytes through response latency.
- **Statistical analysis** (trimmed mean, Welch's t-test, adaptive sampling) recovers the secret despite network jitter.
- **`crypto.timingSafeEqual`** (with SHA-256 normalization) removes the timing signal.

## Documentation

- Server details: [`timeleak-victim-server/README.md`](timeleak-victim-server/README.md)
- Attacker details: [`timeleak-attacker-toolkit/README.md`](timeleak-attacker-toolkit/README.md)
- Full report: [`report/TimeLeak-Writeup.md`](report/TimeLeak-Writeup.md)

## Request volume

For secret length `L`, alphabet size 62, and `S` samples per candidate:

```
Total requests ≈ L × 62 × S
```

Example: L=8, S=200 → ~99,200 requests (~15–30 min on localhost).

## License

MIT — educational use only. Attack only systems you own or have permission to test.
