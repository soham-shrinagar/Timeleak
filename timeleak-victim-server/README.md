# TimeLeak Victim Server

Educational Node.js server demonstrating a **timing side-channel vulnerability** in naive string comparison, and the fix using `crypto.timingSafeEqual`.

## Quick Start

```bash
cd timeleak-victim-server
npm install
npm start
```

The server prints the randomly generated secret to the console at boot (for verification only — never use it in your attacker script during a blind demo).

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/verify/naive` | Vulnerable comparison (`===` or char-by-char loop) |
| `POST` | `/verify/safe` | Patched comparison (SHA-256 + `timingSafeEqual`) |
| `GET` | `/health` | Health check |

### Request / Response

```json
POST /verify/naive
{ "token": "your_guess_here" }

→ { "success": true }   // or { "success": false }
```

Response body is identical in shape for match and mismatch — only **timing** differs.

### Naive comparison modes

Set via `NAIVE_COMPARISON_MODE` in `config.js` or query param `?mode=equals|loop`:

- **`equals`** — native JavaScript `===` (V8 may optimize, weaker leak)
- **`loop`** — manual char-by-char with early exit (stronger, textbook-vulnerable)

## Configuration (`config.js`)

| Option | Default | Description |
|--------|---------|-------------|
| `PORT` | `3000` | Server port |
| `SECRET_LENGTH` | `16` | Random secret length |
| `SIMULATE_JITTER` | `false` | Add random 0–5ms delay per response |
| `JITTER_MAX_MS` | `5` | Max jitter in milliseconds |
| `NAIVE_COMPARISON_MODE` | `loop` | `equals` or `loop` |
| `RATE_LIMIT_ENABLED` | `false` | IP rate limiting |
| `RATE_LIMIT_MAX_PER_SECOND` | `10` | Max requests per IP per second |

Environment variables override config (e.g. `SIMULATE_JITTER=true npm start`).

## Verify with curl

```bash
# Health check
curl http://localhost:3000/health

# Naive endpoint (wrong guess)
curl -X POST http://localhost:3000/verify/naive \
  -H "Content-Type: application/json" \
  -d '{"token":"wrongguess123456"}'

# Safe endpoint
curl -X POST http://localhost:3000/verify/safe \
  -H "Content-Type: application/json" \
  -d '{"token":"wrongguess123456"}'
```

## The Vulnerability

When code compares a secret using `===` or a loop that returns early on the first mismatched character, **comparison time correlates with how many bytes match**. An attacker who can measure response latency across thousands of guesses can recover the secret one byte at a time — without ever seeing the secret in the response.

## The Fix

The `/verify/safe` endpoint hashes both the guess and the secret with SHA-256 (fixed 32-byte output), then compares digests with Node's `crypto.timingSafeEqual()`, which runs in constant time regardless of where bytes differ. Hashing first is required because `timingSafeEqual` throws on unequal buffer lengths — rejecting by length first would leak length information via timing.

## Server-Side Logs

Every verification attempt is logged to `logs/requests.log` (timestamp, endpoint, matched prefix length, response time). This is for your debugging only — not exposed to clients.
