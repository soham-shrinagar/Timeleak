const express = require('express');
const config = require('../config');
const { SECRET } = require('../secrets/secret');
const { logRequest } = require('../logs/requestLog');

const router = express.Router();

/**
 * Add configurable random jitter to simulate network noise.
 */
function applyJitter() {
  if (!config.SIMULATE_JITTER) return;
  const delayMs = Math.random() * config.JITTER_MAX_MS;
  const start = Date.now();
  while (Date.now() - start < delayMs) {
    // Busy-wait synchronously so jitter is included in request handling time.
  }
}

/**
 * Native === comparison. V8 may short-circuit internally, but still leaks
 * some timing signal on average over many samples.
 */
function compareEquals(guess, secret) {
  return guess === secret;
}

/**
 * Busy-wait for a given number of microseconds (amplifies per-char timing leak).
 */
function burnMicroseconds(us) {
  if (us <= 0) return;
  const end = process.hrtime.bigint() + BigInt(us * 1000);
  while (process.hrtime.bigint() < end) {
    // Intentional spin — included in request handling time.
  }
}

/**
 * Manual char-by-char loop with early exit on first mismatch.
 * This is the classic textbook-vulnerable pattern: comparison time is
 * proportional to the number of matching prefix bytes.
 */
function compareLoop(guess, secret) {
  if (guess.length !== secret.length) return false;
  for (let i = 0; i < secret.length; i++) {
    if (guess[i] !== secret[i]) return false;
    burnMicroseconds(config.COMPARE_DELAY_US);
  }
  return true;
}

function verifyNaive(guess) {
  if (config.NAIVE_COMPARISON_MODE === 'equals') {
    return compareEquals(guess, SECRET);
  }
  return compareLoop(guess, SECRET);
}

/**
 * POST /verify/naive
 * Query param ?mode=equals|loop overrides config.NAIVE_COMPARISON_MODE for A/B demos.
 */
router.post('/verify/naive', (req, res) => {
  const start = process.hrtime.bigint();
  const { token } = req.body || {};

  if (typeof token !== 'string') {
    applyJitter();
    const elapsed = Number(process.hrtime.bigint() - start) / 1e6;
    logRequest({ endpoint: 'naive', guess: '', secret: SECRET, responseTimeMs: elapsed });
    return res.json({ success: false });
  }

  const mode = req.query.mode;
  let success;
  if (mode === 'equals') {
    success = compareEquals(token, SECRET);
  } else if (mode === 'loop') {
    success = compareLoop(token, SECRET);
  } else {
    success = verifyNaive(token);
  }

  applyJitter();

  const elapsed = Number(process.hrtime.bigint() - start) / 1e6;
  logRequest({ endpoint: 'naive', guess: token, secret: SECRET, responseTimeMs: elapsed });

  // Identical response shape regardless of match — timing is the only side-channel.
  return res.json({ success });
});

module.exports = router;
