const express = require('express');
const crypto = require('crypto');
const config = require('../config');
const { SECRET } = require('../secrets/secret');
const { logRequest } = require('../logs/requestLog');

const router = express.Router();

function applyJitter() {
  if (!config.SIMULATE_JITTER) return;
  const delayMs = Math.random() * config.JITTER_MAX_MS;
  const start = Date.now();
  while (Date.now() - start < delayMs) {}
}

/**
 * Hash input to a fixed 32-byte digest so timingSafeEqual always compares
 * equal-length buffers regardless of original string length.
 *
 * Why hash first?
 * - crypto.timingSafeEqual(a, b) throws if buffer lengths differ.
 * - Rejecting mismatched lengths *before* the call leaks length via timing
 *   (fast reject vs slow full compare).
 * - Hashing both sides to fixed length removes that leak while enabling
 *   constant-time comparison of the digests.
 */
function hashToken(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest();
}

function verifySafe(guess) {
  const guessHash = hashToken(guess);
  const secretHash = hashToken(SECRET);
  return crypto.timingSafeEqual(guessHash, secretHash);
}

/**
 * POST /verify/safe — same interface as naive, constant-time comparison.
 */
router.post('/verify/safe', (req, res) => {
  const start = process.hrtime.bigint();
  const { token } = req.body || {};

  let success = false;
  if (typeof token === 'string') {
    success = verifySafe(token);
  }

  applyJitter();

  const elapsed = Number(process.hrtime.bigint() - start) / 1e6;
  const guess = typeof token === 'string' ? token : '';
  logRequest({ endpoint: 'safe', guess, secret: SECRET, responseTimeMs: elapsed });

  return res.json({ success });
});

module.exports = router;
