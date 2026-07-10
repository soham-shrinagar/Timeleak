/**
 * Server configuration for TimeLeak victim demo.
 * Toggle flags here to simulate realistic attack conditions.
 */
module.exports = {
  PORT: process.env.PORT || 3000,

  // Length of the randomly generated secret token (alphanumeric).
  SECRET_LENGTH: parseInt(process.env.SECRET_LENGTH, 10) || 16,

  // When true, adds random 0..JITTER_MAX_MS delay to every verification response.
  // Simulates network/OS jitter so the attacker must use real statistics.
  SIMULATE_JITTER: process.env.SIMULATE_JITTER === 'true' || false,
  JITTER_MAX_MS: parseInt(process.env.JITTER_MAX_MS, 10) || 5,

  // Naive comparison strategy: 'equals' (native ===) or 'loop' (char-by-char early exit).
  // The loop variant leaks more timing signal because it explicitly stops at first mismatch.
  NAIVE_COMPARISON_MODE: process.env.NAIVE_COMPARISON_MODE || 'loop',

  // Rate limiting as defense-in-depth (does not fix the crypto bug, only slows attackers).
  RATE_LIMIT_ENABLED: process.env.RATE_LIMIT_ENABLED === 'true' || false,
  RATE_LIMIT_MAX_PER_SECOND: parseInt(process.env.RATE_LIMIT_MAX_PER_SECOND, 10) || 10,
};
