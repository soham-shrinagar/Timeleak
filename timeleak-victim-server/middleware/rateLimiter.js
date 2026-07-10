const config = require('../config');

/**
 * Simple in-memory IP-based rate limiter (sliding 1-second window).
 * Defense-in-depth: slows brute-force and timing enumeration but does not
 * eliminate the underlying comparison vulnerability.
 */
function createRateLimiter() {
  const buckets = new Map();

  return function rateLimiter(req, res, next) {
    if (!config.RATE_LIMIT_ENABLED) {
      return next();
    }

    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const windowMs = 1000;

    let entry = buckets.get(ip);
    if (!entry || now - entry.windowStart >= windowMs) {
      entry = { windowStart: now, count: 0 };
      buckets.set(ip, entry);
    }

    entry.count += 1;

    if (entry.count > config.RATE_LIMIT_MAX_PER_SECOND) {
      return res.status(429).json({
        success: false,
        error: 'Rate limit exceeded',
      });
    }

    return next();
  };
}

module.exports = createRateLimiter;
