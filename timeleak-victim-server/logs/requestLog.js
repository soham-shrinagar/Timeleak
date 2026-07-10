const fs = require('fs');
const path = require('path');

const LOG_DIR = path.join(__dirname);
const LOG_FILE = path.join(LOG_DIR, 'requests.log');

/**
 * Compute how many leading characters of guess match the secret.
 * Used only for server-side debugging — never sent to the client.
 */
function matchedPrefixLength(guess, secret) {
  const len = Math.min(guess.length, secret.length);
  let matched = 0;
  for (let i = 0; i < len; i++) {
    if (guess[i] !== secret[i]) break;
    matched++;
  }
  return matched;
}

/**
 * Append a structured log line for each verification attempt.
 * Helps validate that timing differences correlate with prefix length.
 */
function logRequest({ endpoint, guess, secret, responseTimeMs }) {
  const prefixLen = matchedPrefixLength(guess, secret);
  const line = JSON.stringify({
    timestamp: new Date().toISOString(),
    endpoint,
    matchedPrefixLength: prefixLen,
    responseTimeMs: Math.round(responseTimeMs * 100) / 100,
  });

  fs.appendFile(LOG_FILE, line + '\n', (err) => {
    if (err) console.error('Failed to write request log:', err.message);
  });
}

module.exports = { logRequest, matchedPrefixLength };
