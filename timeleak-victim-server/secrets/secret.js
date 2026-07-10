const crypto = require('crypto');
const config = require('../config');

const ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

/**
 * Generate a cryptographically random alphanumeric secret at boot.
 * Stored in memory only — never exposed via HTTP.
 */
function generateSecret(length) {
  const bytes = crypto.randomBytes(length);
  let secret = '';
  for (let i = 0; i < length; i++) {
    secret += ALPHABET[bytes[i] % ALPHABET.length];
  }
  return secret;
}

const SECRET = generateSecret(config.SECRET_LENGTH);

module.exports = { SECRET, ALPHABET };
