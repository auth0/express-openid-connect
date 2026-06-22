const { epoch } = require('./epoch');

const SESSION_EXPIRY_LEEWAY = 30;

/**
 * Reads the IPSIE `session_expiry` claim from ID token claims.
 * Fail-open: returns undefined unless the value is a positive integer below 10_000_000_000.
 * The upper bound rejects accidental millisecond values (13 digits) while allowing any
 * realistic seconds timestamp (10_000_000_000 ≈ year 2286).
 * A missing or malformed claim must never be treated as already-expired.
 */
function extractSessionExpiry(claims) {
  const value = claims?.session_expiry;
  return typeof value === 'number' &&
    Number.isInteger(value) &&
    value > 0 &&
    value < 10_000_000_000
    ? value
    : undefined;
}

/**
 * Returns whether the session_expiry ceiling has been reached, applying the negative leeway.
 * @param {number|undefined} sessionExpiresAt - stored ceiling in Unix seconds, or undefined for no ceiling
 * @param {number} [nowSeconds] - injectable current time for tests; defaults to epoch()
 */
function isSessionExpiryReached(sessionExpiresAt, nowSeconds) {
  if (sessionExpiresAt === undefined) return false;
  const now = nowSeconds !== undefined ? nowSeconds : epoch();
  return now >= sessionExpiresAt - SESSION_EXPIRY_LEEWAY;
}

module.exports = {
  SESSION_EXPIRY_LEEWAY,
  extractSessionExpiry,
  isSessionExpiryReached,
};
