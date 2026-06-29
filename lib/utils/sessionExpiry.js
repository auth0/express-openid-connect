const { epoch } = require('./epoch');

const SESSION_EXPIRY_LEEWAY = 30;

/**
 * Returns whether a value is a plausible Unix timestamp in seconds: a positive integer below the
 * milliseconds range. Used to reject values mistakenly expressed in milliseconds.
 * 1e10 ≈ year 2286 — far beyond any real session ceiling, yet well below Date.now() (~1.7e12).
 */
function isPlausibleUnixSeconds(value) {
  return (
    typeof value === 'number' &&
    Number.isInteger(value) &&
    value > 0 &&
    value < 10000000000
  );
}

/**
 * Reads the IPSIE `session_expiry` claim from ID token claims.
 * Fail-open: returns undefined unless the value is a plausible Unix-seconds timestamp.
 * A missing or malformed claim must never be treated as already-expired.
 */
function extractSessionExpiry(claims) {
  const value = claims?.session_expiry;
  return isPlausibleUnixSeconds(value) ? value : undefined;
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

/**
 * Returns whether the session_expiry ceiling is already in the past at login time.
 * Uses the ID token `iat` as the reference point rather than the current clock, so a token
 * that arrives late (e.g. delayed callback) is not incorrectly rejected.
 * Falls back to epoch() when `issuedAt` is absent or not a plausible Unix-seconds value.
 * @param {number|undefined} sessionExpiresAt - ceiling in Unix seconds, or undefined for no ceiling
 * @param {number} [issuedAt] - ID token iat claim
 */
function isSessionExpiryInPast(sessionExpiresAt, issuedAt) {
  const reference = isPlausibleUnixSeconds(issuedAt) ? issuedAt : epoch();
  return isSessionExpiryReached(sessionExpiresAt, reference);
}

module.exports = {
  SESSION_EXPIRY_LEEWAY,
  extractSessionExpiry,
  isSessionExpiryReached,
  isSessionExpiryInPast,
};
