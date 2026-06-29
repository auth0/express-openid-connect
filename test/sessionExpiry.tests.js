const assert = require('chai').assert;
const {
  SESSION_EXPIRY_LEEWAY,
  extractSessionExpiry,
  isSessionExpiryReached,
  isSessionExpiryInPast,
} = require('../lib/utils/sessionExpiry');

describe('extractSessionExpiry', () => {
  it('returns the value for a valid positive integer', () => {
    assert.equal(
      extractSessionExpiry({ session_expiry: 1748566800 }),
      1748566800,
    );
  });

  it('returns undefined when the claim is absent', () => {
    assert.isUndefined(extractSessionExpiry({ sub: '__test_sub__' }));
    assert.isUndefined(extractSessionExpiry(undefined));
    assert.isUndefined(extractSessionExpiry(null));
  });

  it('returns undefined for a string value (fail-open)', () => {
    assert.isUndefined(extractSessionExpiry({ session_expiry: '1748566800' }));
  });

  it('returns undefined for a float value (fail-open)', () => {
    assert.isUndefined(extractSessionExpiry({ session_expiry: 1748566800.5 }));
  });

  it('returns undefined for zero (fail-open)', () => {
    assert.isUndefined(extractSessionExpiry({ session_expiry: 0 }));
  });

  it('returns undefined for a negative value (fail-open)', () => {
    assert.isUndefined(extractSessionExpiry({ session_expiry: -100 }));
  });

  it('returns undefined for NaN (fail-open)', () => {
    assert.isUndefined(extractSessionExpiry({ session_expiry: NaN }));
  });

  it('returns undefined for a millisecond-magnitude value (fail-open)', () => {
    assert.isUndefined(extractSessionExpiry({ session_expiry: 1748566800000 }));
  });
});

describe('isSessionExpiryReached', () => {
  it('returns false when sessionExpiresAt is undefined (no ceiling)', () => {
    assert.isFalse(isSessionExpiryReached(undefined));
  });

  it('returns false when ceiling is well in the future', () => {
    const now = 1000000;
    assert.isFalse(isSessionExpiryReached(now + 3600, now));
  });

  it('returns true when ceiling is in the past', () => {
    const now = 1000000;
    assert.isTrue(isSessionExpiryReached(now - 1, now));
  });

  it('returns true when now is within the leeway window (clock skew guard)', () => {
    const now = 1000000;
    // ceiling is 10s away but leeway is 30s — already considered expired
    assert.isTrue(isSessionExpiryReached(now + 10, now));
  });

  it('returns true exactly at the leeway boundary (inclusive)', () => {
    const now = 1000000;
    assert.isTrue(isSessionExpiryReached(now + SESSION_EXPIRY_LEEWAY, now));
  });

  it('returns false just outside the leeway boundary', () => {
    const now = 1000000;
    assert.isFalse(
      isSessionExpiryReached(now + SESSION_EXPIRY_LEEWAY + 1, now),
    );
  });
});

describe('isSessionExpiryInPast', () => {
  it('returns false when sessionExpiresAt is undefined (no ceiling)', () => {
    assert.isFalse(isSessionExpiryInPast(undefined, 1000000));
  });

  it('returns false when ceiling is well in the future relative to iat', () => {
    const iat = 1000000;
    assert.isFalse(isSessionExpiryInPast(iat + 3600, iat));
  });

  it('returns true when ceiling is in the past relative to iat', () => {
    const iat = 1000000;
    assert.isTrue(isSessionExpiryInPast(iat - 1, iat));
  });

  it('returns true when ceiling is within the leeway window relative to iat', () => {
    const iat = 1000000;
    assert.isTrue(isSessionExpiryInPast(iat + 15, iat));
  });

  it('returns true exactly at the leeway boundary relative to iat (inclusive)', () => {
    const iat = 1000000;
    assert.isTrue(isSessionExpiryInPast(iat + SESSION_EXPIRY_LEEWAY, iat));
  });

  it('returns false just outside the leeway boundary relative to iat', () => {
    const iat = 1000000;
    assert.isFalse(isSessionExpiryInPast(iat + SESSION_EXPIRY_LEEWAY + 1, iat));
  });

  it('falls back to epoch() when issuedAt is absent', () => {
    // ceiling well in the future → false regardless of fallback
    assert.isFalse(isSessionExpiryInPast(Math.floor(Date.now() / 1000) + 3600));
  });

  it('falls back to epoch() when issuedAt is a millisecond-magnitude value', () => {
    const iat = Date.now(); // milliseconds — implausible
    const ceiling = Math.floor(Date.now() / 1000) + 3600;
    assert.isFalse(isSessionExpiryInPast(ceiling, iat));
  });
});
