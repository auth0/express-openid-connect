const assert = require('chai').assert;
const {
  SESSION_EXPIRY_LEEWAY,
  extractSessionExpiry,
  isSessionExpiryReached,
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
