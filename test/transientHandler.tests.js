const { assert } = require('chai');

const COOKIES = require('../lib/cookies');
const TransientCookieHandler = require('../lib/transientHandler');

const reqWithCookies = (cookies) => ({ [COOKIES]: cookies });

class ResultMock {
  constructor () {
    this.resetArgs();
  }

  cookie (...args) {
    this.cookieArgs.push(args);
  }

  clearCookie (...args) {
    this.clearCookieArgs.push(args);
  }

  resetArgs () {
    this.cookieArgs = [];
    this.clearCookieArgs = [];
  }
}

const transientHandler = new TransientCookieHandler({ secret: '__test_session_secret__', legacySameSiteCookie: true });

describe('transientHandler', function () {
  const res = new ResultMock();

  beforeEach(async function () {
    res.resetArgs();
  });

  // reset to default
  afterEach(() => {
    transientHandler.legacySameSiteCookie = true;
  });

  describe('store()', function () {
    it('should use the passed-in key to set the cookie', function () {
      transientHandler.store('test_key', {}, res);

      assert.equal('test_key', res.cookieArgs[0][0]); // Main cookie
      assert.equal('_test_key', res.cookieArgs[1][0]); // Fallback cookie
    });

    it('should return the same nonce as the cookie value', function () {
      const value = transientHandler.store('test_key', {}, res, {});
      assert.equal(value, res.cookieArgs[0][1].split('.')[0]); // Main cookie
      assert.equal(value, res.cookieArgs[1][1].split('.')[0]); // Fallback cookie
    });

    it('should use the req.secure property to automatically set cookies secure when on https', function () {
      transientHandler.store('test_key', { secure: true }, res, { sameSite: 'Lax' });
      transientHandler.store('test_key', { secure: false }, res, { sameSite: 'Lax' });

      assert.equal('test_key', res.cookieArgs[0][0]);
      assert.equal('Lax', res.cookieArgs[0][2].sameSite);
      assert.equal(true, res.cookieArgs[0][2].secure);

      assert.equal('test_key', res.cookieArgs[1][0]);
      assert.equal('Lax', res.cookieArgs[1][2].sameSite);
      assert.equal(false, res.cookieArgs[1][2].secure);
    });

    it('should set SameSite=None, secure, and fallback cookie by default', function () {
      transientHandler.store('test_key', {}, res);

      assert.equal('None', res.cookieArgs[0][2].sameSite); // Main cookie
      assert.equal(true, res.cookieArgs[0][2].secure); // Main cookie
      assert.equal(true, res.cookieArgs[0][2].httpOnly); // Main cookie

      assert.equal('_test_key', res.cookieArgs[1][0]); // Fallback cookie
      assert.equal(true, res.cookieArgs[1][2].httpOnly); // Fallback cookie
      assert.equal(undefined, res.cookieArgs[1][2].sameSite); // Fallback cookie
      assert.equal(undefined, res.cookieArgs[1][2].secure); // Fallback cookie
    });

    it('should turn off fallback', function () {
      transientHandler.legacySameSiteCookie = false;
      transientHandler.store('test_key', {}, res);

      assert.equal('test_key', res.cookieArgs[0][0]); // Main cookie
      assert.equal(undefined, res.cookieArgs[1]); // Fallback cookie
    });

    it('should set custom SameSite with no fallback', function () {
      transientHandler.store('test_key', {}, res, { sameSite: 'Lax' });

      assert.equal('Lax', res.cookieArgs[0][2].sameSite); // Main cookie

      assert.equal(undefined, res.cookieArgs[1]); // Fallback cookie
    });

    it('should use the passed-in value', function () {
      const value = transientHandler.store('test_key', {}, res, { value: '__test_value__' });
      assert.equal('__test_value__', value);
      assert.equal(value, res.cookieArgs[0][1].split('.')[0]); // Main cookie
      assert.equal(value, res.cookieArgs[1][1].split('.')[0]); // Fallback cookie
    });
  });

  describe('getOnce()', function () {
    it('should return undefined if there are no cookies', function () {
      assert.equal(transientHandler.getOnce('test_key', reqWithCookies(undefined), res), undefined);
    });

    it('should return main value and delete both cookies by default', function () {
      const cookies = { test_key: 'o7Br3gKh26VwDef9RPinlpwP4yXESaeAipT3BqCFjBI.Y4AuoWAEoDxzhmHFObdgFKlrr8Xc9VaL0AJgfl63F3c', _test_key: 'o7Br3gKh26VwDef9RPinlpwP4yXESaeAipT3BqCFjBI.Y4AuoWAEoDxzhmHFObdgFKlrr8Xc9VaL0AJgfl63F3c' };
      const req = reqWithCookies(cookies);
      const value = transientHandler.getOnce('test_key', req, res);

      assert.equal(value.split('.')[0], 'o7Br3gKh26VwDef9RPinlpwP4yXESaeAipT3BqCFjBI');

      assert.equal('test_key', res.clearCookieArgs[0][0]); // Main cookie

      assert.equal('_test_key', res.clearCookieArgs[1][0]); // Fallback cookie
    });

    it('should return fallback value and delete both cookies if main value not present', function () {
      const cookies = { _test_key: 'o7Br3gKh26VwDef9RPinlpwP4yXESaeAipT3BqCFjBI.Y4AuoWAEoDxzhmHFObdgFKlrr8Xc9VaL0AJgfl63F3c' };
      const req = reqWithCookies(cookies);
      const value = transientHandler.getOnce('test_key', req, res);

      assert.equal(value, 'o7Br3gKh26VwDef9RPinlpwP4yXESaeAipT3BqCFjBI');

      assert.equal('test_key', res.clearCookieArgs[0][0]); // Main cookie

      assert.equal('_test_key', res.clearCookieArgs[1][0]); // Fallback cookie
    });

    it('should not delete fallback cookie if legacy support is off', function () {
      const cookies = { test_key: 'nJ38hOd-rllOU-zEpGnb6gEwbrwtMisG8uLmXq3N9JA.NC0g6K_Pc-UAYvNcwWJvRmosbINKyblTHSaCg9xS3KE', _test_key: 'o7Br3gKh26VwDef9RPinlpwP4yXESaeAipT3BqCFjBI.Y4AuoWAEoDxzhmHFObdgFKlrr8Xc9VaL0AJgfl63F3c' };
      const req = reqWithCookies(cookies);
      transientHandler.legacySameSiteCookie = false;
      const value = transientHandler.getOnce('test_key', req, res);

      assert.equal(value, 'nJ38hOd-rllOU-zEpGnb6gEwbrwtMisG8uLmXq3N9JA');

      assert.equal('test_key', res.clearCookieArgs[0][0]); // Main cookie

      assert.equal(undefined, res.clearCookieArgs[1]); // Fallback cookie
      assert.equal('o7Br3gKh26VwDef9RPinlpwP4yXESaeAipT3BqCFjBI.Y4AuoWAEoDxzhmHFObdgFKlrr8Xc9VaL0AJgfl63F3c', cookies._test_key); // Fallback cookie
    });
  });
});
