const { assert } = require('chai');
const transientHandler = require('../lib/transientHandler');

class ResultMock {
  constructor() {
    this.resetArgs();
  }

  cookie() {
    this.args.push(arguments);
  }

  resetArgs() {
    this.args = [];
  }
}

describe('transientHandler', function() {

  let res = new ResultMock();

  beforeEach(async function() {
    res.resetArgs();
  });

  describe('store()', function() {
    it('should use the passed-in key to set the cookie', function() {
      transientHandler.store('test_key', res);

      assert.equal('test_key', res.args[0][0]); // Main cookie
      assert.equal('_test_key', res.args[1][0]); // Fallback cookie
    });

    it('should return the same nonce as the cookie value', function() {
      const value = transientHandler.store('test_key', res, {});
      assert.equal(value, res.args[0][1]); // Main cookie
      assert.equal(value, res.args[1][1]); // Fallback cookie
    });

    it('should set SameSite=None, secure, and fallback cookie by default', function() {
      transientHandler.store('test_key', res);

      assert.equal('None', res.args[0][2].sameSite); // Main cookie
      assert.equal(true, res.args[0][2].secure); // Main cookie
      assert.equal(true, res.args[0][2].httpOnly); // Main cookie
      assert.equal(600000, res.args[0][2].maxAge); // Main cookie

      assert.equal('_test_key', res.args[1][0]); // Fallback cookie
      assert.equal(true, res.args[1][2].httpOnly); // Fallback cookie
      assert.equal(600000, res.args[1][2].maxAge); // Fallback cookie
      assert.equal(undefined, res.args[1][2].sameSite); // Fallback cookie
      assert.equal(undefined, res.args[1][2].secure); // Fallback cookie
    });

    it('should turn off fallback', function() {
      transientHandler.store('test_key', res, {legacySameSiteCookie: false});

      assert.equal('test_key', res.args[0][0]); // Main cookie
      assert.equal(undefined, res.args[1]); // Fallback cookie
    });

    it('should set custom SameSite with no fallback', function() {
      transientHandler.store('test_key', res, {sameSite: 'Lax'});

      assert.equal('Lax', res.args[0][2].sameSite); // Main cookie
      assert.equal(false, res.args[0][2].secure); // Main cookie

      assert.equal(undefined, res.args[1]); // Fallback cookie
    });

    it('should use the passed-in value', function() {
      const value = transientHandler.store('test_key', res, {value: '__test_value__'});
      assert.equal('__test_value__', value);
      assert.equal(value, res.args[0][1]); // Main cookie
      assert.equal(value, res.args[1][1]); // Fallback cookie
    });

    it('should set a custom maxAge', function() {
      transientHandler.store('test_key', res, {maxAge: 123456789});

      assert.equal(123456789, res.args[0][2].maxAge); // Main cookie
      assert.equal(123456789, res.args[1][2].maxAge); // Fallback cookie
    });
  });

  describe('getOnce()', function() {
    it('should return undefined if there are no cookies', function() {
      assert.equal(transientHandler.getOnce('test_key', {cookies: undefined}, res), undefined);
    });

    it('should return main value and delete both cookies by default', function() {
      const req = {cookies: {test_key: '__test_value__', _test_key: '__test_fallback_value__'}};
      const value = transientHandler.getOnce('test_key', req, res);

      assert.equal(value, '__test_value__');

      assert.equal('test_key', res.args[0][0]); // Main cookie
      assert.equal('', res.args[0][1]); // Main cookie
      assert.equal(0, res.args[0][2].maxAge); // Main cookie
      assert.equal(undefined, req.cookies.test_key); // Main cookie

      assert.equal('_test_key', res.args[1][0]); // Fallback cookie
      assert.equal('', res.args[1][1]); // Fallback cookie
      assert.equal(0, res.args[1][2].maxAge); // Fallback cookie
      assert.equal(undefined, req.cookies._test_key); // Fallback cookie
    });

    it('should return fallback value and delete both cookies if main value not present', function() {
      const req = {cookies: {_test_key: '__test_fallback_value__'}};
      const value = transientHandler.getOnce('test_key', req, res);

      assert.equal(value, '__test_fallback_value__');

      assert.equal('test_key', res.args[0][0]); // Main cookie
      assert.equal('', res.args[0][1]); // Main cookie
      assert.equal(0, res.args[0][2].maxAge); // Main cookie

      assert.equal('_test_key', res.args[1][0]); // Fallback cookie
      assert.equal('', res.args[1][1]); // Fallback cookie
      assert.equal(0, res.args[1][2].maxAge); // Fallback cookie
      assert.equal(undefined, req.cookies._test_key); // Fallback cookie
    });

    it('should not delete fallback cookie if legacy support is off', function() {
      const req = {cookies: {test_key: '__test_value__', _test_key: '__test_fallback_value__'}};
      const value = transientHandler.getOnce('test_key', req, res, {legacySameSiteCookie: false});

      assert.equal(value, '__test_value__');

      assert.equal('test_key', res.args[0][0]); // Main cookie
      assert.equal('', res.args[0][1]); // Main cookie
      assert.equal(0, res.args[0][2].maxAge); // Main cookie

      assert.equal(undefined, res.args[1]); // Fallback cookie
      assert.equal('__test_fallback_value__', req.cookies._test_key); // Fallback cookie
    });
  });
});
