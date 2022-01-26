const { assert } = require('chai');
const sinon = require('sinon');
const { JWS } = require('jose');

const COOKIES = require('../lib/cookies');
const TransientCookieHandler = require('../lib/transientHandler');

const reqWithCookies = (cookies) => ({ [COOKIES]: cookies });
const secret = '__test_session_secret__';

describe('transientHandler', function () {
  let res;
  let transientHandler;
  let generateSignature;

  beforeEach(async function () {
    transientHandler = new TransientCookieHandler({
      secret,
      legacySameSiteCookie: true,
    });
    generateSignature = (cookie, value) =>
      JWS.sign.flattened(
        Buffer.from(`${cookie}=${value}`),
        transientHandler.keyStore,
        { alg: 'HS256', b64: false, crit: ['b64'] }
      ).signature;
    res = { cookie: sinon.spy(), clearCookie: sinon.spy() };
  });

  describe('store()', function () {
    it('should use the passed-in key to set the cookie', function () {
      transientHandler.store('test_key', {}, res);
      sinon.assert.calledWith(res.cookie, 'test_key');
      sinon.assert.calledWith(res.cookie, '_test_key');
    });

    it('should return the same nonce as the cookie value', function () {
      const value = transientHandler.store('test_key', {}, res, {});
      const re = new RegExp(`^${value}\\.`);
      sinon.assert.calledWithMatch(res.cookie, 'test_key', re);
      sinon.assert.calledWithMatch(res.cookie, '_test_key', re);
    });

    it('should use the config.secure property to automatically set cookies secure', function () {
      const transientHandlerHttps = new TransientCookieHandler({
        secret,
        session: { cookie: { secure: true } },
        legacySameSiteCookie: true,
      });
      const transientHandlerHttp = new TransientCookieHandler({
        secret,
        session: { cookie: { secure: false } },
        legacySameSiteCookie: true,
      });
      transientHandlerHttps.store('test_key', {}, res, {
        sameSite: 'Lax',
      });
      transientHandlerHttp.store('test_key', {}, res, {
        sameSite: 'Lax',
      });

      sinon.assert.calledWithMatch(res.cookie.firstCall, 'test_key', '', {
        sameSite: 'Lax',
        secure: true,
      });
      sinon.assert.calledWithMatch(res.cookie.secondCall, 'test_key', '', {
        sameSite: 'Lax',
        secure: false,
      });
    });

    it('should set SameSite=None, secure, and fallback cookie by default', function () {
      transientHandler.store('test_key', {}, res);

      sinon.assert.calledWithMatch(res.cookie, 'test_key', '', {
        sameSite: 'None',
        secure: true,
        httpOnly: true,
      });
      sinon.assert.calledWithMatch(res.cookie, '_test_key', '', {
        sameSite: undefined,
        secure: undefined,
        httpOnly: true,
      });
    });

    it('should turn off fallback', function () {
      transientHandler = new TransientCookieHandler({
        secret,
        legacySameSiteCookie: false,
      });
      transientHandler.store('test_key', {}, res);

      sinon.assert.calledWith(res.cookie, 'test_key');
      sinon.assert.calledOnce(res.cookie);
    });

    it('should set custom SameSite with no fallback', function () {
      transientHandler.store('test_key', {}, res, { sameSite: 'Lax' });

      sinon.assert.calledWithMatch(res.cookie, 'test_key', '', {
        sameSite: 'Lax',
      });
      sinon.assert.calledOnce(res.cookie);
    });

    it('should use the passed-in value', function () {
      const value = transientHandler.store('test_key', {}, res, {
        value: '__test_value__',
      });
      assert.equal('__test_value__', value);
      const re = /^__test_value__\./;
      sinon.assert.calledWithMatch(res.cookie, 'test_key', re);
      sinon.assert.calledWithMatch(res.cookie, '_test_key', re);
    });
  });

  describe('getOnce()', function () {
    it('should return undefined if there are no cookies', function () {
      assert.isUndefined(
        transientHandler.getOnce('test_key', reqWithCookies(), res)
      );
    });

    it('should delete both cookies with a secure iframe config', function () {
      const transientHandlerHttpsIframe = new TransientCookieHandler({
        secret,
        session: { cookie: { secure: true, sameSite: 'None' } },
        legacySameSiteCookie: true,
      });
      const signature = generateSignature('test_key', 'foo');
      const cookies = {
        test_key: `foo.${signature}`,
        _test_key: `foo.${signature}`,
      };
      const req = reqWithCookies(cookies);
      const value = transientHandlerHttpsIframe.getOnce('test_key', req, res);

      assert.equal(value, 'foo');

      sinon.assert.calledWithMatch(res.clearCookie, 'test_key', {
        sameSite: 'None',
        secure: true,
      });
      sinon.assert.calledWithMatch(res.clearCookie, '_test_key', {
        sameSite: undefined,
        secure: undefined,
      });
    });

    it('should return fallback value and delete both cookies if main value not present', function () {
      const cookies = {
        _test_key: `foo.${generateSignature('_test_key', 'foo')}`,
      };
      const req = reqWithCookies(cookies);
      const value = transientHandler.getOnce('test_key', req, res);

      assert.equal(value, 'foo');

      sinon.assert.calledWith(res.clearCookie, 'test_key');
      sinon.assert.calledWith(res.clearCookie, '_test_key');
    });

    it('should not delete fallback cookie if legacy support is off', function () {
      const signature = generateSignature('test_key', 'foo');
      const cookies = {
        test_key: `foo.${signature}`,
        _test_key: `foo.${signature}`,
      };
      const req = reqWithCookies(cookies);
      transientHandler = new TransientCookieHandler({
        secret,
        legacySameSiteCookie: false,
      });
      const value = transientHandler.getOnce('test_key', req, res);

      assert.equal(value, 'foo');

      sinon.assert.calledWith(res.clearCookie, 'test_key');
      sinon.assert.calledOnce(res.clearCookie);
    });

    it("should not throw when it can't verify the signature", function () {
      const cookies = {
        test_key: 'foo.bar',
        _test_key: 'foo.bar',
      };
      const req = reqWithCookies(cookies);
      const value = transientHandler.getOnce('test_key', req, res);

      assert.isUndefined(value);
      sinon.assert.calledTwice(res.clearCookie);
    });
  });
});
