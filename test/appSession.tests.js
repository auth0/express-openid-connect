const assert = require('chai').assert;
const merge = require('lodash/merge');
const crypto = require('crypto');

const appSession = require('../lib/appSession');
const sessionEncryption = require('./fixture/sessionEncryption');
const { get: getConfig } = require('../lib/config');

const defaultConfig = getConfig({
  clientID: '__test_client_id__',
  clientSecret: '__test_client_secret__',
  issuerBaseURL: 'https://op.example.com',
  baseURL: 'https://example.org',
  secret: '__test_secret__',
});

const next = (err) => {
  if (err) {
    throw err;
  }
  return true;
};

describe('appSession', function () {
  describe('no session cookies, no session property', () => {
    let req;
    let appSessionMw;
    let result;

    before(() => {
      req = { get: (key) => key };
      appSessionMw = appSession(defaultConfig);
      result = appSessionMw(req, {}, next);
    });

    it('should call next', function () {
      assert.ok(result);
    });

    it('should set an empty session', function () {
      assert.isEmpty(req.appSession);
    });
  });

  describe('malformed session cookies', () => {
    let thisReq;
    let appSessionMw;

    before(() => {
      appSessionMw = appSession(defaultConfig);
      thisReq = { get: () => 'appSession=__invalid_identity__' };
    });

    it('should not error with malformed appSession', function () {
      const result = appSessionMw(thisReq, {}, next);
      assert.ok(result);
      assert.isEmpty(thisReq.appSession);
    });
  });

  describe('session cookies with old secrets', () => {
    let thisReq;
    let appSessionMw;

    before(() => {
      thisReq = { get: () => 'appSession=' + sessionEncryption.encrypted };
      appSessionMw = appSession({ ...defaultConfig, secret: 'another secret' });
    });

    it('should not error with JWEDecryptionFailed appSession', function() {
      const result = appSessionMw(thisReq, {}, next);
      assert.ok(result);
      assert.isEmpty(thisReq.appSession);
    });
  });

  describe('existing session cookies', () => {
    let thisReq;
    let appSessionMw;

    before(() => {
      appSessionMw = appSession(defaultConfig);
      thisReq = { get: () => 'appSession=' + sessionEncryption.encrypted };
    });

    it('should set the session on req', function () {
      const result = appSessionMw(thisReq, {}, next);
      assert.ok(result);
      assert.equal(thisReq.appSession.sub, '__test_sub__');
    });
  });

  describe('session cookie chunking', () => {
    let cookieArgs;
    let thisRes;

    before(() => {
      cookieArgs = [];
      thisRes = {
        cookie: function cookie () { cookieArgs.push(JSON.parse(JSON.stringify(arguments))); },
        writeHead: () => null,
        setHeader: () => null
      };
    });

    it('should chunk and accept chunked cookies', function () {
      const appSessionMw = appSession(defaultConfig);
      let cookie = '';
      // req 1, chunks a new session
      {
        const thisReq = { get: () => '' };
        appSessionMw(thisReq, thisRes, () => {
          thisReq.appSession.sub = '__new_sub__';
          thisReq.appSession.random = crypto.randomBytes(4000).toString('base64');
        });
        thisRes.writeHead();

        assert.equal(cookieArgs.length, 2);
        cookieArgs.forEach(({ 0: cookieName, 1: cookieValue }, index) => {
          cookie += `${cookieName}=${cookieValue};`;
          assert.equal(cookieName, `appSession.${index}`);
        });
      }
      // req 2, accepts a cookie-chunked session
      {
        let result;
        const thisReq = { get: () => cookie };
        appSessionMw(thisReq, thisRes, () => {
          result = thisReq.appSession;
        });
        assert.ok(result);
        assert.equal(result.sub, '__new_sub__');
        assert.ok(result.random);
      }
    });
  });

  describe('session cookie options', () => {
    let cookieArgs;
    let thisRes;

    before(() => {
      cookieArgs;
      thisRes = {
        cookie: function cookie () { cookieArgs = JSON.parse(JSON.stringify(arguments)); },
        writeHead: () => null,
        setHeader: () => null
      };
    });

    beforeEach(function () {
      cookieArgs = {};
    });

    it('should set the correct cookie by default', function () {
      const thisReq = { get: () => 'appSession=' + sessionEncryption.encrypted };
      const appSessionMw = appSession(defaultConfig);
      const result = appSessionMw(thisReq, thisRes, next);
      thisRes.writeHead();

      assert.ok(result);
      assert.equal(cookieArgs['0'], 'appSession');
      assert.isNotEmpty(cookieArgs['1']);
      assert.isObject(cookieArgs['2']);
      assert.hasAllKeys(cookieArgs['2'], ['expires', 'httpOnly', 'sameSite']);

      const expDate = new Date(cookieArgs['2'].expires);
      const now = new Date();
      assert.approximately(Math.floor((expDate - now) / 1000), 86400, 5);
    });

    it('should set the correct custom cookie name', function () {
      const thisReq = { get: () => 'customName=' + sessionEncryption.encrypted };
      const customConfig = merge({}, defaultConfig, { session: { name: 'customName' } });
      const appSessionMw = appSession(customConfig);
      const result = appSessionMw(thisReq, thisRes, next);
      thisRes.writeHead();

      assert.ok(result);
      assert.equal(cookieArgs['0'], 'customName');
    });

    it('should set an ephemeral cookie', function () {
      const thisReq = { get: () => 'appSession=' + sessionEncryption.encrypted };
      const customConfig = merge({}, defaultConfig, { session: { cookie: { transient: true } } });
      const appSessionMw = appSession(customConfig);
      const result = appSessionMw(thisReq, thisRes, next);
      thisRes.writeHead();

      assert.ok(result);
      assert.equal(cookieArgs['2'].expires, 0);
    });

    it('should pass custom cookie options', function () {
      const thisReq = { get: () => 'appSession=' + sessionEncryption.encrypted };
      const cookieOptConfig = {
        cookie: {
          domain: '__test_domain__',
          secure: true,
          httpOnly: false,
          sameSite: '__test_samesite__'
        }
      };
      const customConfig = merge({}, defaultConfig, { session: cookieOptConfig });
      const appSessionMw = appSession(customConfig);
      const result = appSessionMw(thisReq, thisRes, next);
      thisRes.writeHead();

      assert.ok(result);
      assert.equal(cookieArgs['2'].domain, '__test_domain__');
      assert.equal(cookieArgs['2'].secure, true);
      assert.equal(cookieArgs['2'].httpOnly, false);
      assert.equal(cookieArgs['2'].sameSite, '__test_samesite__');
    });
  });
});
