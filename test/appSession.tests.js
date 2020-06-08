const assert = require('chai').assert;
const appSession = require('../lib/appSession');
const sessionEncryption = require('./fixture/sessionEncryption');

const defaultConfig = {
  name: 'appSession',
  secret: '__test_secret__',
  duration: 3155760000, // 100 years
};

const req = {
  get: (key) => key
};
const next = () => true;

describe('appSession', function() {

  describe('no session cookies, no session property', () => {
    const appSessionMw = appSession(defaultConfig);
    const result = appSessionMw(req, {}, next);

    it('should call next', function() {
      assert.ok(result);
    });

    it('should set an empty appSession', function() {
      assert.isEmpty(req.appSession);
    });
  });

  describe('no session cookies, existing session property', () => {
    const appSessionMw = appSession(defaultConfig);
    const thisReq = Object.assign({}, req, {appSession: {sub: '__test_existing_sub__'}});
    const result = appSessionMw(thisReq, {}, next);

    it('should call next', function() {
      assert.ok(result);
    });

    it('should keep existing appSession', function() {
      assert.equal(thisReq.appSession.sub, '__test_existing_sub__');
    });
  });

  describe('malformed session cookies', () => {
    const appSessionMw = appSession(defaultConfig);
    const thisReq = {get: () => 'appSession=__invalid_identity__'};

    it('should error with malformed appSession', function() {
      assert.throws(() => appSessionMw(thisReq, {}, next), Error, 'JWE malformed or invalid serialization');
    });
  });

  describe('session cookies with old secrets', () => {
    const thisReq = {get: () => 'appSession=' + sessionEncryption.encrypted};
    const appSessionMw = appSession({ ...defaultConfig, secret: 'another secret' });

    it('should not error with JWEDecryptionFailed appSession', function() {
      const result = appSessionMw(thisReq, {}, next);
      assert.ok(result);
      assert.isEmpty(req.appSession);
    });
  });

  describe('session cookies with rotated secrets', () => {
    const thisReq = {get: () => 'appSession=' + sessionEncryption.encrypted};

    it('should use the old valid secret and re-encrypt using the new one', function() {
      let appSessionMw = appSession({ ...defaultConfig, secret: ['new secret', '__test_secret__'] });
      let result = appSessionMw(thisReq, {}, next);
      assert.ok(result);
      assert.equal(thisReq.appSession.sub, '__test_sub__');
      appSessionMw = appSession({ ...defaultConfig, secret: 'new secret' });
      result = appSessionMw(thisReq, {}, next);
      assert.ok(result);
      assert.equal(thisReq.appSession.sub, '__test_sub__');
    });
  });

  describe('existing session cookies', () => {
    const appSessionMw = appSession(defaultConfig);
    const thisReq = {get: () => 'appSession=' + sessionEncryption.encrypted};

    it('should set the appSession on req', function() {
      const result = appSessionMw(thisReq, {}, next);
      assert.ok(result);
      assert.equal(thisReq.appSession.sub, '__test_sub__');
    });
  });

  describe('sessioncookie options', () => {
    let cookieArgs;
    const thisRes = {
      cookie: function cookie() {cookieArgs = JSON.parse(JSON.stringify(arguments)); },
      writeHead: () => null,
      setHeader: () => null
    };

    beforeEach(function() {
      cookieArgs = {};
    });

    it('should set the correct cookie by default', function() {
      const thisReq = {get: () => 'appSession=' + sessionEncryption.encrypted};
      const appSessionMw = appSession(defaultConfig);
      const result = appSessionMw(thisReq, thisRes, next);
      thisRes.writeHead();

      assert.ok(result);
      assert.equal(cookieArgs['0'], 'appSession');
      assert.isNotEmpty(cookieArgs['1']);
      assert.isObject(cookieArgs['2']);
      assert.hasAllKeys(cookieArgs['2'], ['expires']);

      const expDate = new Date(cookieArgs['2'].expires);
      assert.equal( (expDate.getFullYear() - (new Date()).getFullYear()), 100);
    });

    it('should set the correct custom cookie name', function() {
      const thisReq = {get: () => 'customName=' + sessionEncryption.encrypted};
      const customConfig = Object.assign({}, defaultConfig, {name: 'customName'});
      const appSessionMw = appSession(customConfig);
      const result = appSessionMw(thisReq, thisRes, next);
      thisRes.writeHead();

      assert.ok(result);
      assert.equal(cookieArgs['0'], 'customName');
    });

    it('should set an ephemeral cookie', function() {
      const thisReq = {get: () => 'appSession=' + sessionEncryption.encrypted};
      const customConfig = Object.assign({}, defaultConfig, {cookieTransient: true});
      const appSessionMw = appSession(customConfig);
      const result = appSessionMw(thisReq, thisRes, next);
      thisRes.writeHead();

      assert.ok(result);
      assert.equal(cookieArgs['2'].expires, 0);
    });

    it('should pass custom cookie options', function() {
      const thisReq = {get: () => 'appSession=' + sessionEncryption.encrypted};
      const cookieOptConfig = {
        cookieDomain: '__test_domain__',
        cookiePath: '__test_path__',
        cookieSecure: true,
        cookieHttpOnly: false,
        cookieSameSite: '__test_samesite__',
      };
      const customConfig = Object.assign({}, defaultConfig, cookieOptConfig);
      const appSessionMw = appSession(customConfig);
      const result = appSessionMw(thisReq, thisRes, next);
      thisRes.writeHead();

      assert.ok(result);
      assert.equal(cookieArgs['2'].domain, '__test_domain__');
      assert.equal(cookieArgs['2'].path, '__test_path__');
      assert.equal(cookieArgs['2'].secure, true);
      assert.equal(cookieArgs['2'].httpOnly, false);
      assert.equal(cookieArgs['2'].sameSite, '__test_samesite__');
    });
  });
});
