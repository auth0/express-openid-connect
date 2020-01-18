const assert = require('chai').assert;
const appSession = require('../lib/appSession');
const sessionEncryption = require('./fixture/sessionEncryption');

const defaultConfig = {
  name: 'identity',
  secret: '__test_secret__',
  duration: 3155760000, // 100 years
  cookieOptions: {}
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

    it('should set an empty identity', function() {
      assert.isEmpty(req.identity);
    });
  });

  describe('no session cookies, existing session property', () => {
    const appSessionMw = appSession(defaultConfig);
    const thisReq = Object.assign({}, req, {identity: {sub: '__test_existing_sub__'}});
    const result = appSessionMw(thisReq, {}, next);

    it('should call next', function() {
      assert.ok(result);
    });

    it('should keep existing identity', function() {
      assert.equal(thisReq.identity.sub, '__test_existing_sub__');
    });
  });

  describe('malformed session cookies', () => {
    const appSessionMw = appSession(defaultConfig);
    const thisReq = {get: () => 'identity=__invalid_identity__'};

    it('should error with malformed identity', function() {
      assert.throws(() => appSessionMw(thisReq, {}, next), Error, 'JWE malformed or invalid serialization');
    });
  });

  describe('existing session cookies', () => {
    const appSessionMw = appSession(defaultConfig);
    const thisReq = {get: () => 'identity=' + sessionEncryption.encrypted};

    it('should set the identity on req', function() {
      const result = appSessionMw(thisReq, {}, next);
      assert.ok(result);
      assert.equal(thisReq.identity.sub, '__test_sub__');

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
      const thisReq = {get: () => 'identity=' + sessionEncryption.encrypted};
      const appSessionMw = appSession(defaultConfig);
      const result = appSessionMw(thisReq, thisRes, next);
      thisRes.writeHead();

      assert.ok(result);
      assert.equal(cookieArgs['0'], 'identity');
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
      const thisReq = {get: () => 'identity=' + sessionEncryption.encrypted};
      const customConfig = Object.assign({}, defaultConfig, {cookieOptions: {ephemeral: true}});
      const appSessionMw = appSession(customConfig);
      const result = appSessionMw(thisReq, thisRes, next);
      thisRes.writeHead();

      assert.ok(result);
      assert.equal(cookieArgs['2'].expires, 0);
    });

    it('should pass custom cookie options', function() {
      const thisReq = {get: () => 'identity=' + sessionEncryption.encrypted};
      const cookieOptConfig = {cookieOptions: {
        domain: '__test_domain__',
        path: '__test_path__',
        secure: true,
        httpOnly: false,
        sameSite: '__test_samesite__',
      }};
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
