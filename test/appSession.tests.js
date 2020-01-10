const assert = require('chai').assert;
const appSession = require('../lib/appSession');
const sessionEncryption = require('./fixture/sessionEncryption');

const defaultConfig = {
  name: 'identity',
  secret: '__test_secret__',
  duration: 1234567890,
  cookieOptions: {}
};

const req = {
  get: (key) => key
};
const res = {};
const next = () => true;

describe('appSession', function() {

  describe('no session cookies, no session property', () => {
    const appSessionMw = appSession(defaultConfig);
    const result = appSessionMw(req, res, next);

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
    const result = appSessionMw(thisReq, res, next);

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
      assert.throws(() => appSessionMw(thisReq, res, next), Error, 'JWE malformed or invalid serialization');
    });
  });

  describe('existing session cookies', () => {
    const appSessionMw = appSession(defaultConfig);
    const thisReq = {get: () => 'identity=' + sessionEncryption.encrypted};

    it('should set the identity on req', function() {
      const result = appSessionMw(thisReq, res, next);
      assert.ok(result);
      assert.equal(thisReq.identity.sub, '__test_sub__');
    });
  });
});
