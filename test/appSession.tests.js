const assert = require('chai').assert;
const appSession = require('../lib/appSession');

const defaultConfig = {
  name: 'identity',
  secret: '__test_secret__',
  duration: 1234567890,
  cookieOptions: {}
};

let req = {
  get: (key) => key
};
let res = {};
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
    const thisReq = {
      // Encypted '{sub:"__test_sub__"}' with '__test_secret__'
      get: () => 'identity=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiemlwIjoiREVGIiwidWF0IjoxNTc3ODI2NzY5' +
      'LCJpYXQiOjE1Nzc4MjY3NjksImV4cCI6MTU3ODQzMTU2OX0..4XocWueShMw1cD_b.EhS_rNI4HeCFSlJTxKowE1SwLfsEfg' +
      '.JKMnZOkBjwi-9Z5BSHliiw'
    };
    const result = appSessionMw(thisReq, res, next);

    it('should call next', function() {
      assert.ok(result);
    });

    it('should set the identity on req', function() {
      assert.equal(thisReq.identity.sub, '__test_sub__');
    });
  });
});
