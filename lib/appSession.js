const { strict: assert } = require('assert');

const { JWK, JWKS, JWE } = require('jose');
const onHeaders = require('on-headers');
const cookie = require('cookie');
const hkdf = require('futoin-hkdf');

const deriveKey = (secret) => hkdf(secret, 32, { info: 'JWE CEK', hash: 'SHA-256' });
const epoch = () => Date.now() / 1000 | 0;

module.exports = (sessionConfig) => {
  let current;

  const COOKIES = Symbol('cookies');
  const alg = 'dir';
  const enc = 'A256GCM';

  let keystore = new JWKS.KeyStore();

  if (!Array.isArray(sessionConfig.secret)) {
    sessionConfig.secret = [sessionConfig.secret];
  }

  sessionConfig.secret.forEach((secretString, i) => {
    const key = JWK.asKey(deriveKey(secretString));
    if (i === 0) {
      current = key;
    }
    keystore.add(key);
  });

  if (keystore.size === 1) {
    keystore = current;
  }

  function encrypt (payload, headers) {
    return JWE.encrypt(payload, current, { alg, enc, zip: 'DEF', ...headers });
  }

  function decrypt (jwe) {
    return JWE.decrypt(jwe, keystore, { complete: true, algorithms: [enc] });
  }

  function setCookie (req, res, { uat = epoch(), iat = uat, exp = uat + sessionConfig.duration }) {
    if ((!req[sessionConfig.name] || !Object.keys(req[sessionConfig.name]).length) && sessionConfig.name in req[COOKIES]) {
      res.clearCookie(sessionConfig.name);
      return;
    }

    if (req[sessionConfig.name] && Object.keys(req[sessionConfig.name]).length > 0) {
      const value = encrypt(JSON.stringify(req[sessionConfig.name]), { iat, uat, exp });

      const cookieOptions = {};
      Object.keys(sessionConfig).filter(key => /^cookie/.test(key)).forEach(function(key) {
        cookieOptions[key.replace('cookie', '').toLowerCase()] = sessionConfig[key];
      });

      cookieOptions.expires = cookieOptions.transient ? 0 : new Date(exp * 1000);
      delete cookieOptions.transient;

      res.cookie(sessionConfig.name, value, cookieOptions);
    }
  }

  return (req, res, next) => {
    if (!req.hasOwnProperty(COOKIES)) {
      req[COOKIES] = cookie.parse(req.get('cookie') || '');
    }

    if (req.hasOwnProperty(sessionConfig.name)) {
      return next();
    }

    let iat;
    let exp;

    try {

      if (req[COOKIES].hasOwnProperty(sessionConfig.name)) {
        const { protected: header, cleartext } = decrypt(req[COOKIES][sessionConfig.name]);
        ({ iat, exp } = header);
        assert(exp > epoch());
        req[sessionConfig.name] = JSON.parse(cleartext);
      }
    } finally {
      if (!req.hasOwnProperty(sessionConfig.name) || !req[sessionConfig.name]) {
        req[sessionConfig.name] = {};
      }
    }

    onHeaders(res, setCookie.bind(undefined, req, res, { iat }));

    return next();
  };
};
