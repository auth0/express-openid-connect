const { strict: assert } = require('assert');
const { JWK, JWKS, JWE } = require('jose');
const onHeaders = require('on-headers');
const cookie = require('cookie');
const hkdf = require('futoin-hkdf');

const { sessionNameDefault, sessionDurationDefault } = require('./config');

const deriveKey = (secret) => hkdf(secret, 32, { info: 'JWE CEK', hash: 'SHA-256' });
const epoch = () => Date.now() / 1000 | 0;

module.exports = (sessionConfig) => {
  let current;

  const COOKIES = Symbol('cookies');
  const alg = 'dir';
  const enc = 'A256GCM';
  const sessionSecrets = Array.isArray(sessionConfig.secret) ? sessionConfig.secret : [sessionConfig.secret];
  const sessionName = sessionConfig.name || sessionNameDefault;
  const sessionDuration = sessionConfig.duration || sessionDurationDefault;

  let keystore = new JWKS.KeyStore();

  sessionSecrets.forEach((secretString, i) => {
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

  function setCookie (req, res, { uat = epoch(), iat = uat, exp = uat + sessionDuration }) {
    if ((!req[sessionName] || !Object.keys(req[sessionName]).length) && sessionName in req[COOKIES]) {
      res.clearCookie(sessionName);
      return;
    }

    if (req[sessionName] && Object.keys(req[sessionName]).length > 0) {
      const value = encrypt(JSON.stringify(req[sessionName]), { iat, uat, exp });

      const cookieOptions = {};
      Object.keys(sessionConfig).filter(key => /^cookie/.test(key)).forEach(function(key) {
        const cookieOptionKey = key.replace(/^cookie([A-Z])/, (match, p1) => p1.toLowerCase());
        cookieOptions[cookieOptionKey] = sessionConfig[key];
      });

      cookieOptions.expires = cookieOptions.transient ? 0 : new Date(exp * 1000);
      delete cookieOptions.transient;

      res.cookie(sessionName, value, cookieOptions);
    }
  }

  return (req, res, next) => {
    if (!req.hasOwnProperty(COOKIES)) {
      req[COOKIES] = cookie.parse(req.get('cookie') || '');
    }

    if (req.hasOwnProperty(sessionName)) {
      return next();
    }

    let iat;
    let exp;

    try {

      if (req[COOKIES].hasOwnProperty(sessionName)) {
        const { protected: header, cleartext } = decrypt(req[COOKIES][sessionName]);
        ({ iat, exp } = header);
        assert(exp > epoch());
        req[sessionName] = JSON.parse(cleartext);
      }
    } finally {
      if (!req.hasOwnProperty(sessionName) || !req[sessionName]) {
        req[sessionName] = {};
      }
    }

    onHeaders(res, setCookie.bind(undefined, req, res, { iat }));

    return next();
  };
};
