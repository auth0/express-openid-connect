const { strict: assert } = require('assert');

const { JWK, JWKS, JWE } = require('jose');
const onHeaders = require('on-headers');
const cookie = require('cookie');
const hkdf = require('futoin-hkdf');

const deriveKey = (secret) => hkdf(secret, 32, { info: 'JWE CEK', hash: 'SHA-256' });
const epoch = () => Date.now() / 1000 | 0;

module.exports = ({ name, secret, duration, cookieOptions = {} }) => {
  let current;

  const { domain, httpOnly, path, secure, sameSite } = cookieOptions;

  const COOKIES = Symbol();
  const alg = 'dir';
  const enc = 'A256GCM';

  let keystore = new JWKS.KeyStore();

  if (!Array.isArray(secret)) {
    secret = [secret];
  }

  secret.forEach((secretString, i) => {
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
    return JWE.decrypt(jwe, keystore, { complete: true, algorithms: ['A256GCM'] });
  }

  function setCookie (req, res, { uat = epoch(), iat = uat, exp = uat + duration }) {
    if ((!req[name] || !Object.keys(req[name]).length) && name in req[COOKIES]) {
      res.clearCookie(name);
      return;
    }

    if (req[name] && Object.keys(req[name]).length > 0) {
      const value = encrypt(JSON.stringify(req[name]), { iat, uat, exp });

      res.cookie(
        name,
        value,
        {
          domain,
          httpOnly,
          path,
          secure,
          sameSite,
          expires: !duration ? 0 : new Date(exp * 1000)
        }
      );
    }
  }

  return (req, res, next) => {
    if (!(COOKIES in req)) {
      req[COOKIES] = cookie.parse(req.get('cookie') || '');
    }

    if (name in req) {
      return next();
    }

    let iat;
    let exp;

    try {
      // TODO: detect and join chunks
      if (name in req[COOKIES]) {
        const { protected: header, cleartext } = decrypt(req[COOKIES][name])
        ;({ iat, exp } = header);
        assert(exp > epoch());
        req[name] = JSON.parse(cleartext);
      }
    } finally {
      if (!(name in req)) {
        req[name] = {};
      }
    }

    onHeaders(res, setCookie.bind(undefined, req, res, { iat }));

    return next();
  };
};
