const { strict: assert } = require('assert');

const { JWK, JWKS, JWE } = require('jose');
const onHeaders = require('on-headers');
const cookie = require('cookie');
const hkdf = require('futoin-hkdf');

const deriveKey = (secret) => hkdf(secret, 32, { info: 'JWE CEK', hash: 'SHA-256' });
const epoch = () => Date.now() / 1000 | 0;

module.exports = ({ cookieName, propertyName, secret, duration, ephemeral, cookieOptions = {} }) => {
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
    if ((!req[propertyName] || !Object.keys(req[propertyName]).length) && cookieName in req[COOKIES]) {
      res.clearCookie(cookieName);
      return;
    }

    if (req[propertyName] && Object.keys(req[propertyName]).length > 0) {
      const value = encrypt(JSON.stringify(req[propertyName]), { iat, uat, exp });

      // TODO: chunk
      // if (Buffer.byteLength(value) >= 4050) {
      //
      // }

      res.cookie(
        cookieName,
        value,
        {
          domain,
          httpOnly,
          path,
          secure,
          sameSite,
          expires: ephemeral ? 0 : new Date(exp * 1000)
        }
      );
    }
  }

  return (req, res, next) => {
    if (!(COOKIES in req)) {
      req[COOKIES] = cookie.parse(req.get('cookie') || '');
    }

    if (propertyName in req) {
      return next();
    }

    let iat;
    let exp;

    try {
      // TODO: detect and join chunks
      if (cookieName in req[COOKIES]) {
        const { protected: header, cleartext } = decrypt(req[COOKIES][cookieName])
        ;({ iat, exp } = header);
        assert(exp > epoch());
        req[propertyName] = JSON.parse(cleartext);
      }
    } finally {
      if (!(propertyName in req)) {
        req[propertyName] = {};
      }
    }

    onHeaders(res, setCookie.bind(undefined, req, res, { iat }));

    return next();
  };
};
