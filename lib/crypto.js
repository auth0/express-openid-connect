const crypto = require('crypto');
const { JWKS, JWK, JWS } = require('jose');

const BYTE_LENGTH = 32;
const ENCRYPTION_INFO = 'JWE CEK';
const SIGNING_INFO = 'JWS Cookie Signing';
const DIGEST = 'sha256';
const ALG = 'HS256';
const CRITICAL_HEADER_PARAMS = ['b64'];

let encryption, signing;

/**
 *
 * Derives appropriate sized keys from the end-user provided secret random string/passphrase using
 * HKDF (HMAC-based Extract-and-Expand Key Derivation Function) defined in RFC 8569.
 *
 * @see https://tools.ietf.org/html/rfc5869
 *
 */
/* istanbul ignore else */
if (crypto.hkdfSync) {
  // added in v15.0.0
  encryption = (secret) =>
    Buffer.from(
      crypto.hkdfSync(
        DIGEST,
        secret,
        Buffer.alloc(0),
        ENCRYPTION_INFO,
        BYTE_LENGTH
      )
    );
  signing = (secret) =>
    Buffer.from(
      crypto.hkdfSync(
        DIGEST,
        secret,
        Buffer.alloc(0),
        SIGNING_INFO,
        BYTE_LENGTH
      )
    );
} else {
  const hkdf = require('futoin-hkdf');
  encryption = (secret) =>
    hkdf(secret, BYTE_LENGTH, { info: ENCRYPTION_INFO, hash: DIGEST });
  signing = (secret) =>
    hkdf(secret, BYTE_LENGTH, { info: SIGNING_INFO, hash: DIGEST });
}

const getKeyStore = (secret, forEncryption) => {
  let current;
  const secrets = Array.isArray(secret) ? secret : [secret];
  let keystore = new JWKS.KeyStore();
  secrets.forEach((secretString, i) => {
    const key = JWK.asKey(
      forEncryption ? encryption(secretString) : signing(secretString)
    );
    if (i === 0) {
      current = key;
    }
    keystore.add(key);
  });
  return [current, keystore];
};

const header = { alg: ALG, b64: false, crit: CRITICAL_HEADER_PARAMS };

const getPayload = (cookie, value) => Buffer.from(`${cookie}=${value}`);
const flattenedJWSFromCookie = (cookie, value, signature) => ({
  protected: Buffer.from(JSON.stringify(header))
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_'),
  payload: getPayload(cookie, value),
  signature,
});
const generateSignature = (cookie, value, key) => {
  const payload = getPayload(cookie, value);
  return JWS.sign.flattened(payload, key, header).signature;
};
const verifySignature = (cookie, value, signature, keystore) => {
  try {
    return !!JWS.verify(
      flattenedJWSFromCookie(cookie, value, signature),
      keystore,
      { algorithms: [ALG], crit: CRITICAL_HEADER_PARAMS }
    );
    // eslint-disable-next-line no-unused-vars
  } catch (err) {
    return false;
  }
};
const verifyCookie = (cookie, value, keystore) => {
  if (!value) {
    return undefined;
  }
  let signature;
  [value, signature] = value.split('.');
  if (verifySignature(cookie, value, signature, keystore)) {
    return value;
  }

  return undefined;
};

const signCookie = (cookie, value, key) => {
  const signature = generateSignature(cookie, value, key);
  return `${value}.${signature}`;
};

module.exports.signCookie = signCookie;
module.exports.verifyCookie = verifyCookie;

module.exports.getKeyStore = getKeyStore;
module.exports.encryption = encryption;
module.exports.signing = signing;
