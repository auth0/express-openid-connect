const crypto = require('crypto');
const { FlattenedSign, flattenedVerify } = require('jose');

const BYTE_LENGTH = 32;
const ENCRYPTION_INFO = 'JWE CEK';
const SIGNING_INFO = 'JWS Cookie Signing';
const DIGEST = 'sha256';
const ALG = 'HS256';
const CRITICAL_HEADER_PARAMS = ['b64'];

/**
 *
 * Derives appropriate sized keys from the end-user provided secret random string/passphrase using
 * HKDF (HMAC-based Extract-and-Expand Key Derivation Function) defined in RFC 8569.
 *
 * @see https://tools.ietf.org/html/rfc5869
 *
 */
const encryption = (secret) =>
  Buffer.from(
    crypto.hkdfSync(
      DIGEST,
      secret,
      Buffer.alloc(0),
      ENCRYPTION_INFO,
      BYTE_LENGTH
    )
  );
const signing = (secret) =>
  Buffer.from(
    crypto.hkdfSync(
      DIGEST,
      secret,
      Buffer.alloc(0),
      SIGNING_INFO,
      BYTE_LENGTH
    )
  );

/**
 * Creates a keystore (array of keys) from secrets.
 * Returns [currentKey, allKeys] where keys are Uint8Array buffers.
 */
const getKeyStore = (secret, forEncryption) => {
  const secrets = Array.isArray(secret) ? secret : [secret];
  const keys = secrets.map((secretString) =>
    forEncryption ? encryption(secretString) : signing(secretString)
  );
  const current = keys[0];
  // Return keys as an array (or single key if only one)
  const keystore = keys.length === 1 ? current : keys;
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

const generateSignature = async (cookie, value, key) => {
  const payload = getPayload(cookie, value);
  const jws = await new FlattenedSign(payload)
    .setProtectedHeader(header)
    .sign(key);
  return jws.signature;
};

const verifySignature = async (cookie, value, signature, keystore) => {
  const jws = flattenedJWSFromCookie(cookie, value, signature);
  const keys = Array.isArray(keystore) ? keystore : [keystore];

  for (const key of keys) {
    try {
      await flattenedVerify(jws, key, {
        algorithms: [ALG],
        crit: { b64: true },
      });
      return true;
      // eslint-disable-next-line no-unused-vars
    } catch (err) {
      // Try next key
    }
  }
  return false;
};

const verifyCookie = async (cookie, value, keystore) => {
  if (!value) {
    return undefined;
  }
  let signature;
  [value, signature] = value.split('.');
  if (await verifySignature(cookie, value, signature, keystore)) {
    return value;
  }

  return undefined;
};

const signCookie = async (cookie, value, key) => {
  const signature = await generateSignature(cookie, value, key);
  return `${value}.${signature}`;
};

module.exports.signCookie = signCookie;
module.exports.verifyCookie = verifyCookie;

module.exports.getKeyStore = getKeyStore;
module.exports.encryption = encryption;
module.exports.signing = signing;
