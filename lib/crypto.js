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
      BYTE_LENGTH,
    ),
  );
const signing = (secret) =>
  Buffer.from(
    crypto.hkdfSync(DIGEST, secret, Buffer.alloc(0), SIGNING_INFO, BYTE_LENGTH),
  );

/**
 * Creates a keystore (array of keys) from secrets.
 * Returns [currentKey, allKeys] where keys are Uint8Array buffers.
 */
const getKeyStore = (secret, forEncryption) => {
  const secrets = Array.isArray(secret) ? secret : [secret];
  const keys = secrets.map((secretString) =>
    forEncryption ? encryption(secretString) : signing(secretString),
  );
  const current = keys[0];
  // Always return keys as an array for consistent handling by callers
  return [current, keys];
};

const header = { alg: ALG, b64: false, crit: CRITICAL_HEADER_PARAMS };

const PROTECTED_HEADER_B64 = Buffer.from(JSON.stringify(header))
  .toString('base64')
  .replace(/=/g, '')
  .replace(/\+/g, '-')
  .replace(/\//g, '_');

const getPayload = (cookie, value) => Buffer.from(`${cookie}=${value}`);

const flattenedJWSFromCookie = (cookie, value, signature) => ({
  protected: PROTECTED_HEADER_B64,
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

const generateSignatureSync = (cookie, value, key) => {
  const payload = getPayload(cookie, value);
  // JWS signing input for b64:false = ASCII(protectedHeader) + '.' + payload bytes (RFC 7797)
  const signingInput = Buffer.concat([
    Buffer.from(PROTECTED_HEADER_B64, 'ascii'),
    Buffer.from('.'),
    payload,
  ]);
  return crypto
    .createHmac('sha256', key)
    .update(signingInput)
    .digest('base64url');
};

const verifySignature = async (cookie, value, signature, keystore) => {
  const jws = flattenedJWSFromCookie(cookie, value, signature);

  for (const key of keystore) {
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

const signCookieSync = (cookie, value, key) => {
  const signature = generateSignatureSync(cookie, value, key);
  return `${value}.${signature}`;
};

/**
 * Synchronous AES-256-GCM JWE (alg=dir, enc=A256GCM) in Compact Serialization format.
 *
 * Produces output identical in format to jose v6 CompactEncrypt — jose v6 compactDecrypt
 * can decrypt tokens produced by this function transparently.
 *
 * The JWE Compact format is five base64url segments: header..iv.ciphertext.tag
 * The encrypted-key segment (index 1) is empty for alg=dir (key IS the CEK).
 * AAD is the ASCII bytes of the base64url-encoded protected header (RFC 7516 §5.1 step 14).
 *
 * @param {string} payload   UTF-8 plaintext (typically JSON)
 * @param {Buffer} key       32-byte AES-256 CEK (HKDF-derived)
 * @param {object} headers   Additional fields merged into the protected header
 * @returns {string}         JWE Compact Serialization string
 */
const encryptSync = (payload, key, headers) => {
  const protectedHeader = Buffer.from(
    JSON.stringify({ alg: 'dir', enc: 'A256GCM', ...headers }),
  )
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(protectedHeader, 'ascii'));

  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(payload, 'utf8')),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag(); // 16 bytes (128-bit tag) by default

  const b64url = (buf) =>
    buf
      .toString('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');

  return `${protectedHeader}..${b64url(iv)}.${b64url(ciphertext)}.${b64url(tag)}`;
};

module.exports.signCookie = signCookie;
module.exports.signCookieSync = signCookieSync;
module.exports.verifyCookie = verifyCookie;
module.exports.encryptSync = encryptSync;

module.exports.getKeyStore = getKeyStore;
module.exports.encryption = encryption;
module.exports.signing = signing;
