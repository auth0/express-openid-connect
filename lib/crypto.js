import crypto from 'crypto';
import * as jose from 'jose';
import hkdf from 'futoin-hkdf';

const BYTE_LENGTH = 32;
const ENCRYPTION_INFO = 'JWE CEK';
const SIGNING_INFO = 'JWS Cookie Signing';
const DIGEST = 'sha256';

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
        BYTE_LENGTH,
      ),
    );
  signing = (secret) =>
    Buffer.from(
      crypto.hkdfSync(
        DIGEST,
        secret,
        Buffer.alloc(0),
        SIGNING_INFO,
        BYTE_LENGTH,
      ),
    );
} else {
  encryption = (secret) =>
    hkdf(secret, BYTE_LENGTH, { info: ENCRYPTION_INFO, hash: DIGEST });
  signing = (secret) =>
    hkdf(secret, BYTE_LENGTH, { info: SIGNING_INFO, hash: DIGEST });
}

const getKeyStore = (secret, forEncryption) => {
  let current;
  const secrets = Array.isArray(secret) ? secret : [secret];
  let keystore = [];
  secrets.forEach((secretString, i) => {
    const key = forEncryption
      ? encryption(secretString)
      : signing(secretString);
    if (i === 0) {
      current = key;
    }
    keystore.push(key);
  });
  return [current, keystore];
};

const getPayload = (cookie, value) => Buffer.from(`${cookie}=${value}`);
const generateSignature = (cookie, value, key) => {
  const payload = getPayload(cookie, value);
  const hmac = crypto.createHmac('sha256', key);
  hmac.update(payload);
  return hmac.digest('base64url');
};

const verifySignature = (cookie, value, signature, keystore) => {
  try {
    for (const key of keystore) {
      const expectedSignature = generateSignature(cookie, value, key);
      if (
        crypto.timingSafeEqual(
          Buffer.from(signature, 'base64url'),
          Buffer.from(expectedSignature, 'base64url'),
        )
      ) {
        return true;
      }
    }
    return false;
  } catch {
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

export { signCookie, verifyCookie, getKeyStore, encryption, signing };
