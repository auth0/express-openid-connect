import * as jose from 'jose';

import crypto from 'crypto';
import { encryption as deriveKey } from '../../lib/crypto.js';

const epoch = () => (Date.now() / 1000) | 0;

const key = deriveKey('__test_secret__');
const payload = JSON.stringify({ sub: '__test_sub__' });
const epochNow = epoch();
const weekInSeconds = 7 * 24 * 60 * 60;

const encryptOpts = {
  alg: 'dir',
  enc: 'A256GCM',
  uat: epochNow,
  iat: epochNow,
  exp: epochNow + weekInSeconds,
};

// Use synchronous encryption matching appSession.js approach
function encrypt(payload, headers) {
  const algorithm = 'aes-256-gcm';
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(algorithm, key, iv);

  let encrypted = cipher.update(payload, 'utf8', 'base64url');
  encrypted += cipher.final('base64url');
  const tag = cipher.getAuthTag();

  // Create JWE-like compact format with headers
  const protectedHeader = Buffer.from(
    JSON.stringify({
      alg: 'dir',
      enc: 'A256GCM',
      ...headers,
    }),
  ).toString('base64url');

  return `${protectedHeader}..${iv.toString('base64url')}.${encrypted}.${tag.toString('base64url')}`;
}

function decrypt(jweCompact) {
  // Parse compact serialization
  const parts = jweCompact.split('.');
  const protectedHeader = parts[0];
  const iv = parts[2];
  const ciphertext = parts[3];
  const tag = parts[4];

  const algorithm = 'aes-256-gcm';
  const decipher = crypto.createDecipheriv(
    algorithm,
    key,
    Buffer.from(iv, 'base64url'),
  );
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));

  let decrypted = decipher.update(ciphertext, 'base64url', 'utf8');
  decrypted += decipher.final('utf8');

  return {
    payload: decrypted,
    protected: JSON.parse(Buffer.from(protectedHeader, 'base64url').toString()),
  };
}

const encrypted = encrypt(payload, encryptOpts);
const { payload: decrypted } = decrypt(encrypted);

export default {
  encrypted,
  decrypted,
};
