const crypto = require('crypto');

const { encryption: deriveKey } = require('../../lib/crypto');
const epoch = () => (Date.now() / 1000) | 0;

const key = deriveKey('__test_secret__');
const payload = JSON.stringify({ sub: '__test_sub__' });
const epochNow = epoch();
const weekInSeconds = 7 * 24 * 60 * 60;

// Create a JWE manually using crypto (synchronous) instead of jose v5's async APIs
// This follows the Compact JWE Serialization format: BASE64URL(UTF8(JWE Protected Header)) || '.' ||
// BASE64URL(JWE Encrypted Key) || '.' || BASE64URL(JWE Initialization Vector) || '.' ||
// BASE64URL(JWE Ciphertext) || '.' || BASE64URL(JWE Authentication Tag)

const protectedHeader = {
  alg: 'dir',
  enc: 'A256GCM',
  uat: epochNow,
  iat: epochNow,
  exp: epochNow + weekInSeconds,
};

const encodedProtectedHeader = Buffer.from(
  JSON.stringify(protectedHeader),
).toString('base64url');

// For 'dir' algorithm, there is no JWE Encrypted Key (empty)
const encodedEncryptedKey = '';

// Generate IV (96 bits for GCM)
const iv = crypto.randomBytes(12);
const encodedIV = iv.toString('base64url');

// AAD (Additional Authenticated Data) is the encoded protected header
const aad = Buffer.from(encodedProtectedHeader, 'ascii');

// Encrypt the payload
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
cipher.setAAD(aad);

let ciphertext = cipher.update(payload, 'utf8');
ciphertext = Buffer.concat([ciphertext, cipher.final()]);
const encodedCiphertext = ciphertext.toString('base64url');

// Get the authentication tag
const authTag = cipher.getAuthTag();
const encodedAuthTag = authTag.toString('base64url');

// Construct the JWE Compact Serialization
const jwe = `${encodedProtectedHeader}.${encodedEncryptedKey}.${encodedIV}.${encodedCiphertext}.${encodedAuthTag}`;

// Decrypt to verify
const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
decipher.setAAD(aad);
decipher.setAuthTag(authTag);

let decrypted = decipher.update(ciphertext);
decrypted = Buffer.concat([decrypted, decipher.final()]);

module.exports = {
  encrypted: jwe,
  decrypted: decrypted,
};
