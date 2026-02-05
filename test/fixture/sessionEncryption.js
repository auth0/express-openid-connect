const { CompactEncrypt, compactDecrypt } = require('jose');

const { encryption: deriveKey } = require('../../lib/crypto');
const epoch = () => (Date.now() / 1000) | 0;

const keyBuffer = deriveKey('__test_secret__');
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

let encrypted;
let decrypted;

const init = (async () => {
  const encoder = new TextEncoder();

  // Create the JWE
  encrypted = await new CompactEncrypt(encoder.encode(payload))
    .setProtectedHeader({
      alg: encryptOpts.alg,
      enc: encryptOpts.enc,
      uat: encryptOpts.uat,
      iat: encryptOpts.iat,
      exp: encryptOpts.exp,
    })
    .encrypt(keyBuffer);

  // Decrypt it back
  const { plaintext } = await compactDecrypt(encrypted, keyBuffer, {
    contentEncryptionAlgorithms: [encryptOpts.enc],
    keyManagementAlgorithms: [encryptOpts.alg],
  });
  decrypted = plaintext;
})();

module.exports = {
  get encrypted() {
    return encrypted;
  },
  get decrypted() {
    return decrypted;
  },
  init,
};
