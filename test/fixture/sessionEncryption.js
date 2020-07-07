const { JWK, JWE } = require('jose');

const { encryption: deriveKey } = require('../../lib/hkdf');
const epoch = () => Date.now() / 1000 | 0;

const key = JWK.asKey(deriveKey('__test_secret__'));
const epochNow = epoch();
const weekInSeconds = 7 * 24 * 60 * 60;
const expires = epochNow + weekInSeconds;

const encryptOpts = {
  alg: 'dir',
  enc: 'A256GCM',
  uat: epochNow,
  iat: epochNow,
  exp: expires
};

const encrypt = (payload) => JWE.encrypt(JSON.stringify(payload), key, encryptOpts);

const decrypt = (jwe) => JWE.decrypt(jwe, key, { complete: true, algorithms: [encryptOpts.enc] });

const encrypted = encrypt({ sub: '__test_sub__' });

const { cleartext: decrypted } = decrypt(encrypted);

module.exports = {
  encrypted,
  decrypted,
  expires,
  encrypt,
  decrypt
};
