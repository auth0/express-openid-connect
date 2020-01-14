const { JWK, JWE } = require('jose');
const hkdf = require('futoin-hkdf');

const deriveKey = (secret) => hkdf(secret, 32, { info: 'JWE CEK', hash: 'SHA-256' });
const epoch = () => Date.now() / 1000 | 0;

const key = JWK.asKey(deriveKey('__test_secret__'));
const payload = JSON.stringify({sub: '__test_sub__'});
const epochNow = epoch();
const weekInSeconds = 7 * 24 * 60 * 60;

const encryptOpts = {
  alg: 'dir',
  enc: 'A256GCM',
  zip: 'DEF',
  uat: epochNow,
  iat: epochNow,
  exp: epochNow + weekInSeconds
};

const jwe = JWE.encrypt(payload, key, encryptOpts);
const {cleartext} = JWE.decrypt(jwe, key, { complete: true, algorithms: [encryptOpts.enc] });

module.exports = {
  encrypted: jwe,
  decrypted: cleartext
};
