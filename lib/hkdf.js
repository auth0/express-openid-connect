const crypto = require('crypto');

const BYTE_LENGTH = 32;
const ENCRYPTION_INFO = 'JWE CEK';
const SIGNING_INFO = 'JWS Cookie Signing';
const DIGEST = 'sha256';

/**
 *
 * Derives appropriate sized keys from the end-user provided secret random string/passphrase using
 * HKDF (HMAC-based Extract-and-Expand Key Derivation Function) defined in RFC 8569
 *
 * @see https://tools.ietf.org/html/rfc5869
 *
 */

if (crypto.hkdfSync) {
  // added in v15.0.0
  module.exports.encryption = (secret) =>
    Buffer.from(
      crypto.hkdfSync(
        DIGEST,
        secret,
        Buffer.alloc(0),
        ENCRYPTION_INFO,
        BYTE_LENGTH
      )
    );
  module.exports.signing = (secret) =>
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
  module.exports.encryption = (secret) =>
    hkdf(secret, BYTE_LENGTH, { info: ENCRYPTION_INFO, hash: DIGEST });
  module.exports.signing = (secret) =>
    hkdf(secret, BYTE_LENGTH, { info: SIGNING_INFO, hash: DIGEST });
}
