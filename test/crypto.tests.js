'use strict';

const assert = require('chai').assert;
const crypto = require('crypto');
const { compactDecrypt, decodeProtectedHeader } = require('jose');

const {
  encryptSync,
  signCookieSync,
  verifyCookie,
  getKeyStore,
} = require('../lib/crypto');

describe('crypto', () => {
  describe('encryptSync', () => {
    const makeKey = () => crypto.randomBytes(32);

    it('produces a 5-part JWE compact serialization', () => {
      const jwe = encryptSync('hello', makeKey(), {});
      assert.equal(jwe.split('.').length, 5);
    });

    it('encrypted key segment is empty (alg=dir has no wrapped key)', () => {
      const jwe = encryptSync('hello', makeKey(), {});
      assert.equal(jwe.split('.')[1], '');
    });

    it('IV is 12 bytes (96 bits as required by AES-GCM)', () => {
      const jwe = encryptSync('hello', makeKey(), {});
      const iv = Buffer.from(jwe.split('.')[2], 'base64url');
      assert.equal(iv.length, 12);
    });

    it('auth tag is 16 bytes (128-bit tag)', () => {
      const jwe = encryptSync('hello', makeKey(), {});
      const tag = Buffer.from(jwe.split('.')[4], 'base64url');
      assert.equal(tag.length, 16);
    });

    it('protected header contains alg=dir and enc=A256GCM', () => {
      const jwe = encryptSync('hello', makeKey(), {});
      const header = JSON.parse(
        Buffer.from(jwe.split('.')[0], 'base64url').toString(),
      );
      assert.equal(header.alg, 'dir');
      assert.equal(header.enc, 'A256GCM');
    });

    it('merges extra fields into the protected header', () => {
      const jwe = encryptSync('hello', makeKey(), {
        iat: 1000,
        uat: 2000,
        exp: 3000,
      });
      const header = JSON.parse(
        Buffer.from(jwe.split('.')[0], 'base64url').toString(),
      );
      assert.equal(header.iat, 1000);
      assert.equal(header.uat, 2000);
      assert.equal(header.exp, 3000);
    });

    it('jose v6 compactDecrypt can decrypt the output', async () => {
      const key = makeKey();
      const payload = JSON.stringify({ sub: 'user123', iat: 1000 });
      const jwe = encryptSync(payload, key, {
        iat: 1000,
        uat: 1000,
        exp: 9999999999,
      });
      const { plaintext } = await compactDecrypt(jwe, key, {
        contentEncryptionAlgorithms: ['A256GCM'],
        keyManagementAlgorithms: ['dir'],
      });
      assert.equal(new TextDecoder().decode(plaintext), payload);
    });

    it('jose v6 exposes the extra header fields after decryption', async () => {
      const key = makeKey();
      const jwe = encryptSync('payload', key, { iat: 100, uat: 200, exp: 999 });
      const { protectedHeader } = await compactDecrypt(jwe, key, {
        contentEncryptionAlgorithms: ['A256GCM'],
        keyManagementAlgorithms: ['dir'],
      });
      assert.equal(protectedHeader.iat, 100);
      assert.equal(protectedHeader.uat, 200);
      assert.equal(protectedHeader.exp, 999);
    });

    it('decryption fails with a different key', async () => {
      const key = makeKey();
      const jwe = encryptSync('hello', key, {});
      try {
        await compactDecrypt(jwe, makeKey(), {
          contentEncryptionAlgorithms: ['A256GCM'],
          keyManagementAlgorithms: ['dir'],
        });
        assert.fail('expected decryption to fail');
      } catch (e) {
        assert.notEqual(e.message, 'expected decryption to fail');
      }
    });

    it('handles unicode payload (UTF-8 encoding)', async () => {
      const key = makeKey();
      const payload = JSON.stringify({ name: 'José', emoji: '🔐' });
      const jwe = encryptSync(payload, key, {});
      const { plaintext } = await compactDecrypt(jwe, key, {
        contentEncryptionAlgorithms: ['A256GCM'],
        keyManagementAlgorithms: ['dir'],
      });
      assert.equal(new TextDecoder().decode(plaintext), payload);
    });

    it('produces unique ciphertext on each call due to random IV', () => {
      const key = makeKey();
      const jwe1 = encryptSync('same payload', key, {});
      const jwe2 = encryptSync('same payload', key, {});
      assert.notEqual(jwe1, jwe2);
    });

    it('jose v6 decodeProtectedHeader parses the header segment', () => {
      const jwe = encryptSync('hello', makeKey(), { iat: 1, uat: 2, exp: 3 });
      const header = decodeProtectedHeader(jwe);
      assert.equal(header.alg, 'dir');
      assert.equal(header.enc, 'A256GCM');
      assert.equal(header.iat, 1);
    });

    it('output has same structure as jose v6 CompactEncrypt (segment count, IV size, tag size)', async () => {
      const { CompactEncrypt } = require('jose');
      const key = makeKey();
      const payload = 'test payload';

      const joseJwe = await new CompactEncrypt(
        new TextEncoder().encode(payload),
      )
        .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
        .encrypt(key);

      const syncJwe = encryptSync(payload, key, {});

      const joseParts = joseJwe.split('.');
      const syncParts = syncJwe.split('.');

      assert.equal(syncParts.length, joseParts.length);
      assert.equal(syncParts[1], '');
      assert.equal(
        Buffer.from(syncParts[2], 'base64url').length,
        Buffer.from(joseParts[2], 'base64url').length,
      );
      assert.equal(
        Buffer.from(syncParts[4], 'base64url').length,
        Buffer.from(joseParts[4], 'base64url').length,
      );
    });
  });

  describe('signCookieSync', () => {
    let key;

    beforeEach(() => {
      [key] = getKeyStore('__test_secret__');
    });

    it('returns value.signature format', () => {
      const signed = signCookieSync('appSession', 'session-id-123', key);
      assert.match(signed, /^session-id-123\.[A-Za-z0-9_-]+$/);
    });

    it('produces a signature verifiable by verifyCookie', async () => {
      const [key, keystore] = getKeyStore('__test_secret__');
      const signed = signCookieSync('appSession', 'session-id-123', key);
      const result = await verifyCookie('appSession', signed, keystore);
      assert.equal(result, 'session-id-123');
    });

    it('verification fails when cookie name differs', async () => {
      const [key, keystore] = getKeyStore('__test_secret__');
      const signed = signCookieSync('appSession', 'session-id-123', key);
      const result = await verifyCookie('differentName', signed, keystore);
      assert.isUndefined(result);
    });

    it('verification fails when value is tampered', async () => {
      const [key, keystore] = getKeyStore('__test_secret__');
      const signed = signCookieSync('appSession', 'session-id-123', key);
      const tampered = 'tampered-id.' + signed.split('.')[1];
      const result = await verifyCookie('appSession', tampered, keystore);
      assert.isUndefined(result);
    });

    it('verification fails with a different secret', async () => {
      const [key] = getKeyStore('__test_secret__');
      const [, otherKeystore] = getKeyStore('__other_secret__');
      const signed = signCookieSync('appSession', 'session-id-123', key);
      const result = await verifyCookie('appSession', signed, otherKeystore);
      assert.isUndefined(result);
    });

    it('produces the same result as async signCookie', async () => {
      const { signCookie } = require('../lib/crypto');
      const [key] = getKeyStore('__test_secret__');
      const syncSigned = signCookieSync('appSession', 'abc', key);
      const asyncSigned = await signCookie('appSession', 'abc', key);
      // signatures should be deterministic for same inputs
      assert.equal(syncSigned, asyncSigned);
    });
  });
});
