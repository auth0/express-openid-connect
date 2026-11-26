const { assert } = require('chai');
const {
  defaultState,
  encodeState,
  decodeState,
} = require('../lib/hooks/getLoginState');

describe('getLoginState', () => {
  describe('defaultState', () => {
    it('should use options.returnTo when provided', () => {
      assert.deepEqual(
        defaultState({ originalUrl: '/orig' }, { returnTo: '/custom' }),
        { returnTo: '/custom' },
      );
    });

    it('should fall back to req.originalUrl', () => {
      assert.deepEqual(defaultState({ originalUrl: '/orig' }, {}), {
        returnTo: '/orig',
      });
    });
  });

  describe('encodeState', () => {
    it('should encode an empty state when called with no argument', () => {
      assert.equal(encodeState(), 'e30');
    });

    it('should match known output for non-ASCII state', () => {
      assert.equal(
        encodeState({ returnTo: '/ünï?x=1&y=€😀' }),
        'eyJyZXR1cm5UbyI6Ii_DvG7Drz94PTEmeT3igqzwn5iAIn0',
      );
    });

    it('should match known output for every padding length', () => {
      assert.equal(encodeState({ returnTo: '/a' }), 'eyJyZXR1cm5UbyI6Ii9hIn0');
      assert.equal(
        encodeState({ returnTo: '/ab' }),
        'eyJyZXR1cm5UbyI6Ii9hYiJ9',
      );
      assert.equal(
        encodeState({ returnTo: '/abc' }),
        'eyJyZXR1cm5UbyI6Ii9hYmMifQ',
      );
    });

    it('should encode state as unpadded base64url', () => {
      assert.equal(encodeState({ returnTo: '/' }), 'eyJyZXR1cm5UbyI6Ii8ifQ');
    });

    it('should strip nonce, code_verifier and max_age', () => {
      assert.equal(
        encodeState({
          returnTo: '/',
          nonce: 'n',
          code_verifier: 'c',
          max_age: 1,
        }),
        encodeState({ returnTo: '/' }),
      );
    });

    it('should use URL-safe characters only', () => {
      const encoded = encodeState({ returnTo: '/?q=~~~???>>>&x=é😀' });
      assert.match(encoded, /^[A-Za-z0-9_-]+$/);
    });
  });

  describe('decodeState', () => {
    it('should round-trip non-ASCII state', () => {
      const state = { returnTo: '/ünï?x=1&y=€😀' };
      assert.deepEqual(decodeState(encodeState(state)), state);
    });

    it('should decode padded input', () => {
      assert.deepEqual(decodeState('e30='), {});
    });

    it('should return false for valid base64url that is not JSON', () => {
      assert.isFalse(decodeState('aGVsbG8'));
    });

    it('should return false for invalid input', () => {
      assert.isFalse(decodeState('!!!'));
      assert.isFalse(decodeState('abcde'));
      assert.isFalse(decodeState(undefined));
    });
  });
});
