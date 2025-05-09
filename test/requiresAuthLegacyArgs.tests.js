// @ts-check

const { assert } = require('chai');
const {
  requiresAuth,
  claimEquals,
  claimIncludes,
  claimCheck,
} = require('../middleware/requiresAuthLegacyArgs');

describe('requiresAuthLegacyArgs', () => {
  const authorizationParams = { audience: 'foo' };

  describe('normalizeRequiresAuthArgs()', () => {
    const requiresLoginCheck = () => true;

    describe('no args', () => {
      it('returns an empty object', () => {
        const output = requiresAuth.normalize();

        assert.deepEqual(output, {});
      });
    });

    describe('legacy args', () => {
      it('returns converted args', () => {
        const output = requiresAuth.normalize(requiresLoginCheck);

        assert.deepEqual(output, {
          requiresLoginCheck,
        });
      });
    });

    describe('modern args', () => {
      it('returns unchanged args', () => {
        const output = requiresAuth.normalize({
          authorizationParams,
          requiresLoginCheck,
        });

        assert.deepEqual(output, {
          authorizationParams,
          requiresLoginCheck,
        });
      });
    });
  });

  describe('normalizeClaimEqualsArgs()', () => {
    const claim = 'role';
    const value = 'admin';

    describe('legacy args', () => {
      it('returns converted args', () => {
        const output = claimEquals.normalize(claim, value);

        assert.deepEqual(output, {
          claim,
          value,
        });
      });
    });

    describe('modern args', () => {
      it('returns unchanged args', () => {
        const output = claimEquals.normalize({
          claim,
          value,
          authorizationParams,
        });

        assert.deepEqual(output, {
          claim,
          value,
          authorizationParams,
        });
      });
    });
  });

  describe('normalizeClaimIncludesArgs()', () => {
    const claim = 'role';
    const value1 = 'admin';
    const value2 = 'operator';

    describe('legacy args', () => {
      it('returns converted args', () => {
        const output = claimIncludes.normalize(claim, value1, value2);

        assert.deepEqual(output, {
          claim,
          values: [value1, value2],
        });
      });
    });

    describe('modern args', () => {
      describe('single value', () => {
        it('returns expected args', () => {
          const output = claimIncludes.normalize({
            claim,
            value: value1,
            authorizationParams,
          });

          assert.deepEqual(output, {
            claim,
            values: [value1],
            authorizationParams,
          });
        });
      });

      describe('multi value', () => {
        it('returns expected args', () => {
          const output = claimIncludes.normalize({
            claim,
            values: [value1, value2],
            authorizationParams,
          });

          assert.deepEqual(output, {
            claim,
            values: [value1, value2],
            authorizationParams,
          });
        });
      });
    });
  });

  describe('normalizeClaimCheckArgs()', () => {
    const predicate = () => true;

    describe('legacy args', () => {
      it('returns converted args', () => {
        const output = claimCheck.normalize(predicate);

        assert.deepEqual(output, {
          predicate,
        });
      });
    });

    describe('modern args', () => {
      it('returns unchanged args', () => {
        const output = claimCheck.normalize({
          predicate,
          authorizationParams,
        });

        assert.deepEqual(output, {
          predicate,
          authorizationParams,
        });
      });
    });
  });
});
