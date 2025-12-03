// @ts-check

const { assert } = require('chai');
const sinon = require('sinon');
const { TokenHistory, PRUNE_GRACE_PERIOD } = require('../lib/tokenHistory');
const { TokenSetUtils } = require('../lib/tokenSetUtils');

/**
 * @returns {import('express').Request}
 */
function newReq() {
  // @ts-expect-error just for passing around, not worth mocking
  return {};
}

describe('TokenHistory', () => {
  describe('attach()', () => {
    it('attaches the tokensets to the request', () => {
      const req = newReq();
      const tokenSets = [];

      TokenHistory.attach(req, tokenSets);

      assert.strictEqual(TokenHistory.getAll(req), tokenSets);
    });
  });

  describe('getAll()', () => {
    it('returns an empty array if not attached', () => {
      const req = newReq();

      assert.deepEqual(TokenHistory.getAll(req), []);
    });
  });

  describe('append()', () => {
    it('appends a clean tokenset to the list', () => {
      const req = newReq();

      const tokenSet1 = { access_token: 'one' };
      const tokenSet2 = { access_token: 'two' };

      const cleanTokenSetSpy = sinon
        .stub(TokenSetUtils, 'cleanTokenSet')
        .returnsArg(0);

      const tokenSets = [tokenSet1];
      TokenHistory.attach(req, tokenSets);

      TokenHistory.append(req, tokenSet2);

      assert.isTrue(cleanTokenSetSpy.calledOnceWith(tokenSet2));
      assert.deepEqual(TokenHistory.getAll(req), [tokenSet1, tokenSet2]);

      sinon.restore();
    });

    describe('prune()', () => {
      it('prunes tokensets from history as expected', () => {
        const req = newReq();

        const now = Math.round(Date.now() / 1000);

        const tokenSetsBeforePrune = [
          // very expired + unrefreshable => prune
          { expires_at: now - PRUNE_GRACE_PERIOD * 2 },

          // very expired + refreshable => prune
          { expires_at: now - PRUNE_GRACE_PERIOD * 2, refresh_token: 'x' },

          // just expired + refreshable => keep
          { expires_at: now - PRUNE_GRACE_PERIOD / 2, refresh_token: 'x' },

          // active => keep
          { expires_at: now + 999 },
        ];

        const tokenSetsAfterPrune = [
          tokenSetsBeforePrune[2],
          tokenSetsBeforePrune[3],
        ];

        TokenHistory.attach(req, tokenSetsBeforePrune);
        TokenHistory.prune(req);

        assert.deepEqual(TokenHistory.getAll(req), tokenSetsAfterPrune);
      });
    });

    describe('patchByAccessToken()', () => {
      it('patches tokensets in history as expected', () => {
        const req = newReq();

        const tokenSetsBeforePatch = [
          { access_token: 'at1', expires_at: 1111 },
          { access_token: 'at2', expires_at: 2222 },
        ];

        const newValues = { expires_at: 9999 };

        const tokenSetsAfterPatch = [
          { access_token: 'at1', expires_at: 9999 },
          { access_token: 'at2', expires_at: 2222 },
        ];

        TokenHistory.attach(req, tokenSetsBeforePatch);
        TokenHistory.patchByAccessToken(req, 'at1', newValues);

        assert.deepEqual(TokenHistory.getAll(req), tokenSetsAfterPatch);
      });
    });

    describe('patchByRefreshToken()', () => {
      it('patches tokensets in history as expected', () => {
        const req = newReq();

        const tokenSetsBeforePatch = [
          { refresh_token: 'rt1', expires_at: 1111 },
          { refresh_token: 'rt2', expires_at: 2222 },
        ];

        const newValues = { expires_at: 3333 };

        const tokenSetsAfterPatch = [
          { refresh_token: 'rt1', expires_at: 3333 },
          { refresh_token: 'rt2', expires_at: 2222 },
        ];

        TokenHistory.attach(req, tokenSetsBeforePatch);
        TokenHistory.patchByRefreshToken(req, 'rt1', newValues);

        assert.deepEqual(TokenHistory.getAll(req), tokenSetsAfterPatch);
      });
    });
  });
});
