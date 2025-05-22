// @ts-check

const { assert } = require('chai');
const sinon = require('sinon');
const weakCache = require('../lib/weakCache');
const { TokenSets } = require('../lib/tokenSets');

/** @returns {import('express').Request} */
function newReq() {
  // @ts-expect-error just for passing around, not worth mocking
  return {};
}

describe('tokenSets', () => {
  describe('attach()', () => {
    it('attaches the tokensets to the request', () => {
      const req = newReq();
      const tokenSets = [];

      TokenSets.attach(req, tokenSets);

      assert.strictEqual(TokenSets.getAll(req), tokenSets);
    });
  });

  describe('getAll()', () => {
    it('returns an empty array if not attached', () => {
      const req = newReq();

      assert.deepEqual(TokenSets.getAll(req), []);
    });
  });

  describe('append()', () => {
    it('appends a tokenset to the list', () => {
      const req = newReq();

      const tokenSet1 = { access_token: 'one' };
      const tokenSet2 = { access_token: 'two' };

      const tokenSets = [tokenSet1];
      TokenSets.attach(req, tokenSets);

      TokenSets.append(req, tokenSet2);

      assert.deepEqual(TokenSets.getAll(req), [tokenSet1, tokenSet2]);
    });
  });

  describe('_areScopesCompatible', () => {
    describe('yes', () => {
      it('returns true when scopes are enough plus some extra', () => {
        assert.isTrue(TokenSets._areScopesCompatible('a b', 'b c a'));
      });
    });

    describe('returns false when scopes are not enough', () => {
      assert.isFalse(TokenSets._areScopesCompatible('a b', 'b'));
    });
  });

  describe('_invalidateTokenSetIfNeeded()', () => {
    const session = { access_token: 'AT1', refresh_token: 'RT1' };

    describe('access token changed', () => {

      it('deletes the cache', () => {
        const cachedTokenSet = { value: {} };
        sinon.stub(weakCache, 'weakRef').returns(cachedTokenSet);

        TokenSets._invalidateTokenSetIfNeeded(session, { access_token: 'AT2' });

        assert.isUndefined(cachedTokenSet.value);

        sinon.restore();
      });
    });

    describe('refresh token changed', () => {
      it('deletes the cache', () => {
        const cachedTokenSet = { value: {} };
        sinon.stub(weakCache, 'weakRef').returns(cachedTokenSet);

        TokenSets._invalidateTokenSetIfNeeded(session, { refresh_token: 'RT2' });

        assert.isUndefined(cachedTokenSet.value);

        sinon.restore();
      });
    });

    describe('nothing changed', () => {
      it('does not touch the cache', () => {
        const weakRefSpy = sinon.spy(weakCache, 'weakRef');

        TokenSets._invalidateTokenSetIfNeeded(session, {
          access_token: session.access_token,
          refresh_token: session.refresh_token,
        });

        assert.isFalse(weakRefSpy.called);

        sinon.restore();
      });
    });
  });

  describe('setCurrent()', () => {
    it('merges the new tokenset into the session', () => {
      const sessName = 'mySession';

      const req = newReq();
      req[sessName] = {
        access_token: 'foo1',
        something_else: 'bar',
      };

      sinon.stub(weakCache, 'weakRef').returns({
        config: { session: { name: sessName } },
      });

      const newTokenSet = { access_token: 'foo2', refresh_token: 'qux' };

      TokenSets.setCurrent(req, newTokenSet);

      assert.equal(req[sessName].access_token, 'foo2'); // overwritten
      assert.equal(req[sessName].refresh_token, 'qux'); // new prop
      assert.equal(req[sessName].something_else, 'bar'); // untouched

      sinon.restore();
    });

    describe('findCompatible()', () => {
      // TODO: do when the final compatibility logic is implemented
    });
  });
});
