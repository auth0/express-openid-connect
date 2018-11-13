const assert = require('chai').assert;
const url = require('url');
const expressOpenid = require('./..');

describe('routes', function() {
  const router = expressOpenid.routes({
    client_id: '123',
    base_url: 'https://myapp.com',
    issuer_base_url: 'https://flosser.auth0.com'
  });

  it('should contains two routes', function() {
    assert.equal(router.stack.length, 2);
  });

  it('should contains a login route', function() {
    const route = router.stack[0].route;
    assert.equal(route.path, '/login');
    assert.deepEqual(route.methods, { get: true });
  });

  it('should redirect to the authorize url properly on /login', async function() {
    const route = router.stack[0].route;
    const handle = route.stack[0].handle;
    let redirectUrl;
    await handle({
      session: {},
    }, {
      redirect: rurl => redirectUrl = rurl
    });
    const parsed = url.parse(redirectUrl, true);
    assert.equal(parsed.hostname, 'flosser.auth0.com');
    assert.equal(parsed.pathname, '/authorize');
    assert.equal(parsed.query.client_id, '123');
    assert.equal(parsed.query.scope, 'openid profile email');
    assert.equal(parsed.query.response_type, 'id_token');
    assert.equal(parsed.query.response_mode, 'form_post');
    assert.equal(parsed.query.redirect_uri, 'https://myapp.com/callback');
    assert.property(parsed.query, 'nonce');
    assert.property(parsed.query, 'state');
  });

  it('should contains a callback route', function() {
    const route = router.stack[1].route;
    assert.equal(route.path, '/callback');
    assert.deepEqual(route.methods, { post: true });
  });
});
