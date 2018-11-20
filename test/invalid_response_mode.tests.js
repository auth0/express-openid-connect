const assert = require('chai').assert;
const expressOpenid = require('..');

describe('with an invalid response_mode', function() {
  const router = expressOpenid.routes({
    client_id: '123',
    base_url: 'https://myapp.com',
    issuer_base_url: 'https://flosser.auth0.com',
    authorizationParams: {
      response_mode: 'ffff'
    }
  });


  it('should return an error', function(done) {
    const route = router.stack[0].route;
    const handle = route.stack[0].handle;
    const req = { session: {} };
    const res = {
      redirect: () => {}
    };

    handle(req, res, err => {
      assert.include(err.message, 'The issuer doesn\'t support the response_mode ffff');
      done();
    });
  });
});
