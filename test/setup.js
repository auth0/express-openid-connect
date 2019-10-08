const nock = require('nock');
const wellKnown = require('./fixture/well-known.json');
const certs = require('./fixture/cert');

before(function() {
  nock('https://test.auth0.com', { allowUnmocked: true })
    .persist()
    .get('/.well-known/openid-configuration')
    .reply(200, wellKnown);

  nock('https://test.auth0.com', { allowUnmocked: true })
    .persist()
    .get('/.well-known/jwks.json')
    .reply(200, certs.jwks);
});

after(function() {
  nock.cleanAll();
});
