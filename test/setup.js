const nock = require('nock');
const wellKnown = require('./fixture/well-known.json');

// this is used only to speed up tests.

before(function() {
  nock('https://flosser.auth0.com', { allowUnmocked: true })
    .persist()
    .get('/.well-known/openid-configuration')
    .reply(200, wellKnown);
});

after(function() {
  nock.cleanAll();
});
