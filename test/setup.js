const nock = require('nock');
const wellKnown = require('./fixture/well-known.json');
const certs = require('./fixture/cert');

beforeEach(function () {
  nock('https://op.example.com', { allowUnmocked: true })
    .persist()
    .get('/.well-known/openid-configuration')
    .reply(200, wellKnown);

  nock('https://op.example.com', { allowUnmocked: true })
    .persist()
    .get('/.well-known/jwks.json')
    .reply(200, certs.jwks);

  nock('https://test.eu.auth0.com', { allowUnmocked: true })
    .persist()
    .get('/.well-known/openid-configuration')
    .reply(200, { ...wellKnown, end_session_endpoint: undefined });

  nock('https://test.eu.auth0.com', { allowUnmocked: true })
    .persist()
    .get('/.well-known/jwks.json')
    .reply(200, certs.jwks);
});

afterEach(function () {
  nock.cleanAll();
});
