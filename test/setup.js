const nock = require('nock');
const sinon = require('sinon');
const wellKnown = require('./fixture/well-known.json');
const certs = require('./fixture/cert');

let warn;

beforeEach(function () {
  warn = sinon.stub(global.console, 'warn');
  nock('https://op.example.com')
    .persist()
    .get('/.well-known/openid-configuration')
    .reply(200, wellKnown);

  nock('https://op.example.com')
    .persist()
    .get('/.well-known/jwks.json')
    .reply(200, certs.jwks);

  nock('https://test.eu.auth0.com')
    .persist()
    .get('/.well-known/openid-configuration')
    .reply(200, { ...wellKnown, end_session_endpoint: undefined });

  nock('https://test.eu.auth0.com')
    .persist()
    .get('/.well-known/jwks.json')
    .reply(200, certs.jwks);
});

afterEach(function () {
  nock.cleanAll();
  warn.restore();
});
