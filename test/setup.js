const nock = require('nock');
const sinon = require('sinon');
const wellKnown = require('./fixture/well-known.json');
const certs = require('./fixture/cert');

// Enable nock to intercept undici/fetch requests
nock.enableNetConnect();
nock.disableNetConnect();

let warn;

beforeEach(function () {
  warn = sinon.stub(global.console, 'warn');

  // Allow localhost connections for supertest, but block external
  nock.disableNetConnect();
  // Use regex to match localhost with any port
  nock.enableNetConnect(/localhost|127\.0\.0\.1/);

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
    .reply(200, {
      ...wellKnown,
      issuer: 'https://test.eu.auth0.com/',
      end_session_endpoint: undefined,
    });

  nock('https://test.eu.auth0.com')
    .persist()
    .get('/.well-known/jwks.json')
    .reply(200, certs.jwks);
});

afterEach(function () {
  nock.cleanAll();
  warn.restore();
});
