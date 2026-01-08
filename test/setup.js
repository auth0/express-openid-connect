import nock from 'nock';
import sinon from 'sinon';
import wellKnown from './fixture/well-known.json' with { type: 'json' };
import certs from './fixture/cert.js';

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
