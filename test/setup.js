import nock from 'nock';
import sinon from 'sinon';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';
import certs from './fixture/cert.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const wellKnown = JSON.parse(
  readFileSync(path.join(__dirname, 'fixture', 'well-known.json'), 'utf8'),
);

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
