import { URL } from 'url';
import sinon from 'sinon';
import { assert } from 'chai';
import { create as createServer } from './fixture/server.js';
import { makeIdToken } from './fixture/cert.js';
import { auth, attemptSilentLogin } from '../index.js';
import request from 'request-promise-native';
import weakRef from '../lib/weakCache.js';
import {
  cancelSilentLogin,
  resumeSilentLogin,
} from '../middleware/attemptSilentLogin.js';

const requestDefaults = request.defaults({
  simple: false,
  resolveWithFullResponse: true,
  followRedirect: false,
});

const baseUrl = 'http://localhost:3000';

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  baseURL: 'http://example.org',
  issuerBaseURL: 'https://op.example.com',
};

const login = async (claims) => {
  const jar = requestDefaults.jar();
  await requestDefaults.post('/session', {
    baseUrl,
    jar,
    json: {
      id_token: makeIdToken(claims),
    },
  });
  return jar;
};

describe('attemptSilentLogin', () => {
  let server;

  afterEach(async () => {
    if (server) {
      server.close();
    }
  });

  it("should attempt silent login on user's first route", async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
      }),
      attemptSilentLogin(),
    );
    const jar = requestDefaults.jar();
    const response = await requestDefaults({ baseUrl, jar, url: '/protected' });

    assert.equal(response.statusCode, 302);
    const uri = new URL(response.headers.location);
    assert.equal(uri.searchParams.get('prompt'), 'none');
    assert.include(jar.getCookies(baseUrl)[0], {
      key: 'skipSilentLogin',
      value: 'true',
      httpOnly: true,
    });
  });

  it('should not attempt silent login for non html requests', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
      }),
      attemptSilentLogin(),
    );
    const jar = requestDefaults.jar();
    const response = await requestDefaults({
      baseUrl,
      jar,
      url: '/protected',
      json: true,
    });

    assert.equal(response.statusCode, 200);
  });

  it("should not attempt silent login on user's subsequent routes", async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
      }),
      attemptSilentLogin(),
    );
    const jar = requestDefaults.jar();
    const response = await requestDefaults({ baseUrl, jar, url: '/protected' });
    assert.equal(response.statusCode, 302);
    const response2 = await requestDefaults({
      baseUrl,
      jar,
      url: '/protected',
    });
    assert.equal(response2.statusCode, 200);
    const response3 = await requestDefaults({
      baseUrl,
      jar,
      url: '/protected',
    });
    assert.equal(response3.statusCode, 200);
  });

  it('should not attempt silent login for authenticated user', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
      }),
      attemptSilentLogin(),
    );
    const jar = await login();
    const response = await requestDefaults({ baseUrl, jar, url: '/protected' });
    assert.equal(response.statusCode, 200);
  });

  it('should not attempt silent login after first anonymous request after logout', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
      }),
      attemptSilentLogin(),
    );
    const jar = await login();
    await requestDefaults({ baseUrl, jar, url: '/protected' });
    await requestDefaults.get({
      uri: '/logout',
      baseUrl,
      jar,
      followRedirect: false,
    });
    const response = await requestDefaults({ baseUrl, jar, url: '/protected' });
    assert.equal(response.statusCode, 200);
  });

  it('should not attempt silent login after first request is to logout', async () => {
    server = await createServer(
      auth({
        ...defaultConfig,
        authRequired: false,
      }),
      attemptSilentLogin(),
    );
    const jar = await login();
    await requestDefaults.get({
      uri: '/logout',
      baseUrl,
      jar,
      followRedirect: false,
    });
    const response = await requestDefaults({ baseUrl, jar, url: '/protected' });
    assert.equal(response.statusCode, 200);
  });

  it("should throw when there's no auth middleware", async () => {
    server = await createServer(attemptSilentLogin());
    const {
      body: { err },
    } = await requestDefaults({ baseUrl, url: '/protected', json: true });
    assert.equal(
      err.message,
      'req.oidc is not found, did you include the auth middleware?',
    );
  });

  it('should honor SameSite config for use in iframes', async () => {
    const ctx = {};
    const oidc = weakRef(ctx);
    oidc.config = {
      session: {
        cookie: {
          sameSite: 'None',
          secure: true,
        },
      },
    };
    const resumeSpy = sinon.spy();
    const cancelSpy = sinon.spy();
    resumeSilentLogin({ oidc: ctx }, { clearCookie: resumeSpy });
    cancelSilentLogin({ oidc: ctx }, { cookie: cancelSpy });
    sinon.assert.calledWithMatch(resumeSpy, 'skipSilentLogin', {
      sameSite: 'None',
      secure: true,
    });
    sinon.assert.calledWithMatch(cancelSpy, 'skipSilentLogin', true, {
      sameSite: 'None',
      secure: true,
    });
  });
});
