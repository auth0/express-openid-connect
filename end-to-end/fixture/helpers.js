const path = require('path');
const sinon = require('sinon');
const express = require('express');
const request = require('request-promise-native').defaults({ json: true });

const baseUrl = 'http://localhost:3000';

const start = (app, port) =>
  new Promise((resolve, reject) => {
    const server = app.listen(port, (err) => {
      if (err) {
        reject(err);
      } else {
        resolve(server);
      }
    });
  });

const runExample = (name) => {
  const app = require(path.join('..', '..', 'examples', name));
  app.use(testMw());
  return start(app, 3000);
};

const runApi = () => {
  const app = require(path.join('..', '..', 'examples', 'api'));
  return start(app, 3002);
};

const stubEnv = (
  env = {
    ISSUER_BASE_URL: 'http://localhost:3001',
    CLIENT_ID: 'test-express-openid-connect-client-id',
    BASE_URL: 'http://localhost:3000',
    SECRET: 'LONG_RANDOM_VALUE',
    CLIENT_SECRET: 'test-express-openid-connect-client-secret',
  }
) =>
  sinon.stub(process, 'env').value({
    ...process.env,
    ...env,
  });

const testMw = () => {
  const router = new express.Router();
  router.get('/context', (req, res) => {
    res.json({
      idToken: req.oidc.idToken,
      accessToken: req.oidc.accessToken
        ? {
            access_token: req.oidc.accessToken.access_token,
            token_type: req.oidc.accessToken.token_type,
            expires_in: req.oidc.accessToken.expires_in,
            isExpired: req.oidc.accessToken.isExpired(),
          }
        : {},
      refreshToken: req.oidc.refreshToken,
      idTokenClaims: req.oidc.idTokenClaims,
      user: req.oidc.user,
      isAuthenticated: req.oidc.isAuthenticated(),
    });
  });
  return router;
};

const checkContext = async (cookies) => {
  const jar = request.jar();
  cookies.forEach(({ name, value }) =>
    jar.setCookie(`${name}=${value}`, baseUrl)
  );
  return request('/context', { jar, baseUrl });
};

const goto = async (url, page) =>
  Promise.all([page.goto(url), page.waitForNavigation()]);

const login = async (username, password, page) => {
  await page.type('[name=login]', username);
  await page.type('[name=password]', password);
  await Promise.all([page.click('.login-submit'), page.waitForNavigation()]);
  await Promise.all([page.click('.login-submit'), page.waitForNavigation()]); // consent
  if (!page.url().startsWith('http://localhost:3000')) {
    await page.waitForNavigation();
  }
};

const logout = async (page) => {
  await goto(`${baseUrl}/logout`, page);
  await Promise.all([page.click('[name=logout]'), page.waitForNavigation()]);
};

module.exports = {
  baseUrl,
  start,
  runExample,
  runApi,
  stubEnv,
  testMw,
  checkContext,
  goto,
  login,
  logout,
};
