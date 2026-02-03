import path from 'path';
import crypto from 'crypto';
import sinon from 'sinon';
import express from 'express';
import { SignJWT } from 'jose';
import { getPrivateJWK } from './jwk.js';
import request from 'request-promise-native';
import puppeteer from 'puppeteer';

const requestDefaults = request.defaults({ json: true });

const baseUrl = 'http://localhost:3000';

/**
 * Get Puppeteer launch options for CI compatibility
 */
const getPuppeteerLaunchOptions = () => ({
  headless: true,
  args: [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
  ],
});

/**
 * Launch Puppeteer browser with CI-compatible options
 */
const launchBrowser = () => puppeteer.launch(getPuppeteerLaunchOptions());

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

const runExample = async (name) => {
  // Ensure environment variables are set BEFORE the dynamic import
  // because auth() is called during module initialization
  const env = {
    ISSUER_BASE_URL: 'http://localhost:3001',
    CLIENT_ID: 'test-express-openid-connect-client-id',
    BASE_URL: 'http://localhost:3000',
    SECRET: 'LONG_RANDOM_VALUE',
    CLIENT_SECRET: 'test-express-openid-connect-client-secret',
  };

  // Set environment variables first
  const originalEnv = {};
  for (const [key, value] of Object.entries(env)) {
    originalEnv[key] = process.env[key];
    process.env[key] = value;
  }

  try {
    // Use absolute path and ensure fresh import
    const modulePath = path.resolve('examples', `${name}.js`);
    const { default: appOrPromise } = await import(
      `${modulePath}?t=${Date.now()}`
    );

    // Handle both sync apps and async app promises
    const app = await Promise.resolve(appOrPromise);
    app.use(testMw());
    return start(app, 3000);
  } catch (error) {
    // Restore original environment on error
    for (const [key, value] of Object.entries(originalEnv)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
    throw error;
  }
};

const runApi = async () => {
  const { default: app } = await import(path.resolve('examples', 'api.js'));
  return start(app, 3002);
};

const stubEnv = (
  env = {
    ISSUER_BASE_URL: 'http://localhost:3001',
    CLIENT_ID: 'test-express-openid-connect-client-id',
    BASE_URL: 'http://localhost:3000',
    SECRET: 'LONG_RANDOM_VALUE',
    CLIENT_SECRET: 'test-express-openid-connect-client-secret',
  },
) => {
  // For ES modules and dynamic imports, set env vars directly
  Object.assign(process.env, env);
  return sinon.stub(process, 'env').value({
    ...process.env,
    ...env,
  });
};

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
  const jar = requestDefaults.jar();
  cookies.forEach(({ name, value }) =>
    jar.setCookie(`${name}=${value}`, baseUrl),
  );
  return requestDefaults('/context', { jar, baseUrl });
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

const logoutTokenTester = (clientId, sid, sub) => async (req, res) => {
  const privateJWK = await getPrivateJWK();

  const logoutToken = await new SignJWT({
    events: {
      'http://schemas.openid.net/event/backchannel-logout': {},
    },
    ...(sid && { sid: req.oidc.user.sid }),
    ...(sub && { sub: req.oidc.user.sub }),
  })
    .setProtectedHeader({
      alg: 'RS256',
      typ: 'logout+jwt',
    })
    .setIssuer(`http://localhost:${process.env.PROVIDER_PORT || 3001}`)
    .setAudience(clientId)
    .setIssuedAt()
    .setJti(crypto.randomBytes(16).toString('hex'))
    .sign(privateJWK);

  res.send(`
    <pre style="border: 1px solid #ccc; padding: 10px; white-space: break-spaces; background: whitesmoke;">curl -X POST http://localhost:3000/backchannel-logout -d "logout_token=${logoutToken}"</pre>
  `);
};

const shouldSkipPuppeteerTest = () => {
  const nodeVersion = process.version;
  const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0]);

  // Skip on macOS with Node.js 20 due to Puppeteer DNS resolution issues
  // Also skip on Node.js v24+ with macOS for similar reasons
  if (process.platform === 'darwin') {
    return majorVersion === 20 || majorVersion >= 24;
  }
  return false;
};

export {
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
  logoutTokenTester,
  shouldSkipPuppeteerTest,
  launchBrowser,
};
