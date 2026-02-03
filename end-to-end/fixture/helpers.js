import path from 'path';
import crypto from 'crypto';
import http from 'http';
import sinon from 'sinon';
import express from 'express';
import { SignJWT } from 'jose';
import { getPrivateJWK } from './jwk.js';
import request from 'request-promise-native';
import puppeteer from 'puppeteer';

const requestDefaults = request.defaults({ json: true });

// Use 127.0.0.1 directly to avoid DNS resolution issues in CI
const baseUrl = 'http://127.0.0.1:3000';

/**
 * Wait for a server to be ready by attempting to connect to it
 */
const waitForServer = (
  port,
  host = '127.0.0.1',
  maxAttempts = 30,
  delay = 100,
) => {
  return new Promise((resolve, reject) => {
    let attempts = 0;
    const tryConnect = () => {
      attempts++;
      const req = http.get(`http://${host}:${port}/`, (res) => {
        // Any response means server is up
        res.resume(); // Consume response data to free up memory
        resolve();
      });

      req.on('error', (err) => {
        if (attempts >= maxAttempts) {
          reject(
            new Error(
              `Server not ready after ${maxAttempts} attempts: ${err.message}`,
            ),
          );
        } else {
          setTimeout(tryConnect, delay);
        }
      });

      req.setTimeout(1000, () => {
        req.destroy();
        if (attempts >= maxAttempts) {
          reject(
            new Error(
              `Server not ready after ${maxAttempts} attempts: timeout`,
            ),
          );
        } else {
          setTimeout(tryConnect, delay);
        }
      });
    };
    tryConnect();
  });
};

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

const start = async (app, port) => {
  return new Promise((resolve, reject) => {
    // Add error handling for the app
    app.on('error', (error) => {
      console.error(`Express app error:`, error);
    });

    // Bind to 0.0.0.0 to accept connections from any interface
    const server = app.listen(port, '0.0.0.0', async (err) => {
      if (err) {
        console.error(`Failed to start server on port ${port}:`, err);
        reject(err);
      } else {
        try {
          // Wait for the server to be ready to accept connections
          await waitForServer(port);
          resolve(server);
        } catch (waitErr) {
          console.error(`Server wait failed:`, waitErr);
          reject(waitErr);
        }
      }
    });

    // Add error handler for the server
    server.on('error', (error) => {
      console.error(`Server error on port ${port}:`, error);
      reject(error);
    });
  });
};

const runExample = async (name) => {
  // Ensure environment variables are set BEFORE the dynamic import
  // because auth() is called during module initialization
  // Use 127.0.0.1 to avoid DNS resolution issues in CI
  const env = {
    ISSUER_BASE_URL: 'http://127.0.0.1:3001',
    CLIENT_ID: 'test-express-openid-connect-client-id',
    BASE_URL: 'http://127.0.0.1:3000',
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
    ISSUER_BASE_URL: 'http://127.0.0.1:3001',
    CLIENT_ID: 'test-express-openid-connect-client-id',
    BASE_URL: 'http://127.0.0.1:3000',
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

  // Login form submission
  await Promise.all([page.click('.login-submit'), page.waitForNavigation()]);

  // Check if we need to handle consent
  try {
    // Wait for either consent form or redirect back to app
    await page.waitForSelector('.login-submit', { timeout: 1000 });
    // If consent form exists, click it
    await Promise.all([
      page.click('.login-submit'),
      page.waitForNavigation({ timeout: 10000 }),
    ]);
  } catch {
    // No consent form found, might already be redirected
  }

  // Wait for final redirect back to the app (with longer timeout)
  let attempts = 0;
  const maxAttempts = 10;
  while (
    !page.url().startsWith('http://127.0.0.1:3000') &&
    attempts < maxAttempts
  ) {
    try {
      await page.waitForNavigation({ timeout: 2000 });
    } catch {
      // Navigation timeout, check URL again
    }
    attempts++;
  }

  // If we're still not back at the app, there might be an issue
  if (!page.url().startsWith('http://127.0.0.1:3000')) {
    console.log(`Login did not complete properly. Final URL: ${page.url()}`);
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
    .setIssuer(`http://127.0.0.1:${process.env.PROVIDER_PORT || 3001}`)
    .setAudience(clientId)
    .setIssuedAt()
    .setJti(crypto.randomBytes(16).toString('hex'))
    .sign(privateJWK);

  res.send(`
    <pre style="border: 1px solid #ccc; padding: 10px; white-space: break-spaces; background: whitesmoke;">curl -X POST http://127.0.0.1:3000/backchannel-logout -d "logout_token=${logoutToken}"</pre>
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
