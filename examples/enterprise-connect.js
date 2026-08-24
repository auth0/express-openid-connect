const express = require('express');
const { auth } = require('../');

const app = express();

// Enterprise Connect (app-embedded) demo.
//
// Auth0 acts as a pure SSO relay here: it federates to the enterprise IdP and
// hands back an ID token, but holds no session of its own. This app owns the
// session entirely - afterCallback writes it to a cookie and returns
// `undefined`, which suppresses the SDK's own session cookie write.
//
// Run with: node examples/run_example.js enterprise-connect
// Against the mock provider, isFederatedDomain() always resolves false (the
// mock has no WebFinger endpoint), so the login form falls through to the
// "not federated" branch below. Point ISSUER_BASE_URL/CLIENT_ID at a real
// Enterprise Connect tenant in examples/.env to see the federated redirect.

const APP_SESSION_COOKIE = 'ec_app_session';

function getAppSession(req) {
  const header = req.headers.cookie || '';
  const match = header
    .split(';')
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${APP_SESSION_COOKIE}=`));
  if (!match) {
    return null;
  }
  try {
    const raw = match.slice(APP_SESSION_COOKIE.length + 1);
    return JSON.parse(Buffer.from(raw, 'base64').toString('utf-8'));
  } catch {
    return null;
  }
}

app.use(
  auth({
    authRequired: false,
    enterpriseConnect: true,
    authorizationParams: {
      response_type: 'code',
      scope: 'openid profile email', // no offline_access - no refresh tokens in EC mode
      // Do NOT set a static organization - it is resolved per login via HRD
    },
    afterCallback: (req, res) => {
      const claims = req.oidc.idTokenClaims;
      const encoded = Buffer.from(
        JSON.stringify({
          sub: claims.sub,
          email: claims.email,
          orgId: claims['org_id'],
        }),
      ).toString('base64');
      res.cookie(APP_SESSION_COOKIE, encoded, {
        httpOnly: true,
        sameSite: 'lax',
      });

      // Return undefined: the SDK skips writing its own session cookie, since
      // this app's own session (set above) is already on the response.
      return undefined;
    },
  }),
);

app.get('/', (req, res) => {
  const session = getAppSession(req);
  if (session) {
    return res.send(
      `<p>Logged in as <strong>${session.email}</strong> (org: ${session.orgId || 'n/a'})</p>` +
        `<a href="/ec-logout">logout</a>`,
    );
  }
  res.send(`
    <form method="POST" action="/ec-login">
      <label>Work email <input name="email" type="email" required></label>
      <button type="submit">Continue</button>
    </form>
  `);
});

app.post(
  '/ec-login',
  express.urlencoded({ extended: false }),
  async (req, res) => {
    const { email } = req.body;
    const started = await res.oidc.startEnterpriseLogin({
      email,
      returnTo: '/',
    });
    if (!started) {
      res.send(
        `<p>${email} is not on a federated domain.</p><a href="/">back</a>`,
      );
    }
    // federated -> startEnterpriseLogin already issued the redirect.
  },
);

app.get('/ec-logout', (req, res) => {
  res.clearCookie(APP_SESSION_COOKIE);
  res.oidc.logout({ returnTo: '/', federated: true });
});

module.exports = app;
