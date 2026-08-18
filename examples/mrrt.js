const express = require('express');
const { auth, requiresAuth } = require('../');

const app = express();

/*
 * Multi-Resource Refresh Tokens (MRRT).
 *
 * MRRT is an Auth0 feature that lets a single refresh token be exchanged for
 * access tokens targeting multiple pre-approved resource servers (audiences).
 * Which audiences (and scopes) a refresh token may be exchanged for is governed
 * by refresh token policies configured on the Auth0 application — see
 * https://auth0.com/docs/secure/tokens/refresh-tokens/multi-resource-refresh-token
 *
 * `req.oidc.getAccessToken({ audience?, scope? })` drives it:
 *   - no arguments  -> returns a token for the audience used at login, cached in
 *                      the session and refreshed automatically when it expires.
 *   - with audience -> exchanges the session's refresh token for a token scoped
 *                      to that resource server (MRRT). Tokens are cached per
 *                      audience+scope and reused until they expire.
 *
 * `offline_access` must be requested at login so the session holds a refresh
 * token to exchange.
 *
 * Run with: npm run start:example -- mrrt
 * NOTE: MRRT requires a real Auth0 tenant — the bundled mock authorization
 * server does not implement refresh token policies. Configure a tenant and the
 * two audiences via .env (see .env.sample): ISSUER_BASE_URL, CLIENT_ID,
 * CLIENT_SECRET, BASE_URL, SECRET, plus AUDIENCE_1 / SCOPE_1 (used at login) and
 * AUDIENCE_2 / SCOPE_2 (the second resource server). The Auth0 application also
 * needs a refresh token policy authorizing AUDIENCE_2 for the requested scopes.
 */

const {
  AUDIENCE_1,
  SCOPE_1 = 'read:products',
  AUDIENCE_2,
  SCOPE_2 = 'read:orders',
} = process.env;

app.use(
  auth({
    authRequired: false,
    authorizationParams: {
      response_type: 'code',
      audience: AUDIENCE_1,
      scope: `openid profile email offline_access ${SCOPE_1}`,
    },
  }),
);

app.get('/', (req, res) => {
  if (req.oidc.isAuthenticated()) {
    res.send(
      `<p>Logged in as <strong>${req.oidc.user.sub}</strong></p>` +
        '<ul>' +
        '<li><a href="/login-api">Login-audience API</a></li>' +
        '<li><a href="/mrrt-api">Second API (MRRT exchange)</a></li>' +
        '</ul>' +
        '<a href="/logout">logout</a>',
    );
  } else {
    res.send('<a href="/login">login</a>');
  }
});

// Token for the audience configured at login. getAccessToken() returns the
// cached token when it is still valid, or refreshes it when it has expired.
app.get('/login-api', requiresAuth(), async (req, res, next) => {
  try {
    const { access_token, token_type } = await req.oidc.getAccessToken();
    res.json({ audience: AUDIENCE_1, token_type, access_token });
  } catch (err) {
    next(err);
  }
});

// Token for a different resource server. Passing `audience` exchanges the
// session's refresh token for a token scoped to the second API (MRRT). This
// requires a refresh token policy on the Auth0 application authorizing that
// audience and the requested scopes.
app.get('/mrrt-api', requiresAuth(), async (req, res, next) => {
  try {
    const { access_token, token_type } = await req.oidc.getAccessToken({
      audience: AUDIENCE_2,
      scope: SCOPE_2,
    });
    res.json({ audience: AUDIENCE_2, token_type, access_token });
  } catch (err) {
    next(err);
  }
});

module.exports = app;
