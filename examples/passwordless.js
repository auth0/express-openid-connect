const express = require('express');
const { auth } = require('../');

const app = express();

/*
 * Passwordless authentication via Universal Login.
 *
 * Passwordless is an Auth0 connection type (`email` or `sms`). Auth0 hosts the
 * entire experience on the Universal Login page: it sends the one-time code (or
 * magic link) and collects it from the user. This SDK only has to point the
 * browser at the right connection — it never touches the email/phone, the code,
 * or the /passwordless/start endpoint.
 *
 * The SDK signals the connection through the `connection` authorization
 * parameter, and can prefill the identifier with `login_hint`. Both are ordinary
 * authorizationParams, so no dedicated config is needed.
 *
 * Whether the email connection delivers a one-time CODE or a MAGIC LINK is a
 * setting on the Auth0 Email connection, not something the application chooses
 * here. SMS connections deliver a code.
 *
 * Magic-link note: a magic link only completes in the SAME browser that started
 * login, because the callback validates the browser-bound transaction cookie
 * (state/nonce/PKCE). Cross-device magic links (start on laptop, click on phone)
 * are not supported by this redirect-based SDK. One-time codes are unaffected.
 *
 * Run with: npm run start:example -- passwordless
 * NOTE: the bundled mock provider has no passwordless connections, so the
 * /passwordless/email and /passwordless/sms routes below will only reach a real
 * Auth0 tenant that has the email/sms connections enabled. Configure a tenant
 * via .env (ISSUER_BASE_URL, CLIENT_ID, CLIENT_SECRET, BASE_URL, SECRET) to try
 * them end to end.
 */

app.use(
  auth({
    authRequired: false,
    // `code` returns an authorization code the SDK exchanges for tokens. The
    // default `id_token` (implicit) also works for passwordless; use `code`
    // when you also need an access token or refresh token.
    authorizationParams: {
      response_type: 'code',
      scope: 'openid profile email',
    },
  }),
);

app.get('/', (req, res) => {
  if (req.oidc.isAuthenticated()) {
    res.send(
      `<p>Logged in as <strong>${req.oidc.user.sub}</strong></p>` +
        `<a href="/logout">logout</a>`,
    );
  } else {
    res.send(
      '<p>Log in with passwordless:</p>' +
        '<ul>' +
        '<li><a href="/passwordless/email">Email</a></li>' +
        '<li><a href="/passwordless/sms">SMS</a></li>' +
        '</ul>',
    );
  }
});

// Email passwordless. Auth0 sends a one-time code or a magic link (per the
// Email connection's configuration) to the address. Pass the address as
// `login_hint` to prefill it on the Universal Login page, e.g.
// /passwordless/email?email=user@example.com
app.get('/passwordless/email', (req, res) =>
  res.oidc.login({
    returnTo: '/',
    authorizationParams: {
      connection: 'email',
      ...(req.query.email ? { login_hint: req.query.email } : undefined),
    },
  }),
);

// SMS passwordless. Auth0 texts a one-time code to the phone number. Pass the
// number (E.164, e.g. +14155550100) as `login_hint` to prefill it, e.g.
// /passwordless/sms?phone_number=+14155550100
app.get('/passwordless/sms', (req, res) =>
  res.oidc.login({
    returnTo: '/',
    authorizationParams: {
      connection: 'sms',
      ...(req.query.phone_number
        ? { login_hint: req.query.phone_number }
        : undefined),
    },
  }),
);

module.exports = app;
