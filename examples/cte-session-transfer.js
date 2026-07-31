'use strict';

/**
 * CTE Session Transfer — impersonation via Session Transfer Token (STT)
 *
 * Demonstrates the full initiator → target flow across two Express apps running
 * in the same process:
 *
 *   Initiator (PORT 3000) — the support/admin console. The agent logs in here
 *     and requests an STT on behalf of a customer via Custom Token Exchange.
 *
 *   Target (PORT 3001) — the customer-facing app. It receives the STT as a
 *     query parameter on its /login route and forwards it to /authorize to
 *     establish an impersonation session as the subject user.
 *
 * Prerequisites (Auth0 tenant configuration):
 *   - Initiator client: session_transfer.can_create_session_transfer_token = true
 *     and a CTE profile of type custom_authentication that calls setActor()
 *   - Target client: session_transfer.delegation.allow_delegated_access = true,
 *     allowed_authentication_methods = ["query"], jwt_configuration.alg = "RS256"
 *   - The target's callback URL must be a routable HTTPS URL (not localhost) —
 *     use a tunnel (e.g. cloudflared) for local development and set TARGET_BASE_URL
 *
 * This example runs two servers from a single file and cannot be launched via
 * `npm run start:example`. Run it directly:
 *
 *   ISSUER_BASE_URL=https://YOUR_DOMAIN            \
 *   INITIATOR_CLIENT_ID=...                        \
 *   INITIATOR_CLIENT_SECRET=...                    \
 *   TARGET_CLIENT_ID=...                           \
 *   TARGET_CLIENT_SECRET=...                       \
 *   SUBJECT_TOKEN=YOUR_SUBJECT_USER_ID             \
 *   SUBJECT_TOKEN_TYPE=urn:yourcompany:token-type  \
 *   SECRET=LONG_RANDOM_VALUE                       \
 *   node examples/cte-session-transfer.js
 *
 * Or with a .env file:
 *   node -r dotenv/config examples/cte-session-transfer.js dotenv_config_path=.env
 */

const express = require('express');
const { auth, requiresAuth } = require('../');

const {
  ISSUER_BASE_URL,
  SECRET = 'LONG_RANDOM_VALUE',
  INITIATOR_CLIENT_ID,
  INITIATOR_CLIENT_SECRET,
  TARGET_CLIENT_ID,
  TARGET_CLIENT_SECRET,
  INITIATOR_PORT = 3000,
  TARGET_PORT = 3001,
  // Optional: public HTTPS base URL for the target (required when localhost
  // callbacks are not accepted by the AS for STT redemption).
  TARGET_BASE_URL,
  // The subject token your CTE Action uses to identify the customer.
  SUBJECT_TOKEN,
  // The subject_token_type registered in your CTE profile.
  SUBJECT_TOKEN_TYPE,
} = process.env;

// ---------------------------------------------------------------------------
// Initiator app
// ---------------------------------------------------------------------------
const initiator = express();

initiator.use(
  auth({
    issuerBaseURL: ISSUER_BASE_URL,
    clientID: INITIATOR_CLIENT_ID,
    clientSecret: INITIATOR_CLIENT_SECRET,
    baseURL: `http://localhost:${INITIATOR_PORT}`,
    secret: SECRET,
    // Distinct session name avoids cookie collision when both apps share a domain.
    session: { name: 'appSession.initiator' },
    authorizationParams: {
      response_type: 'code',
      // offline_access is required so the SDK can refresh the id_token used as
      // the actor_token when it expires before the STT is requested.
      scope: 'openid profile email offline_access',
    },
  }),
);

initiator.get('/', requiresAuth(), (req, res) => {
  const { sub, name, email } = req.oidc.user;
  res.send(`
    <h2>Initiator App (support console)</h2>
    <p>Logged in as: <strong>${name || email || sub}</strong> (${sub})</p>
    <form method="POST" action="/impersonate">
      <p>Subject token: <input name="subjectToken" value="${SUBJECT_TOKEN || ''}" size="40" /></p>
      <p>Reason: <input name="reason" value="" size="40" /></p>
      <button type="submit">Impersonate customer →</button>
    </form>
    <hr/>
    <a href="/logout">Logout</a>
  `);
});

initiator.use(express.urlencoded({ extended: false }));
initiator.post('/impersonate', requiresAuth(), async (req, res, next) => {
  try {
    const subjectToken = req.body.subjectToken;
    const reason = req.body.reason;

    const result = await req.oidc.requestSessionTransferToken({
      subject_token: subjectToken,
      subject_token_type: SUBJECT_TOKEN_TYPE,
      ...(reason && { extra: { reason } }),
    });

    const targetLoginUrl = TARGET_BASE_URL
      ? `${TARGET_BASE_URL}/login`
      : `http://localhost:${TARGET_PORT}/login`;

    const redirectUrl = req.oidc.buildSessionTransferRedirect(
      targetLoginUrl,
      result,
    );

    res.redirect(redirectUrl);
  } catch (err) {
    // err.error contains the OAuth error code, err.message the description.
    next(err);
  }
});

initiator.get('/logout', (req, res) => {
  res.oidc.logout({ returnTo: `http://localhost:${INITIATOR_PORT}` });
});

// ---------------------------------------------------------------------------
// Target app
// ---------------------------------------------------------------------------
const target = express();

target.use(
  auth({
    issuerBaseURL: ISSUER_BASE_URL,
    clientID: TARGET_CLIENT_ID,
    clientSecret: TARGET_CLIENT_SECRET,
    baseURL: TARGET_BASE_URL || `http://localhost:${TARGET_PORT}`,
    secret: SECRET,
    session: { name: 'appSession.target' },
    // authRequired: false is required so the custom /login route below runs
    // freely. With the default (true) the auth middleware intercepts
    // unauthenticated requests to /login before the route handler fires,
    // stashing the STT in returnTo state instead of forwarding it to /authorize.
    authRequired: false,
    routes: {
      login: false,
    },
    authorizationParams: {
      response_type: 'code',
      scope: 'openid profile email',
    },
  }),
);

// Custom /login — forwards the STT (and optional organization) to /authorize.
target.get('/login', async (req, res, next) => {
  try {
    const authorizationParams = {};

    if (req.query.session_transfer_token) {
      authorizationParams.session_transfer_token =
        req.query.session_transfer_token;
    }
    if (req.query.organization) {
      authorizationParams.organization = req.query.organization;
    }

    // returnTo: '/' prevents an infinite redirect loop: without it the SDK
    // stores /login?session_transfer_token=... as the post-callback destination,
    // which triggers another login cycle after the callback completes.
    await res.oidc.login({ authorizationParams, returnTo: '/' });
  } catch (err) {
    next(err);
  }
});

target.get('/', requiresAuth(), (req, res) => {
  const user = req.oidc.user;
  const actor = user.act;

  res.send(`
    <h2>Target App (customer app)</h2>
    ${
      actor
        ? `<div style="background:#fff3cd;padding:12px;border:1px solid #ffc107;margin-bottom:16px">
             ⚠️ <strong>Impersonation session</strong> — acting as customer on behalf of agent<br/>
             Actor: <code>${JSON.stringify(actor)}</code>
           </div>`
        : '<p>(No impersonation — normal session)</p>'
    }
    <h3>Session (sub = customer)</h3>
    <pre>${JSON.stringify(user, null, 2)}</pre>
    <hr/>
    <a href="/logout">Logout</a>
  `);
});

target.get('/logout', (req, res) => {
  res.oidc.logout({
    returnTo: TARGET_BASE_URL || `http://localhost:${TARGET_PORT}`,
  });
});

// ---------------------------------------------------------------------------
// Start both servers
// ---------------------------------------------------------------------------
initiator.listen(INITIATOR_PORT, () =>
  console.log(`[initiator] http://localhost:${INITIATOR_PORT}`),
);

target.listen(TARGET_PORT, () =>
  console.log(
    `[target]    ${TARGET_BASE_URL || `http://localhost:${TARGET_PORT}`}`,
  ),
);
