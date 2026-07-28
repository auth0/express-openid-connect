# Examples

1. [Basic setup](#1-basic-setup)
2. [Require authentication for specific routes](#2-require-authentication-for-specific-routes)
3. [Route customization](#3-route-customization)
4. [Obtaining access tokens to call external APIs](#4-obtaining-access-tokens-to-call-external-apis)
5. [Obtaining and using refresh tokens](#5-obtaining-and-using-refresh-tokens)
6. [Calling userinfo](#6-calling-userinfo)
7. [Protect a route based on specific claims](#7-protect-a-route-based-on-specific-claims)
8. [Logout from Identity Provider](#8-logout-from-identity-provider)
9. [Validate Claims from an ID token before logging a user in](#9-validate-claims-from-an-id-token-before-logging-a-user-in)
10. [Use a custom session store](#10-use-a-custom-session-store)
11. [Back-Channel Logout](#11-back-channel-logout)
12. [Custom Token Exchange](#12-custom-token-exchange)
13. [Impersonation via Session Transfer Token](#13-impersonation-via-session-transfer-token)
14. [Use a proxy for OIDC requests](#14-use-a-proxy-for-oidc-requests)
15. [Session expiry from upstream IdP (IPSIE `session_expiry`)](#15-session-expiry-from-upstream-idp-ipsie-session_expiry)
16. [JWT-Secured Authorization Requests (JAR)](#16-jwt-secured-authorization-requests-jar)
17. [mTLS client authentication](#17-mtls-client-authentication)

## 1. Basic setup

The simplest use case for this middleware. By default all routes are protected. The middleware uses the [Implicit Flow with Form Post](https://auth0.com/docs/flows/concepts/implicit) to acquire an ID Token from the authorization server and an encrypted cookie session to persist it.

```text
# .env
ISSUER_BASE_URL=https://YOUR_DOMAIN
CLIENT_ID=YOUR_CLIENT_ID
BASE_URL=https://YOUR_APPLICATION_ROOT_URL
SECRET=LONG_RANDOM_STRING
```

```js
// basic.js
const express = require('express');
const { auth } = require('express-openid-connect');

const app = express();

app.use(auth());

app.get('/', (req, res) => {
  res.send(`hello ${req.oidc.user.sub}`);
});
```

**What you get:**

- Every route after the `auth()` middleware requires authentication.
- If a user tries to access a resource without being authenticated, the application will redirect the user to log in. After completion the user is redirected back to the resource.
- The application creates `/login` and `/logout` `GET` routes.

Full example at [basic.js](./examples/basic.js), to run it: `npm run start:example -- basic`

## 2. Require authentication for specific routes

If your application has routes accessible to anonymous users, you can enable authorization per route:

```js
const { auth, requiresAuth } = require('express-openid-connect');

app.use(
  auth({
    authRequired: false,
  }),
);

// Anyone can access the homepage
app.get('/', (req, res) => {
  res.send('<a href="/admin">Admin Section</a>');
});

// requiresAuth checks authentication.
app.get('/admin', requiresAuth(), (req, res) =>
  res.send(`Hello ${req.oidc.user.sub}, this is the admin section.`),
);
```

Full example at [routes.js](./examples/routes.js), to run it: `npm run start:example -- routes`

## 3. Route customization

If you need to customize the provided login, logout, and callback routes, you can disable the default routes and write your own route handler and pass custom paths to mount the handler at that path.

When overriding the callback route you should pass a `authorizationParams.redirect_uri` value on `res.oidc.login` and a `redirectUri` value on your `res.oidc.callback` call.

```js
app.use(
  auth({
    routes: {
      // Override the default login route to use your own login route as shown below
      login: false,
      // Pass a custom path to redirect users to a different
      // path after logout.
      postLogoutRedirect: '/custom-logout',
      // Override the default callback route to use your own callback route as shown below
      callback: false,
    },
  }),
);

app.get('/login', (req, res) =>
  res.oidc.login({
    returnTo: '/profile',
    authorizationParams: {
      redirect_uri: 'http://localhost:3000/callback',
    },
  }),
);

app.get('/custom-logout', (req, res) => res.send('Bye!'));

app.get('/callback', (req, res) =>
  res.oidc.callback({
    redirectUri: 'http://localhost:3000/callback',
  }),
);

app.post('/callback', express.urlencoded({ extended: false }), (req, res) =>
  res.oidc.callback({
    redirectUri: 'http://localhost:3000/callback',
  }),
);

module.exports = app;
```

Please note that the login and logout routes are not required. Trying to access any protected resource triggers a redirect directly to Auth0 to login. These are helpful if you need to provide user-facing links to login or logout.

Full example at [custom-routes.js](./examples/custom-routes.js), to run it: `npm run start:example -- custom-routes`

## 4. Obtaining access tokens to call external APIs

If your application needs an [access token](https://auth0.com/docs/tokens/access-tokens) for external APIs you can request one by adding `code` to your `response_type`. The Access Token will be available on the request context:

```js
app.use(
  auth({
    authorizationParams: {
      response_type: 'code', // This requires you to provide a client secret
      audience: 'https://api.example.com/products',
      scope: 'openid profile email read:products',
    },
  }),
);

app.get('/', async (req, res) => {
  let { token_type, access_token } = req.oidc.accessToken;
  const products = await request.get('https://api.example.com/products', {
    headers: {
      Authorization: `${token_type} ${access_token}`,
    },
  });
  res.send(`Products: ${products}`);
});
```

Full example at [access-an-api.js](./examples/access-an-api.js), to run it: `npm run start:example -- access-an-api`

## 5. Obtaining and using refresh tokens

[Refresh tokens](https://auth0.com/docs/tokens/concepts/refresh-tokens) can be requested along with access tokens using the `offline_access` scope during login. On a route that calls an API, check for an expired token and attempt a refresh:

```js
app.use(
  auth({
    authorizationParams: {
      response_type: 'code', // This requires you to provide a client secret
      audience: 'https://api.example.com/products',
      scope: 'openid profile email offline_access read:products',
    },
  }),
);

app.get('/', async (req, res) => {
  let { token_type, access_token, isExpired, refresh } = req.oidc.accessToken;
  if (isExpired()) {
    ({ access_token } = await refresh());
  }
  const products = await request.get('https://api.example.com/products', {
    headers: {
      Authorization: `${token_type} ${access_token}`,
    },
  });
  res.send(`Products: ${products}`);
});
```

Full example at [access-an-api.js](./examples/access-an-api.js), to run it: `npm run start:example -- access-an-api`

## 6. Calling userinfo

If your application needs to call the `/userinfo` endpoint you can use the `fetchUserInfo` method on the request context:

```js
app.use(auth());

app.get('/', async (req, res) => {
  const userInfo = await req.oidc.fetchUserInfo();
  // ...
});
```

Full example at [userinfo.js](./examples/userinfo.js), to run it: `npm run start:example -- userinfo`

## 7. Protect a route based on specific claims

You can check a user's specific claims to determine if they can access a route:

```js
const {
  auth,
  claimEquals,
  claimIncludes,
  claimCheck,
} = require('express-openid-connect');

app.use(
  auth({
    authRequired: false,
  }),
);

// claimEquals checks if a claim equals the given value
app.get('/admin', claimEquals('isAdmin', true), (req, res) =>
  res.send(`Hello ${req.oidc.user.sub}, this is the admin section.`),
);

// claimIncludes checks if a claim includes all the given values
app.get(
  '/sales-managers',
  claimIncludes('roles', 'sales', 'manager'),
  (req, res) =>
    res.send(`Hello ${req.oidc.user.sub}, this is the sales managers section.`),
);

// claimCheck takes a function that checks the claims and returns true to allow access
app.get(
  '/payroll',
  claimCheck(({ isAdmin, roles }) => isAdmin || roles.includes('payroll')),
  (req, res) =>
    res.send(`Hello ${req.oidc.user.sub}, this is the payroll section.`),
);
```

## 8. Logout from Identity Provider

When using an IDP, such as Auth0, the default configuration will only log the user out of your application session. When the user logs in again, they will be automatically logged back in to the IDP session. To have the user additionally logged out of the IDP session you will need to add `idpLogout: true` to the middleware configuration.

```js
const { auth } = require('express-openid-connect');

app.use(
  auth({
    idpLogout: true,
    // auth0Logout: true // if using custom domain with Auth0
  }),
);
```

## 9. Validate Claims from an ID token before logging a user in

The `afterCallback` hook can be used to do validation checks on claims after the ID token has been received in the callback phase.

```js
const { decodeJwt } = require('jose'); // jose v6 named export

app.use(
  auth({
    afterCallback: (req, res, session) => {
      const claims = decodeJwt(session.id_token);
      if (claims.org_id !== 'Required Organization') {
        throw new Error('User is not a part of the Required Organization');
      }
      return session;
    },
  }),
);
```

In this example, the application is validating the `org_id` to verify that the ID Token was issued to the correct Organization. [Organizations](https://auth0.com/docs/organizations) is a set of features of Auth0 that provide better support for developers who build and maintain SaaS and Business-to-Business (B2B) applications.

If you don't know the Organization upfront, then your application should validate the claim to ensure that the value received is expected or known and that it corresponds to an entity your application trusts, such as a paying customer. If the claim cannot be validated, then the application should deem the token invalid. See https://auth0.com/docs/organizations/using-tokens for more info.

## 10. Use a custom session store

By default the session is stored in an encrypted cookie. But when the session gets too large it can bump up against the limits of the platform's max header size (16KB for Node >= 14, 8KB for Node <14). In these instances you can use a custom session store. The store should have `get`, `set` and `destroy` methods, making it compatible with [express-session stores](https://github.com/expressjs/session#session-store-implementation).

```js
const { auth } = require('express-openid-connect');
const { createClient } = require('redis');
const RedisStore = require('connect-redis')(auth);

// redis@v4
let redisClient = createClient({ legacyMode: true });
redisClient.connect().catch(console.error);

// redis@v3
let redisClient = createClient();

app.use(
  auth({
    session: {
      store: new RedisStore({ client: redisClient }),
    },
  }),
);
```

Full example at [custom-session-store.js](./examples/custom-session-store.js), to run it: `npm run start:example -- custom-session-store`

## 11. Back-Channel Logout

Configure the SDK with `backchannelLogout` enabled. You will also need a session store (like Redis) - you can use any `express-session` compatible store.

```js
// index.js
const { auth } = require('express-openid-connect');
const { createClient } = require('redis');
const RedisStore = require('connect-redis')(auth);

// redis@v4
let redisClient = createClient({ legacyMode: true });
redisClient.connect();

app.use(
  auth({
    idpLogout: true,
    backchannelLogout: {
      store: new RedisStore({ client: redisClient }),
    },
  }),
);
```

If you're already using a session store for stateful sessions you can just reuse that.

```js
app.use(
  auth({
    idpLogout: true,
    session: {
      store: new RedisStore({ client: redisClient }),
    },
    backchannelLogout: true,
  }),
);
```

### This will:

- Create the handler `/backchannel-logout` that you can register with your Identity Provider.
- On receipt of a valid Logout Token, the SDK will store an entry by `sid` (Session ID) and an entry by `sub` (User ID) in the `backchannelLogout.store` - the expiry of the entry will be set to the duration of the session (this is customisable using the [onLogoutToken](https://auth0.github.io/express-openid-connect/interfaces/BackchannelLogoutOptions.html#onLogoutToken) config hook)
- On all authenticated requests, the SDK will check the store for an entry that corresponds with the session's ID token's `sid` or `sub`. If it finds a corresponding entry it will invalidate the session and clear the session cookie. (This is customisable using the [isLoggedOut](https://auth0.github.io/express-openid-connect/interfaces/BackchannelLogoutOptions.html#isLoggedOut) config hook)
- If the user logs in again, the SDK will remove any stale `sub` entry in the Back-Channel Logout store to ensure they are not logged out immediately (this is customisable using the [onLogin](https://auth0.github.io/express-openid-connect/interfaces/BackchannelLogoutOptions.html#onLogin) config hook)

The config options are [documented here](https://auth0.github.io/express-openid-connect/interfaces/BackchannelLogoutOptions.html)

## 12. Custom Token Exchange

When your app logs in with one API audience but needs to call a different downstream service, `customTokenExchange()` lets you swap the session's access token for one accepted by that service. This follows the [OAuth 2.0 Token Exchange spec (RFC 8693)](https://www.rfc-editor.org/rfc/rfc8693).

```js
const { auth, requiresAuth } = require('express-openid-connect');
const axios = require('axios');

app.use(
  auth({
    authorizationParams: {
      response_type: 'code',
      // Token issued at login is scoped to the upstream API
      audience: 'https://api.example.com',
      scope: 'openid profile offline_access',
    },
  }),
);

app.get('/reports', requiresAuth(), async (req, res, next) => {
  try {
    // Exchange the session token for one accepted by the reporting service.
    // subject_token and subject_token_type are resolved automatically.
    const { access_token } = await req.oidc.customTokenExchange({
      audience: 'https://reports.internal.example.com',
      scope: 'openid read:reports',
    });

    const { data } = await axios.get(
      'https://reports.internal.example.com/v1/summary',
      { headers: { Authorization: `Bearer ${access_token}` } },
    );

    res.json(data);
  } catch (err) {
    // Authorization server rejections surface as HTTP 400 and 401
    // with err.error and err.error_description set
    next(err);
  }
});
```

`subject_token` is resolved automatically from the session's accessToken and `subject_token_type` defaults to [urn:ietf:params:oauth:token-type:access_token](https://datatracker.ietf.org/doc/html/rfc8693#section-3-3.2). The returned token is ephemeral — it is not stored in the session, so use it within the same request.

### Delegation / impersonation

Use `actor_token` and `actor_token_type` to perform a delegation exchange (RFC 8693). The response includes an `act` claim identifying the acting party.

```js
app.post('/impersonate', requiresAuth(), async (req, res, next) => {
  try {
    const { customerSubjectToken, customerSubjectTokenType } = req.body;

    const tokenSet = await req.oidc.customTokenExchange({
      subject_token: customerSubjectToken,
      subject_token_type: customerSubjectTokenType,
      actor_token: req.oidc.accessToken.access_token,
      actor_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      audience: 'https://api.example.com/support',
    });

    // tokenSet.act identifies the acting party: { sub: '<agent-sub>' }
    res.json({ access_token: tokenSet.access_token, act: tokenSet.act });
  } catch (err) {
    next(err);
  }
});
```

`actor_token_type` is required when `actor_token` is provided.

### Organization-scoped exchange

Use `organization` to issue a token bound to a specific organization:

```js
const tokenSet = await req.oidc.customTokenExchange({
  audience: 'https://api.example.com/products',
  scope: 'read:products',
  organization: 'org_abc123',
});
```

### Vendor-specific parameters

Parameters not covered by the named options (e.g., Token Vault connection) can be passed through the `extra` option:

```js
const tokenSet = await req.oidc.customTokenExchange({
  audience: 'https://downstream-api.example.com',
  scope: 'read:data',
  extra: {
    connection: 'google-oauth2',
  },
});
```

## 13. Impersonation via Session Transfer Token

Custom Token Exchange Impersonation via Session Transfer lets a support or admin application log a user into a target web application as a customer — so a support engineer can reproduce the customer's exact experience without knowing their password. The initiator is recorded in the `act` claim on the impersonated session, making every impersonation auditable.

The flow involves two roles:

- **Initiator** — your support/admin app. It requests a short-lived, single-use Session Transfer Token (STT) and redirects the user's browser to the target app carrying the STT.
- **Target** — the customer's web app. It forwards the STT to `/authorize`, where Auth0 redeems it and establishes an ephemeral session as the customer, recording the initiator in the `act` (actor) claim.

The STT is **opaque, single-use, and short-lived (~60s)**. The SDK requests it, surfaces it, and helps you build the redirect — it never decodes, validates, caches, or persists it.

> **Prerequisites:** See [Custom Token Exchange docs](https://auth0.com/docs/authenticate/custom-token-exchange) for prerequisites and setup.

### Initiator: requesting an STT and redirecting

The user must be logged in to the initiator app — the SDK sources the actor from the session's ID token by default (refreshing it automatically if expired). Run your own authorization check before calling the SDK.

```js
const { auth, requiresAuth } = require('express-openid-connect');

app.post('/impersonate', requiresAuth(), async (req, res, next) => {
  try {
    // Your own proof of which customer to impersonate — validated by your Action.
    const { customerToken, customerTokenType } = req.body;

    const result = await req.oidc.requestSessionTransferToken({
      subject_token: customerToken,
      subject_token_type: customerTokenType,
      // Optional: pass custom context to your Action via event.request.body
      extra: { reason: 'Investigating ticket TCK-1234' },
    });

    // targetLoginUrl must be a trusted, app-controlled value — never derived from
    // untrusted input such as a returnTo param, or the STT could leak to an attacker host.
    const redirectUrl = req.oidc.buildSessionTransferRedirect(
      'https://app.example.com/auth/login',
      result,
    );

    res.redirect(redirectUrl);
  } catch (err) {
    // err.error === 'actor_unavailable'        — user not logged in or session expired
    // err.error === 'setactor_required'        — Action did not call setActor
    next(err);
  }
});
```

> [!IMPORTANT]
> An actor is mandatory for an STT — that is what makes this auditable impersonation ("X acting as Y") rather than a silent takeover. If no explicit `actor_token` is passed and no usable session ID token can be resolved (user not logged in, or expired ID token with no refresh token), the SDK throws with `err.error === 'actor_unavailable'` before any network call. The session ID token must also be unexpired; the SDK refreshes it automatically when a refresh token is available.

> **Branch on `result.issued_token_type`**, not `result.token_type`. The `token_type` field is `"N_A"` for an STT response — it is informational only. `issued_token_type` is always `"urn:auth0:params:oauth:token-type:session_transfer_token"` for a successful STT exchange, and `buildSessionTransferRedirect` requires exactly that value.

If the customer belongs to an organization, forward it on the redirect:

```js
const redirectUrl = req.oidc.buildSessionTransferRedirect(
  'https://app.example.com/auth/login',
  result,
  { organization: 'org_globex' },
);
```

To supply the acting party explicitly instead of using the session ID token:

```js
const result = await req.oidc.requestSessionTransferToken({
  subject_token: customerToken,
  subject_token_type: customerTokenType,
  actor_token: agentIdToken,
  actor_token_type: 'urn:ietf:params:oauth:token-type:id_token',
});
```

> **Explicit `actor_token` requirements:** Auth0 validates the actor token server-side before running the exchange. It must be unexpired and signed with an asymmetric algorithm (RS256 or PS256) — an HS256 token or an expired token will be rejected. An Auth0 session ID token already satisfies both requirements; if you source `actor_token` from elsewhere, ensure it meets them.

### Target: redeeming the STT

On the target app, forward the `session_transfer_token` query parameter (and `organization` when present) to `/authorize` through the existing `res.oidc.login()` call — no new SDK methods required.

The target app must set `authRequired: false` on the `auth()` middleware so the custom login route handles the request directly. Without it, the middleware intercepts the unauthenticated request to `/login` and stashes the STT in `returnTo` state instead of forwarding it to `/authorize`.

```js
app.use(
  auth({
    // ... your other config
    authRequired: false, // required — lets the custom /login route run freely
    routes: { login: false },
  }),
);

app.get('/auth/login', async (req, res) => {
  const authorizationParams = {};

  if (req.query.session_transfer_token) {
    authorizationParams.session_transfer_token =
      req.query.session_transfer_token;
  }
  if (req.query.organization) {
    authorizationParams.organization = req.query.organization;
  }

  // returnTo: '/' prevents a redirect loop after the callback —
  // without it the SDK redirects back to /login?session_transfer_token=...
  await res.oidc.login({ authorizationParams, returnTo: '/' });
});
```

The established session is short-lived (hard-capped at 2 hours) and cannot mint a refresh token.

> [!NOTE]
> Because the STT travels as a query parameter, it can land in places that log or retain full URLs — web-server access logs, proxy/CDN logs, and the browser's history. This is inherent to the redemption mechanism and is mitigated by the token being single-use and short-lived (~60s): a leaked STT is worthless once redeemed or expired. Even so, avoid logging redemption URLs verbatim, and never persist or forward the STT beyond the immediate redirect.

### Reading the `act` claim

Once the impersonation session is established, the acting party is available as `req.oidc.user.act`:

```js
app.get('/dashboard', requiresAuth(), (req, res) => {
  const actor = req.oidc.user.act; // { sub: 'support-agent-007' } when impersonated
  if (actor) {
    // Render an impersonation banner so the agent knows they are acting as the customer.
  }
  res.render('dashboard');
});
```

## 14. Use a proxy for OIDC requests

If you need to route all OIDC HTTP requests (discovery, token, userinfo, etc.) through a proxy, use the `customFetch` option with `undici`'s `ProxyAgent`:

```js
const express = require('express');
const { auth } = require('express-openid-connect');
const { ProxyAgent, fetch: undiciFetch } = require('undici');

const app = express();

const dispatcher = new ProxyAgent('http://proxy.example.com:8080');

app.use(
  auth({
    customFetch: (url, options) => undiciFetch(url, { ...options, dispatcher }),
    // ... other options
  }),
);
```

The SDK wraps your `customFetch` function to add required headers (User-Agent, Auth0-Client telemetry) before making requests.

## 15. Session expiry from upstream IdP (IPSIE `session_expiry`)

When an upstream IdP supports the IPSIE SL1 spec, it can include a `session_expiry` claim in the ID token — an absolute Unix timestamp (seconds) marking the latest moment the IdP considers the session valid.

### Emitting the claim

How the claim is included in the ID token depends on your authorization server. For example on Auth0, it is emitted on `okta` and `oidc` enterprise connections configured with `id_token_session_expiry_supported: true`, computing it as the earliest of the tenant's absolute session lifetime, the upstream IdP's own session expiry, and any value set via `api.session.setExpiresAt` in a Post-Login Action. For the canonical Action setup, see the [Auth0 documentation](#) _(link to be added once the session_expiry Action guide is published)_.

> [!WARNING]
> `session_expiry` must be a Unix timestamp in **seconds**. The SDK rejects implausibly large values (anything at or above `10,000,000,000`, ≈ year 2286) as malformed and treats them as "no ceiling", so a milliseconds value will silently disable enforcement rather than expiring the session ~55,000 years from now. Any other malformed value — non-integer, float, zero, or negative — also fails open. If your authorization server computes this value from a millisecond timestamp, ensure it divides by 1000 before including it in the ID token. For example, in an Auth0 Post-Login Action, make sure to convert the timestamp to seconds before setting the claim.

### What the SDK does automatically

No configuration or code change is required. When the claim is present, the SDK handles everything automatically:

- Persists the ceiling as `sessionExpiresAt` (Unix seconds) on the session.
- Rejects login with HTTP 400 if the ceiling is already in the past at callback time, so a born-dead session is never persisted.
- Treats the session as expired once `sessionExpiresAt` is reached on every request, with a 30-second leeway for clock skew.
- Throws `SessionExpiredError` on `accessToken.refresh()` instead of making a token endpoint call that would fail anyway.
- Caps the session cookie lifetime at the ceiling as a defense-in-depth backstop.

This is layered **on top of** your existing idle and absolute session timeouts — the session ends at whichever limit is reached first.

### Behavior on expiry

- **Session reads:** `req.appSession` is cleared and `req.oidc.isAuthenticated()` returns `false`. Your existing redirect-to-login path runs unchanged.
- **Token refresh:** `req.oidc.accessToken.refresh()` throws `SessionExpiredError` (`error.code === 'ERR_SESSION_EXPIRED'`, `error.status === 401`). Catch it to redirect the user to log in again.

```js
const { SessionExpiredError } = require('express-openid-connect');

app.get('/resource', async (req, res, next) => {
  try {
    let { token_type, access_token, isExpired, refresh } = req.oidc.accessToken;
    if (isExpired()) {
      ({ access_token } = await refresh());
    }
    // use access_token
  } catch (err) {
    if (err instanceof SessionExpiredError) {
      return res.redirect('/');
    }
    next(err);
  }
});
```

### Reading the value (optional)

To show a "your session ends soon" prompt, read `sessionExpiresAt` off the session:

```js
app.get('/status', (req, res) => {
  const { sessionExpiresAt } = req.appSession || {};
  if (sessionExpiresAt) {
    const remainingSeconds = sessionExpiresAt - Math.floor(Date.now() / 1000);
    res.json({ remainingSeconds });
  } else {
    res.json({});
  }
});
```

### Upgrading existing apps

Once your IdP starts emitting `session_expiry`, `req.appSession` can be `null` for a previously logged-in user once the ceiling is reached. If your code assumed the session always exists after login, add a null check. Sessions created before the upgrade (or through connections without the claim) have no `sessionExpiresAt` and behave exactly as before.

## 16. JWT-Secured Authorization Requests (JAR)

[JAR](https://www.rfc-editor.org/rfc/rfc9101.html) (part of Auth0's Highly Regulated Identity feature set) signs all authorization parameters into a JWT and sends them as the `request` parameter, so the `/authorize` redirect carries only `client_id` and `request`. Set `requestObjectSigningKey` to enable it. `requestObjectSigningAlg` is always required, since Web Crypto algorithm names are not valid JWA `alg` values.

```js
app.use(
  auth({
    authorizationParams: {
      response_type: 'code',
    },
    // Sign the authorization request object.
    requestObjectSigningKey: fs.readFileSync('./request-object-key.pem'),
    requestObjectSigningAlg: 'RS256',
    // Optional: set a `kid` in the request object's JWT header.
    // requestObjectSigningKeyId: 'my-key-id',

    // Recommended for FAPI: combine with PAR so the signed request object is
    // POSTed to /oauth/par and only an opaque request_uri is exposed in the URL.
    pushedAuthorizationRequests: true,
  }),
);
```

The request object's `aud` is set to the issuer identifier advertised in the discovery document (which may differ from `issuerBaseURL`, e.g. a trailing slash), as JAR requires. `requestObjectSigningKey` accepts the same key formats as `clientAssertionSigningKey` (PEM string, Buffer, KeyObject, JWK, CryptoKey).

`requestObjectSigningAlg` must be a JWA algorithm name from the following set: `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`, `Ed25519`. Register the corresponding public key with your authorization server so it can verify the signed request object.

Generate a signing key pair that matches your chosen algorithm, for example an RSA key for `RS256`/`PS256`:

```bash
# Private key (used by the app as requestObjectSigningKey)
openssl genrsa -out request-object-key.pem 2048
# Public key (registered with the authorization server)
openssl rsa -in request-object-key.pem -pubout -out request-object-key.pub.pem
```

For an EC algorithm such as `ES256`, generate a P-256 key instead:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out request-object-key.pem
openssl ec -in request-object-key.pem -pubout -out request-object-key.pub.pem
```

Full example at [jar.js](./examples/jar.js), to run it: `npm run start:example -- jar`

## 17. mTLS client authentication

[mTLS](https://www.rfc-editor.org/rfc/rfc8705) (RFC 8705) authenticates your application to the token endpoint with a TLS client certificate instead of a client secret. Enable it with `useMtls: true` (or the `AUTH0_MTLS=true` environment variable). Issued access tokens carry a `cnf.x5t#S256` claim binding them to the certificate.

The certificate is presented at the TLS layer by your `customFetch`, never by the SDK. Node's global `fetch` ignores the `agent` option, so the certificate must be attached via an [undici](https://github.com/nodejs/undici) `Agent` on the request `dispatcher`.

```js
const { Agent, fetch: undiciFetch } = require('undici');

const tlsAgent = new Agent({
  connect: {
    cert: fs.readFileSync('./client.crt'),
    key: fs.readFileSync('./client.key'),
  },
});

app.use(
  auth({
    // Point issuerBaseURL at your custom domain, not the *.auth0.com host.
    issuerBaseURL: 'https://auth.your-domain.com',
    authorizationParams: {
      response_type: 'code',
      audience: 'https://your-api/',
      scope: 'openid profile email offline_access',
    },
    useMtls: true,
    customFetch: (url, options) =>
      undiciFetch(url, { ...options, dispatcher: tlsAgent }),
  }),
);
```

When `useMtls` is set, the SDK routes token, refresh, revocation, userinfo, and PAR requests to the server's `mtls_endpoint_aliases`. mTLS requires:

- A custom domain with self-managed certificates. It does not work on canonical `*.auth0.com` domains (the SDK logs a warning if you try).
- mTLS endpoint aliases enabled on the tenant. If the discovery document does not advertise them, the SDK throws an `MtlsError` with code `mtls_endpoint_aliases_missing`.
- No `clientSecret` or `clientAssertionSigningKey`. Combining either (or an explicit `clientAuthMethod`) with `useMtls` throws an `MtlsError` (`mtls_incompatible_client_auth`), and a missing `customFetch` throws `mtls_requires_custom_fetch`.

`MtlsError` and `MtlsErrorCode` are exported for structured handling:

```js
const { auth, MtlsError, MtlsErrorCode } = require('express-openid-connect');

try {
  app.use(auth({ useMtls: true /* customFetch missing */ }));
} catch (err) {
  if (err.code === MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH) {
    // provide a TLS-aware customFetch
  }
}
```

Full example at [mtls.js](./examples/mtls.js).
