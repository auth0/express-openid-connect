# V3 Migration Guide

`v3.x` upgrades `openid-client` (v4 → v6) and `jose` (v2 → v6) to their latest major versions, bringing improved security, performance, and standards compliance.

**Node.js Version:** Now requires `^20.19.0 || ^22.12.0 || >= 23.0.0` (previously Node.js 14+)  
**Module Support:** Works with BOTH CommonJS and ESM apps

---

## Breaking Changes Summary

| Change                                                                                                                     | Who is affected                                                                                                                 | Action required                                          |
| -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| [Node.js version](#nodejs-version-requirement)                                                                             | Everyone                                                                                                                        | Upgrade Node.js                                          |
| [`httpAgent` config](#httpagent-config)                                                                                    | Apps using `httpAgent` for proxies                                                                                              | Replace with `customFetch`                               |
| [`clientAssertionSigningAlg` config now required](#clientassertionsigningalg-now-required)                                 | Apps using `clientAssertionSigningKey` with a PEM, Buffer, or KeyObject                                                         | Add `clientAssertionSigningAlg` explicitly               |
| [`ES256K` / `EdDSA` removed](#es256k-and-eddsa-removed)                                                                    | Apps using `clientAssertionSigningAlg: 'ES256K'` or `'EdDSA'`                                                                   | Rename `EdDSA` to `Ed25519`, no replacement for `ES256K` |
| [`afterCallback` behavior change](#aftercallback-behavior-change)                                                          | Apps reading `req.oidc` inside `afterCallback` to inspect the previous session                                                  | Read previous state before the callback flow starts      |
| [Session cookie dropped when headers sent before `res.end()`](#session-cookie-dropped-when-headers-are-sent-before-resend) | Apps that flush headers before `res.end()` (e.g. `res.write()`, `res.flushHeaders()`, `res.sendFile()`) on session-aware routes | Avoid flushing headers early on session-aware routes     |
| [`clientAssertionSigningKey` type](#clientassertionsigningkey-type-changed)                                                | TypeScript apps with explicit type annotations on `clientAssertionSigningKey`                                                   | Update imported types                                    |

---

## Breaking Changes

### Node.js Version Requirement

v3 depends on `openid-client` v6 and `jose` v6, which are ESM-only packages. Node.js added `require(ESM)` support in:

- **v20.19.0** (backported to the v20.x LTS line)
- **v22.12.0** (backported to the v22.x LTS line)
- **v23.0.0+** (included by default)

| Version | Minimum Node.js                         |
| ------- | --------------------------------------- |
| v2.x    | Node.js 14+                             |
| v3.x    | `^20.19.0 \|\| ^22.12.0 \|\| >= 23.0.0` |

There is no workaround — you must upgrade Node.js.

---

### `httpAgent` Config

The `httpAgent` option was specific to `got`, the HTTP client used in v2. v3 uses the native `fetch` API instead, and `httpAgent` is no longer supported. Passing it will throw at startup:

```
TypeError: "httpAgent" is not allowed
```

The replacement is `customFetch`, a new config option that accepts a `fetch`-compatible function. The SDK wraps it to inject the required `User-Agent` and telemetry headers before making requests.

**Before (v2):**

```js
const { ProxyAgent } = require('proxy-agent');

app.use(
  auth({
    httpAgent: new ProxyAgent('http://proxy.example.com:8080'),
  }),
);
```

**After (v3):**

```js
const { ProxyAgent, fetch: undiciFetch } = require('undici');

const dispatcher = new ProxyAgent('http://proxy.example.com:8080');

app.use(
  auth({
    customFetch: (url, options) => undiciFetch(url, { ...options, dispatcher }),
  }),
);
```

See [EXAMPLES.md — Use a proxy for OIDC requests](./EXAMPLES.md#13-use-a-proxy-for-oidc-requests) for the full example.

---

### `clientAssertionSigningAlg` Config Now Required

Previously, if `clientAssertionSigningAlg` was omitted, the SDK silently defaulted to `RS256`. This default has been removed. If your `clientAssertionSigningKey` is a PEM string, Buffer, KeyObject, or a JWK without an `alg` property, you must now specify the algorithm explicitly. Omitting it will throw at startup:

```
TypeError: "clientAssertionSigningAlg" is required when "clientAssertionSigningKey" is a PEM, Buffer, KeyObject, or a JWK without an "alg" property
```

**Before (v2):**

```js
app.use(
  auth({
    clientAssertionSigningKey: '-----BEGIN PRIVATE KEY-----\n...',
    // clientAssertionSigningAlg was optional, defaulted to RS256
  }),
);
```

**After (v3):**

```js
app.use(
  auth({
    clientAssertionSigningKey: '-----BEGIN PRIVATE KEY-----\n...',
    clientAssertionSigningAlg: 'RS256', // now required for PEM keys
  }),
);
```

**Not affected:** `CryptoKey` instances and JWK objects that include an `alg` property carry the algorithm themselves — `clientAssertionSigningAlg` remains optional for those.

---

### `ES256K` and `EdDSA` Removed

These two values are no longer accepted for `clientAssertionSigningAlg`. Passing either will throw a validation error at startup.

| v2 value | v3 replacement                                    |
| -------- | ------------------------------------------------- |
| `EdDSA`  | `Ed25519`                                         |
| `ES256K` | No replacement, not supported by openid-client v6 |

**Before (v2):**

```js
app.use(
  auth({
    clientAssertionSigningAlg: 'EdDSA',
  }),
);
```

**After (v3):**

```js
app.use(
  auth({
    clientAssertionSigningAlg: 'Ed25519',
  }),
);
```

---

### `afterCallback` Behavior Change

In v2, `req.oidc` inside `afterCallback` reflected the **previous** session state (the user who was logged in before this authentication completed). In v3, `req.oidc` reflects the **incoming** user's new tokens.

This only affects you if your `afterCallback` reads `req.oidc.user`, `req.oidc.isAuthenticated()`, `req.oidc.accessToken`, or `req.oidc.idTokenClaims` to inspect the prior session.

**Before (v2):**

```js
app.use(
  auth({
    async afterCallback(req, res, session) {
      // req.oidc.user was the PREVIOUS user (before this login)
      const previousUser = req.oidc.user;
      return session;
    },
  }),
);
```

**After (v3):**

If you need the previous session state, disable the built-in callback route and handle it yourself. This gives you a window after `req.oidc` is attached (the auth middleware always runs its session setup) but before the callback processing replaces the session:

```js
app.use(
  auth({
    routes: { callback: false }, // disable the built-in /callback route
    async afterCallback(req, res, session) {
      // req.oidc.user is now the INCOMING user (new tokens)
      // use res.locals.previousUser for the prior state
      const previousUser = res.locals.previousUser;
      return session;
    },
  }),
);

// req.oidc is available here — auth() has already run its session setup for this request
app.get('/callback', (req, res) => {
  res.locals.previousUser = req.oidc.user; // capture the previous session before it is replaced
  res.oidc.callback(); // proceed with OIDC callback processing
});
```

The `session` argument passed to `afterCallback` is unchanged — it still contains the new tokens from the current authentication.

---

### Session Cookie Dropped When Headers Are Sent Before `res.end()`

v2 used `on-headers`, which hooked into `res.writeHead` and injected the `Set-Cookie` header right before headers were flushed, regardless of how the response was written. v3 uses a `res.end` wrapper instead, so the session cookie is written only at `res.end()`. If headers are flushed earlier, `res.headersSent` is already `true` by the time the cookie write runs and the session cookie is **silently dropped** — there is no workaround within the same response.

Standard OIDC flows (login, callback, logout) are not affected — they use `res.redirect()` and `res.send()`, which flush headers only at `res.end()`.

**Affected patterns:**

Any response that sends headers before `res.end()`:

```js
// res.write() — flushes headers on the first call
app.get('/stream', (req, res) => {
  res.write('first chunk'); // headers sent here — session cookie will be dropped
  res.end('done');
});

// res.flushHeaders() — explicitly flushes headers early
app.get('/sse', (req, res) => {
  res.flushHeaders(); // headers sent here — session cookie will be dropped
  res.end();
});

// res.sendFile() / res.download() — pipe a stream and flush headers early
app.get('/file', (req, res) => {
  res.sendFile('/path/to/file'); // headers sent here — session cookie will be dropped
});
```

**Migration:** avoid these patterns on routes that need to set or update a session cookie. Since there is no way to inject `Set-Cookie` after headers are already sent, routes that flush headers early are fundamentally incompatible with session cookie writes in v3.

---

### `clientAssertionSigningKey` Type Changed

The TypeScript type for `clientAssertionSigningKey` has been updated to reflect the jose v2 → v6 rename and the addition of Web Crypto `CryptoKey` support. Runtime behavior is unchanged — all previously supported key forms still work.

| v2 type                                              | v3 type                                                                |
| ---------------------------------------------------- | ---------------------------------------------------------------------- |
| `KeyInput \| KeyObject \| JSONWebKey` (from jose v2) | `KeyObject \| CryptoKey \| JWK \| string \| Buffer` (jose v6 / crypto) |

- `KeyObject` is unchanged
- `KeyInput` (jose v2) is replaced by the explicit `string` (PEM) and `Buffer` types it represented
- `JSONWebKey` (jose v2) is renamed to `JWK` in jose v6
- `CryptoKey` is new — Web Crypto key support added in v3

If you have explicit TypeScript annotations importing `KeyInput` or `JSONWebKey` from `jose`, replace them with `string`/`Buffer` and `JWK` respectively.

---

## What Has Not Changed

### Configuration

All configuration options work exactly as before (except `httpAgent`, which is replaced by `customFetch`).

> **Note for local development:** If your `issuerBaseURL` uses `http://` (e.g. a local OIDC provider), the SDK automatically enables insecure requests for that issuer. No additional configuration is needed.

```js
app.use(
  auth({
    authRequired: false,
    auth0Logout: true,
    baseURL: 'https://example.com',
    clientID: 'YOUR_CLIENT_ID',
    issuerBaseURL: 'https://YOUR_DOMAIN',
    secret: 'LONG_RANDOM_STRING',
    idpLogout: true,
    idTokenSigningAlg: 'RS256',
    clientAuthMethod: 'client_secret_post',
    pushedAuthorizationRequests: true,
    // ... all other options
  }),
);
```

### Middleware

All middleware functions work identically.

```js
const { auth, requiresAuth } = require('express-openid-connect');

app.use(auth(config));
app.get('/admin', requiresAuth(), (req, res) => {
  res.send('Admin page');
});
```

### Request Context (`req.oidc`)

The entire `req.oidc` API remains unchanged.

```js
app.get('/profile', async (req, res) => {
  const user = req.oidc.user;
  const claims = req.oidc.idTokenClaims;
  const isAuthenticated = req.oidc.isAuthenticated();
  const idToken = req.oidc.idToken;
  const accessToken = req.oidc.accessToken;
  const refreshToken = req.oidc.refreshToken;
  const userInfo = await req.oidc.fetchUserInfo();

  res.oidc.login({});
  res.oidc.logout({});
});
```

### Routes

Custom route configuration remains unchanged.

```js
app.use(
  auth({
    routes: {
      login: '/custom/login',
      logout: '/custom/logout',
      callback: '/custom/callback',
      postLogoutRedirect: '/custom/post-logout',
    },
  }),
);
```

### Session Handling

Session configuration, custom stores, and lifecycle hooks all work the same.

```js
app.use(
  auth({
    session: {
      rolling: true,
      rollingDuration: 86400,
      absoluteDuration: 86400 * 7,
      store: customStore,
    },
  }),
);
```

### Authentication Methods

All client authentication methods continue to work.

```js
app.use(auth({ clientAuthMethod: 'client_secret_basic' }));
app.use(auth({ clientAuthMethod: 'client_secret_post' }));
app.use(auth({ clientAuthMethod: 'client_secret_jwt' }));
app.use(auth({ clientAuthMethod: 'private_key_jwt' }));
app.use(auth({ clientAuthMethod: 'none' }));
```
