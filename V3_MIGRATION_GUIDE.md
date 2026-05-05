# V3 Migration Guide

`v3.x` upgrades `openid-client` (v4 → v6) and `jose` (v2 → v6) to their latest major versions, bringing improved security, performance, and standards compliance.

**Node.js Version:** Now requires `^20.19.0 || ^22.12.0 || >= 23.0.0` (previously Node.js 14+)  
**Module Support:** Works with BOTH CommonJS and ESM apps

---

## Breaking Changes Summary

| Change                                                                                          | Who is affected                                                                                 | Action required                                          |
| ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| [Node.js version](#nodejs-version-requirement)                                                  | Everyone                                                                                        | Upgrade Node.js                                          |
| [`httpAgent` config](#httpagent-config)                                                         | Apps using `httpAgent` for proxies                                                              | Replace with `customFetch`                               |
| [`clientAssertionSigningAlg` config now required](#clientassertionsigningalg-now-required)      | Apps using `clientAssertionSigningKey` with a PEM, Buffer, or KeyObject                         | Add `clientAssertionSigningAlg` explicitly               |
| [`ES256K` / `EdDSA` removed](#es256k-and-eddsa-removed)                                         | Apps using `clientAssertionSigningAlg: 'ES256K'` or `'EdDSA'`                                   | Rename `EdDSA` to `Ed25519`, no replacement for `ES256K` |
| [`afterCallback` behavior change](#aftercallback-behavior-change)                               | Apps reading `req.oidc` inside `afterCallback` to inspect the previous session                  | Read previous state before the callback flow starts      |
| [Session cookie dropped on streaming responses](#session-cookie-dropped-on-streaming-responses) | Apps that call `res.write()` or `res.flushHeaders()` before `res.end()` on session-aware routes | Avoid pre-sending headers on session-aware routes        |
| [`clientAssertionSigningKey` type](#clientassertionsigningkey-type-changed)                     | TypeScript apps with explicit type annotations on `clientAssertionSigningKey`                   | Update imported types                                    |

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

```js
// If you need the previous user, capture it in middleware before the callback route.
app.use((req, res, next) => {
  res.locals.previousUser = req.oidc.user;
  next();
});

app.use(
  auth({
    async afterCallback(req, res, session) {
      // req.oidc.user is now the INCOMING user (new tokens)
      // use res.locals.previousUser for the prior state
      return session;
    },
  }),
);
```

The `session` argument passed to `afterCallback` is unchanged — it still contains the new tokens from the current authentication.

---

### Session Cookie Dropped on Streaming Responses

v2 used `on-headers`, which hooks into `res.writeHead` and injects the `Set-Cookie` header right before headers are flushed — regardless of how the response is written. v3 uses a `res.end` wrapper instead. If `res.write()`, `res.flushHeaders()`, or `res.writeHead()` is called before `res.end()`, headers are already sent by the time the cookie write runs and the session cookie is **silently dropped**.

Standard OIDC flows (login, callback, logout) are not affected — they use `res.redirect()` and `res.send()`, which flush headers only at `res.end()`.

**Affected pattern:**

```js
app.get('/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  res.write('first chunk'); // headers sent here — session cookie will be dropped
  req.session.visited = true;
  res.end('done');
});
```

**Migration:** for session-aware routes that stream a response, complete any session mutations before calling `res.write()` or `res.flushHeaders()`.

---

### `clientAssertionSigningKey` Type Changed

The accepted TypeScript type for `clientAssertionSigningKey` has changed from jose v2 types to jose v6 / Web Crypto types. Runtime behavior is unchanged — all previously supported key forms (PEM string, Buffer, KeyObject, JWK) still work.

| v2 type                                              | v3 type                                                                             |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `KeyInput \| KeyObject \| JSONWebKey` (from jose v2) | `KeyObject \| CryptoKey \| JWK \| string \| Uint8Array` (from jose v6 / Web Crypto) |

If you have explicit TypeScript annotations importing `KeyInput` or `JSONWebKey` from `jose`, update them to use `JWK` and `CryptoKey` from `jose` v6, or `string` for PEM keys.

---

## What Has Not Changed

### Configuration

All configuration options work exactly as before (except `httpAgent`, which is replaced by `customFetch`).

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
