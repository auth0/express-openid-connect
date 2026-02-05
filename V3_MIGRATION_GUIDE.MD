# OIDC V4 to V6 Migration Guide

This release upgrades express-openid-connect to use openid-client v6 internally.
openid-client v6 is a major rewrite that adopts modern Web APIs and removes legacy OAuth flows.

For most applications, configuration stays the same, but some legacy flows and helper methods are no longer supported.

## Summary of Changes

- Requires Node.js 20 or newer
- **SDK is now ESM-only** (ES Modules)
- Uses openid-client v6 functional APIs
- Enforces Authorization Code Flow with PKCE
- Implicit flow is no longer supported
- Token introspection and request helpers are removed
- Uses WebCrypto (CryptoKey) for client authentication
- Stricter OpenID Connect validation

---

## Breaking Changes

### 1. ESM Import Syntax Required

The SDK is now an ES Module (`"type": "module"`). Import syntax must change from CommonJS to ESM.

**This will fail (CommonJS):**

```js
const { auth, requiresAuth } = require('express-openid-connect');
// Error: require() of ES Module not supported
```

**Fix:** Use ESM import syntax:

```js
import { auth, requiresAuth } from 'express-openid-connect';
```

**All available exports:**

```js
import {
  auth,
  requiresAuth,
  claimEquals,
  claimIncludes,
  claimCheck,
  attemptSilentLogin,
} from 'express-openid-connect';
```

**For CommonJS projects:** If you must use CommonJS, use dynamic import:

```js
// CommonJS project (not recommended)
async function setup() {
  const { auth, requiresAuth } = await import('express-openid-connect');
  // use auth, requiresAuth...
}
```

> **Note:** We recommend migrating your project to ESM by adding `"type": "module"` to your `package.json`.

---

### 2. Node.js 20+ Required

openid-client v6 relies on native `fetch`, WebCrypto (`CryptoKey`), and modern ESM support.

**This will fail on Node.js 18 or earlier:**

```js
// package.json
{
  "engines": {
    "node": ">=18.0.0"  // Will fail - Node 18 not supported
  }
}

// Running on Node 18:
// Error: openid-client requires Node.js 20 or newer
```

**Fix:** Update to Node.js 20+

```js
// package.json
{
  "engines": {
    "node": ">=20.0.0"  // Correct
  }
}
```

---

### 3. HTTP Base URLs Require Explicit Opt-in

**This will fail with HTTP URLs:**

```js
const { auth } = require('express-openid-connect');

app.use(
  auth({
    issuerBaseURL: 'https://your-tenant.auth0.com',
    baseURL: 'http://localhost:3000', // HTTP URL
    clientID: 'client-id',
    secret: '',
  }),
);

// Error: "baseURL" must use HTTPS unless allowInsecureRequests is enabled
```

**Fix:** Add `allowInsecureRequests: true` for local development:

```js
import { auth } from 'express-openid-connect';

app.use(
  auth({
    issuerBaseURL: 'https://your-tenant.auth0.com',
    baseURL: 'http://localhost:3000',
    clientID: 'your-client-id',
    secret: 'your-secret',
    allowInsecureRequests: true, // Required for HTTP URLs
  }),
);
```

> **Note:** Never use `allowInsecureRequests: true` in production. Always use HTTPS.

---

### 4. Implicit Flow Removed

The implicit flow (`response_type: 'id_token'`, `response_type: 'token'`, `response_type: 'id_token token'`) is no longer supported.

**Why was implicit flow removed?**

1. **Security vulnerabilities:** Tokens are exposed in the URL fragment, making them susceptible to browser history, referrer headers, and XSS attacks
2. **No refresh tokens:** Implicit flow cannot issue refresh tokens, requiring frequent re-authentication
3. **Industry deprecation:** OAuth 2.0 Security Best Current Practice (RFC 9700) recommends against using implicit flow
4. **PKCE is more secure:** Authorization Code Flow with PKCE provides the same benefits without exposing tokens in URLs

**This will fail:**

```js
const { auth } = require('express-openid-connect');

app.use(
  auth({
    issuerBaseURL: 'https://your-tenant.auth0.com',
    baseURL: 'https://your-app.com',
    clientID: 'your-client-id',
    secret: 'your-secret',
    authorizationParams: {
      response_type: 'id_token', // Implicit flow not supported
      scope: 'openid profile email',
    },
  }),
);

// Error: Implicit flow (response_type: 'id_token') is not supported.
// Use authorization code flow with response_type: 'code'
```

**Also fails with:**

```js
authorizationParams: {
  response_type: 'token', // Not supported
}

authorizationParams: {
  response_type: 'id_token token', // Not supported
}
```

**Fix:** Use Authorization Code Flow with PKCE (default):

```js
import { auth } from 'express-openid-connect';

app.use(
  auth({
    issuerBaseURL: 'https://your-tenant.auth0.com',
    baseURL: 'https://your-app.com',
    clientID: 'client-id',
    secret: '',
    authorizationParams: {
      response_type: 'code', // Authorization code flow (default)
      scope: 'openid profile email',
    },
  }),
);
```

**Or use Hybrid Flow if you need an ID token in the authorization response:**

```js
authorizationParams: {
  response_type: 'code id_token', // Hybrid flow is supported
  scope: 'openid profile email',
}
```

---

### 5. Token Introspection Removed

The `client.introspect()` method is no longer available.

**This will fail:**

```js
app.get('/introspect', async (req, res) => {
  const client = req.oidc.client;

  // introspect() method no longer exists
  const result = await client.introspect(req.oidc.accessToken.access_token);

  res.json(result);
});

// TypeError: client.introspect is not a function
```

**Fix:** Use the standard `fetch` API or an HTTP client to call the introspection endpoint directly:

```js
app.get('/introspect', async (req, res) => {
  const accessToken = req.oidc.accessToken.access_token;

  // Use fetch to call introspection endpoint directly
  const response = await fetch(
    'https://your-tenant.auth0.com/oauth/introspect',
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        token: accessToken,
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
      }),
    },
  );

  const result = await response.json();
  res.json(result);
});
```

---

### 6. Custom Client Helpers Removed

Direct access to low-level client methods that relied on openid-client v4 internals will fail.

**This will fail:**

```js
app.get('/userinfo-custom', async (req, res) => {
  const client = req.oidc.client;

  // requestResource is not available in v6
  const response = await client.requestResource(
    'https://api.example.com/userinfo',
    req.oidc.accessToken.access_token,
  );

  res.json(response);
});

// TypeError: client.requestResource is not a function
```

**Fix:** Use `fetch` with the access token:

```js
app.get('/userinfo-custom', async (req, res) => {
  const accessToken = req.oidc.accessToken.access_token;

  // Use fetch with Bearer token
  const response = await fetch('https://api.example.com/userinfo', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  const data = await response.json();
  res.json(data);
});
```

---

### 7. Client Authentication Methods

The following client authentication methods are supported. The SDK auto-detects the appropriate method based on your configuration:

| Method                | When Used                                    | Configuration                         |
| --------------------- | -------------------------------------------- | ------------------------------------- |
| `private_key_jwt`     | When `clientAssertionSigningKey` is provided | Requires PEM, JWK, or CryptoKey       |
| `client_secret_jwt`   | When explicitly set                          | Requires `clientSecret`               |
| `client_secret_post`  | Default when `clientSecret` is provided      | Client secret in request body         |
| `client_secret_basic` | When explicitly set                          | Client secret in Authorization header |
| `none`                | When no secret or key provided               | Public client with PKCE               |

**Example - Client Secret JWT:**

```js
import { auth } from 'express-openid-connect';

app.use(
  auth({
    issuerBaseURL: 'https://your-tenant.auth0.com',
    baseURL: 'https://your-app.com',
    clientID: 'client-id',
    clientSecret: 'client-secret',
    secret: 'cookie-encryption-secret',
    clientAuthMethod: 'client_secret_jwt', // Explicit method
  }),
);
```

---

### 8. Private Key JWT Authentication

If using `private_key_jwt` client authentication, keys must be provided in a supported format.

**This will fail with invalid key format:**

```js
const { auth } = require('express-openid-connect');

app.use(
  auth({
    issuerBaseURL: 'https://your-tenant.auth0.com',
    baseURL: 'https://your-app.com',
    clientID: 'client-id',
    secret: '',
    clientAuthMethod: 'private_key_jwt',
    clientAssertionSigningKey: 'not-a-valid-key', // Invalid key format
  }),
);

// Error: clientAssertionSigningKey must be a PEM string, JWK object, or CryptoKey
```

**Fix:** Provide a valid PEM, JWK, or CryptoKey:

```js
import { readFileSync } from 'fs';
import { auth } from 'express-openid-connect';

// Option 1: PEM string
const privateKeyPem = readFileSync('./private-key.pem', 'utf8');

app.use(
  auth({
    issuerBaseURL: 'https://your-tenant.auth0.com',
    baseURL: 'https://your-app.com',
    clientID: 'your-client-id',
    secret: '',
    clientAuthMethod: 'private_key_jwt',
    clientAssertionSigningKey: privateKeyPem, // PEM string
  }),
);

// Option 2: JWK object
const privateKeyJwk = {
  kty: 'RSA',
  kid: 'my-key-id',
  // ... other JWK properties
};

app.use(
  auth({
    // ...
    clientAssertionSigningKey: privateKeyJwk, // JWK object
  }),
);
```

---

### 9. Stricter Token Validation

openid-client v6 performs stricter OpenID Connect validation. Tokens that were previously accepted may now fail validation.

**This may fail with non-compliant tokens:**

```js
// If your identity provider returns non-standard tokens:
// - Missing required claims (iss, sub, aud, exp, iat)
// - Invalid signature
// - Expired tokens
// - Audience mismatch

// Error: JWT validation failed: "aud" claim mismatch
// Error: JWT validation failed: token is expired
// Error: JWT validation failed: invalid signature
```

**Fix:** Ensure your identity provider is configured correctly and returns compliant tokens. Check:

1. Token has all required claims (`iss`, `sub`, `aud`, `exp`, `iat`)
2. `aud` claim matches your `clientID`
3. `iss` claim matches your `issuerBaseURL`
4. Token signature is valid against the provider's JWKS
5. Token is not expired

---

## Unchanged Behavior

The following behaviors remain the same:

- **Logout:** Auth0 tenants use `/v2/logout`, other providers use `end_session_endpoint`
- **Session management:** Cookie-based sessions work identically
- **Custom routes:** `/login`, `/logout`, `/callback` routes remain the same
- **Middleware:** `requiresAuth()`, `claimEquals()`, `claimIncludes()` work identically
- **Access tokens:** `req.oidc.accessToken` structure is unchanged
- **User info:** `req.oidc.user` contains the same claims
- **Back-Channel Logout:** Fully supported with the same configuration API
- **Pushed Authorization Requests (PAR):** Still supported via `pushedAuthorizationRequests: true`
- **Discovery Cache:** `discoveryCacheMaxAge` option still supported (default: 10 minutes)
- **HTTP Options:** `httpTimeout`, `httpUserAgent`, and `httpAgent` options still supported
