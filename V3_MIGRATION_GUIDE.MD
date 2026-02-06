# OIDC V4 to V6 Migration Guide

This release upgrades express-openid-connect to use openid-client v6 internally.
openid-client v6 is a major rewrite that adopts modern Web APIs and removes legacy OAuth flows.

For most applications, configuration stays the same, but some legacy flows and helper methods are no longer supported.

## Summary of Changes

- Requires Node.js 20 or newer
- Uses openid-client v6 functional APIs
- Uses WebCrypto (CryptoKey) for client authentication
- Stricter OpenID Connect validation

---

## Breaking Changes

> **Why are these breaking changes required?**
>
> These breaking changes stem from openid-client v6, our underlying OIDC library. openid-client v6 is a complete rewrite that adopts modern Web APIs (native fetch, WebCrypto) and enforces stricter security practices. These changes cannot be abstracted away at the SDK level because they are fundamental to how the library operates.

### 1. Node.js 20+ Required

**Why this is required:** openid-client v6 uses native `fetch()` and `crypto.subtle` (WebCrypto), which are only fully stable in Node.js 20+. This is a hard dependency of openid-client v6 that we cannot work around.

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

### 2. HTTP Base URLs Require Explicit Opt-in

**Why this is required:** openid-client v6 enforces HTTPS by default as a security measure. The `allowInsecureRequests()` function must be explicitly called to permit HTTP connections. This is a security improvement mandated by openid-client v6 and aligns with OAuth 2.0 security best practices.

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

### 3. Private Key JWT Authentication

**Why this is required:** openid-client v6 uses WebCrypto (`CryptoKey`) instead of Node.js `crypto` module for cryptographic operations. The SDK automatically converts PEM strings and JWK objects to CryptoKey, but the input must be a valid key format. This is a fundamental change in how openid-client v6 handles cryptography.

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

### 4. Stricter Token Validation

**Why this is required:** openid-client v6 (via oauth4webapi) performs stricter OIDC-compliant token validation internally. This validation happens at the library level and cannot be disabled or relaxed by the SDK. This is a security improvement that ensures tokens conform to the OpenID Connect specification.

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
- **Token introspection:** `client.introspect()` is still supported
- **Resource requests:** `client.requestResource()` is still supported
- **Back-Channel Logout:** Fully supported with the same configuration API
- **Pushed Authorization Requests (PAR):** Still supported via `pushedAuthorizationRequests: true`
- **Discovery Cache:** `discoveryCacheMaxAge` option still supported (default: 10 minutes)
- **HTTP Options:** `httpTimeout`, `httpUserAgent`, and `httpAgent` options still supported
- **Implicit Flow:** `response_type: 'id_token'` is still supported for scenarios where only identity verification is needed

---

## Reference

### Client Authentication Methods

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
