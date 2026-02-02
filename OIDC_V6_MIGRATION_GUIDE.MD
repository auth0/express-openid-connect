# OIDC V4 to V6 migration guide

This release upgrades express-openid-connect to use openid-client v6 internally.
openid-client v6 is a major rewrite that adopts modern Web APIs and removes legacy OAuth flows.

For most applications, configuration stays the same, but some legacy flows and helper methods are no longer supported.

## Summary of changes

- Requires Node.js 20 or newer

- Uses openid-client v6 functional APIs

- Enforces Authorization Code Flow with PKCE

- Implicit flow is no longer supported

- Token introspection and request helpers are removed

- Uses WebCrypto (CryptoKey) for client authentication

- Stricter OpenID Connect validation

### Configuration

## Required configuration changes

# Before

```js
app.use(
  auth({
    issuerBaseURL: 'https://your-tenant.auth0.com',
    baseURL: 'http://localhost:3000', // HTTP for dev
    clientID: 'client-id',
    secret: '',
  }),
);
```

# After

```js
app.use(
  auth({
    issuerBaseURL: 'https://your-tenant.auth0.com',
    baseURL: 'http://localhost:3000',
    clientID: 'client-id',
    secret: '',
    allowInsecureRequests: true, // Only needed for HTTP
    // response_type defaults to 'code' - authorization code flow with PKCE
  }),
);
```

### Node.js requirement

This version requires Node.js 20+ .

openid-client v6 relies on: - Native fetch/request - Webcrypto (cryptoKey) - Modern ESM support
Older Node.js versions are not supported.

### Authorization flow changes (Breaking)

## Implicit Flow removed

The implicit flow is no longer supported.

This includes following `response_type` values;

```js
    id_token
    token
    id_token token
```

If the application relied on recieving tokens directly in the authorization redirect, it will fail.
Attemplting to use implicit flow will result in runtime error during callback phase.

### Required flow: Authorization code + PKCE

All application must use Authorization code with PKCE:

```js

authorizationParams: {
  response_type: 'code',
  scope: 'openid profile email'
}

```

## Hybrid flow support

Hybrid flow is supported

```js
response_type: 'code id_token';
```

### Client authentication changes

Client authentication is handled using WebCrypto keys and oidc v6 authentication helpers.

Supported methods:

- private_key_jwt
- client_secret_jwt
- client_secret_basic
- client_secret_post
- none (public clients)

## Private key KWT

If using private_jey_jwt, keys must be provided as:

- PEM
- JWK
- cryptoKey
  PEM and JWK formats are automatically converted to cryptoKey internally.

### Removed helper methods

THe following client helper methods are no longer supported in prod.

- client.introspect() --- Not supported
  -Previously used for token introspection
- Now throws an error at runtime
- Exist only as test shim

## use instead:

- fetch
- axios
- standard HTTP client

## Token validation changes

oidc v6 performs stricter OpenID connect validation:

- ID tokens are validated against issuer metadata
- JWKS signature verification is enforced
- Invalid or non-compliant tokens now fail

## logout behaviour

Logout behaviour is unchanged:

- Auth0 tenants use /v2/logout
- Other providers use end_session_endpoint if available
- An error is thrown if the issuer does not support logout

## HTTP

- Custom HTTP headers, agents and timeouts are still supported
- HTTP issuer require explicit opt-in via allowInsecure Requests
