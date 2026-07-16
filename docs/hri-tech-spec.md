# [SDK-4761] HRI Feature Support in express-openid-connect

---

## Goals

- Add JAR (JWT-Secured Authorization Requests) support so authorization parameters can be signed and tamper-proofed before reaching the IdP
- Add mTLS client authentication so applications can authenticate to Auth0 using mutual TLS instead of a shared secret
- Add JWE access token decryption so applications receiving encrypted access tokens can transparently decrypt them before use

### Non goals

- RAR (Rich Authorization Requests) - `authorization_details` already passes through `authorizationParams`; no first-class support planned in this phase
- mTLS Token Binding (`cnf` claim validation) - resource-server concern, not called out in Phase 2
- SPA SDKs - HRI Phase 2 targets confidential clients only

### Current state

| Feature | Status |
|---|---|
| PAR (Pushed Authorization Requests) | Shipped - `pushedAuthorizationRequests: true` |
| Private Key JWT client auth | Shipped - `clientAuthMethod: 'private_key_jwt'` |
| JAR | Missing |
| mTLS client auth | Missing |
| JWE access token decryption | Missing |

---

## Functional Requirements

### JAR

- When `requestObjectSigningKey` is configured, the SDK must sign all authorization parameters as a JWT and send it as the `request` parameter
- The `request` JWT payload must include all authorization params plus `iss` (set to `clientID`) and `aud` (set to `issuerBaseURL`)
- When JAR is active, the `/authorize` redirect must only carry `client_id` and `request` - all other params move into the JWT
- JAR must compose with PAR: when both are enabled, the signed `request` JWT is POSTed to `/oauth/par`
- `requestObjectSigningKey` must accept the same key formats as `clientAssertionSigningKey`: CryptoKey, KeyObject, JWK, PEM string, Buffer
- `requestObjectSigningAlg` is always required - there is no self-description fallback from the key (Web Crypto algorithm names are not JWA names and cannot be used in JWT headers directly)
- An optional `requestObjectSigningKeyId` sets the `kid` header in the signed JWT; it is never auto-read from the key, consistent with `clientAssertionSigningKey` behavior

### mTLS client authentication

- `clientAuthMethod` must accept `tls_client_auth` (CA-signed) and `self_signed_tls_client_auth` (self-signed) as valid values
- Both variants map to `client.TlsClientAuth()` from openid-client v6, which is the only mTLS auth method the library exposes
- When either mTLS method is set, `clientSecret` and `clientAssertionSigningKey` must not be required
- Both mTLS methods must be valid for code flow clients and when `pushedAuthorizationRequests` is true
- Certificate presentation is the developer's responsibility via `customFetch` - the SDK does not manage certificates

### JWE access token decryption

- When `accessTokenDecryptionKey` is configured, the SDK must decrypt the access token received at the callback before writing it to the session
- Decryption happens before `afterCallback` runs, so hooks always receive a usable plaintext JWT. This is the correct behavior: `afterCallback` is designed to inspect and modify token data, which requires the token to be readable. Developers who were previously doing their own decryption inside `afterCallback` should remove that logic and use `accessTokenDecryptionKey` instead.
- After decryption, the token stored in the session and exposed via `req.oidc.accessToken` is a standard plaintext JWT - no change to consuming code
- `accessTokenDecryptionKey` must accept the same key formats as other key config fields
- `accessTokenDecryptionAlg` must default to `RSA-OAEP-256` (Auth0's default key-wrapping algorithm for JWE)
- If decryption fails, the error must propagate through the normal `next(err)` path and not silently store an unusable token

---

## Non-functional Requirements

- **No breaking changes**: all three features are opt-in via new config fields; existing config remains valid
- **Consistent key handling**: new key config fields reuse the existing `importPrivateKey()` utility in `lib/client.js`; no new key-import logic elsewhere. `decryptAccessToken` is co-located in `lib/client.js` so it can call `importPrivateKey` directly without requiring it to be exported
- **Config validation at startup**: invalid or missing key material must throw a `TypeError` at `auth()` initialization time via Joi, not at request time
- **Shared algorithm list**: `requestObjectSigningAlg` and `clientAssertionSigningAlg` share the same valid algorithm set; extract as a named constant in `config.js` so future additions only need one change
- **JAR + PAR warning**: if `requestObjectSigningKey` is set but `pushedAuthorizationRequests` is `false`, emit a `console.warn` in the `get()` function body in `config.js` after Joi validation completes. `Joi.any().rule({ warn: true })` cannot be used here because it only converts existing validation errors - `Joi.any()` has no constraint to fail, so the warning would silently never fire.
- **mTLS + canonical domain warning**: same approach - a `console.warn` in `get()` after Joi validation, checking `clientAuthMethod` and `issuerBaseURL` directly. The Joi `.when()` approach for this case is also broken: when the first argument to `.when()` is a schema rather than a reference, Joi tests the entire parent object against it, not the current field value, so the condition never evaluates correctly.
- **JWE requires code flow**: if `accessTokenDecryptionKey` is set, `authorizationParams.response_type` must include `code`; implicit flow does not produce access tokens from the token endpoint
- **Test coverage**: each feature needs unit tests in `test/` (mocking `openid-client` at the `lib/client.js` boundary), type tests in `index.test-d.ts` using `tsd` (file already exists at repo root), and an end-to-end test for the PAR + JAR combined flow

---

## Implementation

### Feature 1: JAR

#### `lib/client.js`

Add `buildRequestObject(authParams, config)` and export it. Reuses the existing `importPrivateKey()`:

```js
const crypto = require('crypto');
const { SignJWT } = require('jose');

async function buildRequestObject(authParams, config) {
  const key = await importPrivateKey(
    config.requestObjectSigningKey,
    config.requestObjectSigningAlg,
  );
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    ...authParams,
    client_id: config.clientID,  // required by PAR: must match the authenticated client_id
    iss: config.clientID,
    aud: config.issuerBaseURL,
    jti: crypto.randomBytes(16).toString('hex'),  // replay detection
    iat: now,
    nbf: now,
    exp: now + 60,  // short-lived: request objects are single-use
  };
  return new SignJWT(payload)
    .setProtectedHeader({
      alg: config.requestObjectSigningAlg,
      ...(config.requestObjectSigningKeyId && { kid: config.requestObjectSigningKeyId }),
    })
    .sign(key);
}

exports.buildRequestObject = buildRequestObject;
```

Note: `requestObjectSigningAlg` is always required (see functional requirements), so there is no fallback to `key.algorithm.name`. Web Crypto algorithm names (e.g. `RSASSA-PKCS1-v1_5`) are not valid JWA algorithm names for JWT headers.

#### `lib/config.js`

Extract a shared algorithm constant at the top of the schema (above `paramsSchema`):

```js
const ASYMMETRIC_SIGNING_ALGS = [
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'Ed25519',
];
```

Replace the existing `clientAssertionSigningAlg` valid list with `...ASYMMETRIC_SIGNING_ALGS`, then add the new JAR fields as a single definition each:

```js
requestObjectSigningKey: Joi.any().optional(),

requestObjectSigningAlg: Joi.string()
  .valid(...ASYMMETRIC_SIGNING_ALGS)
  .when('requestObjectSigningKey', {
    is: Joi.exist(),
    then: Joi.string().required().messages({
      'any.required': '"requestObjectSigningAlg" is required when "requestObjectSigningKey" is set',
    }),
    otherwise: Joi.string().optional(),
  }),

requestObjectSigningKeyId: Joi.string().optional(),
```

The JAR+PAR warning cannot use `.rule({ warn: true })` here - `Joi.any()` has no constraint to fail, so `.rule()` would silently never fire. The warning is emitted in `get()` instead (see below).

#### `lib/context.js` - `ResponseContext.login()`

Import `buildRequestObject` at the top alongside the existing `client` imports. Insert the signing step after `authParams` is fully assembled and before the PAR/authorize branch (around line 557):

```js
if (config.requestObjectSigningKey) {
  const requestJwt = await buildRequestObject(authParams, config);
  authParams = {
    client_id: config.clientID,
    request: requestJwt,
  };
}

if (config.pushedAuthorizationRequests) {
  authorizationUrl = await oidcClient.buildAuthorizationUrlWithPAR(
    configuration, authParams,
  );
} else {
  authorizationUrl = oidcClient.buildAuthorizationUrl(configuration, authParams);
}
```

#### `index.d.ts`

Mirror the `clientAssertionSigningKey` type exactly, using `JoseCryptoKey` (already imported as an alias from `jose`):

```ts
requestObjectSigningKey?: KeyObject | JoseCryptoKey | JWK | string | Buffer;
requestObjectSigningAlg?: 'RS256' | 'RS384' | 'RS512' | 'PS256' | 'PS384' | 'PS512'
  | 'ES256' | 'ES384' | 'ES512' | 'Ed25519';
requestObjectSigningKeyId?: string;
```

#### Example

```js
app.use(auth({
  pushedAuthorizationRequests: true,
  requestObjectSigningKey: fs.readFileSync('./private.pem'),
  requestObjectSigningAlg: 'RS256',
  requestObjectSigningKeyId: 'my-key-id',  // optional
}));
```

---

### Feature 2: mTLS client authentication

#### `lib/client.js` - `getClientAuth()`

openid-client v6 exposes a single `TlsClientAuth()` function for mTLS. Both `tls_client_auth` and `self_signed_tls_client_auth` map to it - the distinction between CA-signed and self-signed is enforced by Auth0 at the network layer, not by the client library:

```js
case 'tls_client_auth':
case 'self_signed_tls_client_auth':
  return client.TlsClientAuth();
```

No key material is passed - certificate handling is entirely in the developer's `customFetch`.

#### `lib/config.js`

Extend `clientAuthMethod` valid values:

```js
clientAuthMethod: Joi.string()
  .valid(
    'client_secret_basic',
    'client_secret_post',
    'client_secret_jwt',
    'private_key_jwt',
    'tls_client_auth',              // new
    'self_signed_tls_client_auth',  // new
    'none',
  )
```

The existing `clientSecret` requirement uses `.includes('client_secret')` to detect which methods need a secret - mTLS method names don't match, so they correctly skip the requirement with no changes needed.

The existing code flow `Joi.string().invalid('none')` restriction is already correct for mTLS - `tls_client_auth` and `self_signed_tls_client_auth` are not `'none'`, so they pass without changes.

The mTLS canonical domain warning cannot be expressed correctly in Joi: when `.when()`'s first argument is a schema (rather than a `Joi.ref`), Joi tests the entire parent object against it rather than the current field's value, so the condition would never evaluate correctly. The warning is emitted in `get()` instead (see below).

#### `lib/config.js` - `get()` function body

Both the JAR+PAR and mTLS+canonical-domain warnings live here, immediately after the existing `if (warning) console.warn(warning.message)` block. This is the correct pattern when a warning condition cannot be expressed as a Joi constraint failure:

```js
const { value, error, warning } = paramsSchema.validate(config);
if (error) throw new TypeError(error.details[0].message);
if (warning) console.warn(warning.message);

if (value.requestObjectSigningKey && !value.pushedAuthorizationRequests) {
  console.warn(
    'Using JAR without PAR is permitted but not recommended for FAPI compliance. ' +
    'Consider enabling pushedAuthorizationRequests.'
  );
}

const mtlsMethods = ['tls_client_auth', 'self_signed_tls_client_auth'];
if (
  mtlsMethods.includes(value.clientAuthMethod) &&
  /\.auth0\.com$/.test(new URL(value.issuerBaseURL).hostname)
) {
  console.warn(
    'mTLS client authentication requires a custom Auth0 domain. ' +
    'It will not work with canonical *.auth0.com domains.'
  );
}

return value;
```

#### `index.d.ts`

Extend `clientAuthMethod`:

```ts
clientAuthMethod?: 'client_secret_basic' | 'client_secret_post' | 'client_secret_jwt'
  | 'private_key_jwt' | 'tls_client_auth' | 'self_signed_tls_client_auth' | 'none';
```

#### Example

```js
const cert = fs.readFileSync('./client.crt');
const key  = fs.readFileSync('./client.key');

app.use(auth({
  clientID: '...',
  clientAuthMethod: 'tls_client_auth',  // or 'self_signed_tls_client_auth'
  // no clientSecret needed
  customFetch: (url, options) =>
    fetch(url, { ...options, dispatcher: new undici.Agent({ connect: { cert, key } }) }),
}));
```

> mTLS requires an Auth0 custom domain. It does not work with canonical `*.auth0.com` domains.

---

### Feature 3: JWE access token decryption

#### `lib/client.js`

Co-locate `decryptAccessToken` in `lib/client.js` alongside `buildRequestObject` so it can call the unexported `importPrivateKey` directly. Export it:

```js
const { compactDecrypt } = require('jose');

async function decryptAccessToken(token, keyData, alg) {
  const key = await importPrivateKey(keyData, alg);
  const { plaintext } = await compactDecrypt(token, key);
  return Buffer.from(plaintext).toString('utf8');
}

exports.decryptAccessToken = decryptAccessToken;
```

`jose`'s `compactDecrypt` unwraps the outer JWE envelope and returns the inner signed JWT as plaintext.

#### `lib/config.js`

```js
accessTokenDecryptionKey: Joi.any().optional(),

accessTokenDecryptionAlg: Joi.string().optional().default('RSA-OAEP-256'),
```

Add cross-field validation requiring code flow when decryption is configured:

```js
accessTokenDecryptionKey: Joi.any()
  .optional()
  .when(Joi.ref('authorizationParams.response_type', {
    adjust: (v) => v && !v.includes('code'),
  }), {
    is: true,
    then: Joi.any().forbidden().messages({
      'any.unknown': '"accessTokenDecryptionKey" requires a code flow. Set authorizationParams.response_type to "code" or "code id_token".',
    }),
  }),
```

#### `lib/context.js` - `ResponseContext.callback()`

Import `decryptAccessToken` from `./client`. After the session object is built from the token response (around line 829) and before it is written to `req[config.session.name]`, add the decryption step:

```js
if (config.accessTokenDecryptionKey && session.access_token) {
  session.access_token = await decryptAccessToken(
    session.access_token,
    config.accessTokenDecryptionKey,
    config.accessTokenDecryptionAlg,
  );
}
```

This placement is intentional: `afterCallback` fires after this block, so hooks always receive the decrypted plaintext token. Developers who previously decrypted inside `afterCallback` should migrate to `accessTokenDecryptionKey`.

#### `index.d.ts`

```ts
accessTokenDecryptionKey?: KeyObject | JoseCryptoKey | JWK | string | Buffer;
accessTokenDecryptionAlg?: string;
```

#### Example

```js
app.use(auth({
  authorizationParams: { response_type: 'code' },
  accessTokenDecryptionKey: fs.readFileSync('./api-private-key.pem'),
  accessTokenDecryptionAlg: 'RSA-OAEP-256',
}));

// req.oidc.accessToken.access_token is a plain JWT - no change needed downstream
app.get('/profile', requiresAuth(), (req, res) => {
  res.json(req.oidc.user);
});
```
