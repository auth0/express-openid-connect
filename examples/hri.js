const express = require('express');
const { auth } = require('../');
const { privateJWK, privatePEM } = require('../end-to-end/fixture/jwk');

const app = express();

// HRI (Highly Regulated Identity) feature demo.
//
// Three features are shown:
//   1. JAR  - authorization params signed as a JWT (active - runs against the mock OIDC provider)
//   2. mTLS - mutual TLS client authentication via customFetch (commented - requires real certs)
//   3. JWE  - encrypted access token decryption (commented - requires an RSA enc key)
//
// Run with: node examples/run_example.js hri.js
// The mock OIDC provider is auto-started. Login with any username/password.

app.use(
  auth({
    authRequired: false,
    authorizationParams: {
      response_type: 'code',
    },

    // Feature 1: JAR (JWT-Secured Authorization Requests)
    // All authorization params are signed into a JWT and sent as the `request` parameter.
    // Pairing with PAR (pushedAuthorizationRequests) is recommended for FAPI compliance.
    // requestObjectSigningAlg is always required - Web Crypto algorithm names are not JWA names.
    //
    // The mock provider uses the 'hri-client' which is registered with:
    //   token_endpoint_auth_method: 'private_key_jwt'
    //   request_object_signing_alg: 'RS256'
    // clientAssertionSigningKey authenticates the token exchange; requestObjectSigningKey signs the JAR.
    // Both use the same test key pair here - in production they can be separate keys.
    clientAuthMethod: 'private_key_jwt',
    clientAssertionSigningKey: privateJWK,
    pushedAuthorizationRequests: true,
    requestObjectSigningKey: privatePEM,
    requestObjectSigningAlg: 'RS256',

    // Feature 2: mTLS client authentication
    // Enable with `useMtls: true` (or the AUTH0_MTLS=true env var). The certificate
    // is presented at the TLS layer by your customFetch, never by the SDK directly.
    // Node's global fetch ignores the `agent` option, so the cert must ride on an
    // undici Dispatcher. Requires an Auth0 custom domain with self-managed certs -
    // it does not work with *.auth0.com. When enabled, `clientSecret` and
    // `clientAssertionSigningKey` must not be set.
    //
    // const { Agent, fetch: undiciFetch } = require('undici');
    // const fs = require('fs');
    // const tlsAgent = new Agent({
    //   connect: {
    //     cert: fs.readFileSync('./client.crt'),
    //     key: fs.readFileSync('./client.key'),
    //   },
    // });
    //
    // useMtls: true,
    // customFetch: (url, opts) => undiciFetch(url, { ...opts, dispatcher: tlsAgent }),

    // Feature 3: JWE access token decryption
    // The SDK decrypts the token before writing it to the session (at the callback
    // and on refresh), so afterCallback and req.oidc.accessToken always see a plain
    // JWT - no changes needed in application code. Use a separate RSA key pair
    // (use:'enc') for decryption in production. The key-management alg is read from
    // the JWE header (RSA-OAEP-256, RSA-OAEP-512, ...); set accessTokenDecryptionAlg
    // only if you want to pin it.
    //
    // accessTokenDecryptionKey: require('fs').readFileSync('./api-decryption-key.pem'),
  }),
);

app.get('/', (req, res) => {
  if (req.oidc.isAuthenticated()) {
    const token = req.oidc.accessToken;
    res.send(
      `<p>Logged in as <strong>${req.oidc.user.sub}</strong></p>` +
        `<p>Access token (first 60 chars): ${token?.access_token?.slice(0, 60) ?? 'n/a'}...</p>` +
        `<a href="/logout">logout</a>`,
    );
  } else {
    res.send('<a href="/login">login</a>');
  }
});

module.exports = app;
