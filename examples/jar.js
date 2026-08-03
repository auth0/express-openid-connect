const express = require('express');
const { auth } = require('../');
const { privateJWK, privatePEM } = require('../end-to-end/fixture/jwk');

const app = express();

// JAR (JWT-Secured Authorization Requests) demo.
//
// When `requestObjectSigningKey` is set, the SDK signs all authorization
// parameters into a JWT and sends it as the `request` parameter, so the
// /authorize redirect carries only `client_id` and `request`. Combined with PAR
// (recommended for FAPI), the signed request object is POSTed to /oauth/par and
// only an opaque `request_uri` appears in the browser redirect.
//
// `requestObjectSigningAlg` is always required - Web Crypto algorithm names are
// not valid JWA `alg` values.
//
// Run with: node examples/run_example.js jar.js
// The mock OIDC provider is auto-started. Login with any username/password.

app.use(
  auth({
    authRequired: false,
    authorizationParams: {
      response_type: 'code',
    },

    // The mock provider's 'jar-client' is registered for private_key_jwt + JAR.
    // clientAssertionSigningKey authenticates the token exchange; the same key
    // pair signs the JAR request object here. In production they can differ.
    clientAuthMethod: 'private_key_jwt',
    clientAssertionSigningKey: privateJWK,

    pushedAuthorizationRequests: true,
    requestObjectSigningKey: privatePEM,
    requestObjectSigningAlg: 'RS256',
    // Optional: set a `kid` in the signed request object's JWT header.
    // requestObjectSigningKeyId: 'my-key-id',
  }),
);

app.get('/', (req, res) => {
  if (req.oidc.isAuthenticated()) {
    res.send(
      `<p>Logged in as <strong>${req.oidc.user.sub}</strong></p>` +
        `<a href="/logout">logout</a>`,
    );
  } else {
    res.send('<a href="/login">login</a>');
  }
});

module.exports = app;
