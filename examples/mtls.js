const express = require('express');
const { auth } = require('../');
const { Agent, fetch: undiciFetch } = require('undici');
const fs = require('fs');

const app = express();

// mTLS (Mutual TLS, RFC 8705) client authentication demo.
//
// With `useMtls: true` the SDK authenticates to the token endpoint with a TLS
// client certificate instead of a client secret, and routes token/refresh/
// revocation/userinfo/PAR requests to the server's `mtls_endpoint_aliases`.
// Issued access tokens carry a `cnf.x5t#S256` claim binding them to the
// certificate (certificate-bound tokens).
//
// The certificate is presented at the TLS layer by your customFetch, never by
// the SDK. Node's global fetch ignores the `agent` option, so the cert must ride
// on an undici Agent's `connect` options via the `dispatcher`.
//
// Prerequisites (see the mTLS docs):
//   - A custom domain with self-managed certs (does NOT work on *.auth0.com).
//   - mTLS endpoint aliases enabled on the tenant.
//   - App Credentials > Authentication Method set to mTLS, with the client cert
//     uploaded.
//   - No clientSecret / clientAssertionSigningKey (mutually exclusive with mTLS).
//
// `AUTH0_MTLS=true` can be used instead of `useMtls: true`.

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
    authRequired: false,
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

app.get('/', (req, res) => {
  if (req.oidc.isAuthenticated()) {
    res.send(`hello ${req.oidc.user.sub} <a href="/logout">logout</a>`);
  } else {
    res.send('<a href="/login">login</a>');
  }
});

module.exports = app;
