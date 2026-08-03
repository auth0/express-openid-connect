const express = require('express');
const { auth } = require('../');
const { Agent, fetch: undiciFetch } = require('undici');
const fs = require('fs');
const path = require('path');

const app = express();

// mTLS (Mutual TLS, RFC 8705) client authentication demo.
//
// With `useMtls: true` the SDK authenticates to the token endpoint with a TLS
// client certificate instead of a client secret. Requests are sent to the
// server's `mtls_endpoint_aliases` for each endpoint the server advertises an
// alias for; an endpoint without an alias is sent over the standard (non-mTLS)
// channel, so the tenant must advertise aliases for every endpoint you use.
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

// Resolve the certificate and key relative to this file so the example works
// regardless of the caller's working directory. Fail with a message naming the
// expected files rather than an opaque ENOENT.
const readCertFile = (name) => {
  const file = path.join(__dirname, name);
  try {
    return fs.readFileSync(file);
  } catch (e) {
    throw new Error(
      `mTLS example: could not read "${file}". Place your client certificate ` +
        `("client.crt") and private key ("client.key") next to this example. ` +
        `(${e.code || e.message})`,
    );
  }
};

const tlsAgent = new Agent({
  connect: {
    cert: readCertFile('client.crt'),
    key: readCertFile('client.key'),
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
