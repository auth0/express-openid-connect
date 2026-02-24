const https = require('https');
const fs = require('fs');
const express = require('express');
const { auth } = require('../');

const app = express();

app.use(
  auth({
    authRequired: false,
    authorizationParams: {
      response_type: 'code',
      scope: 'openid profile email',
    },
    // Enable mTLS client authentication (RFC 8705).
    // The SDK will use `mtls_endpoint_aliases` from the OIDC discovery
    // document and default `clientAuthMethod` to `tls_client_auth`.
    useMtls: true,
    // Provide an https.Agent with the client certificate, private key,
    // and (optionally) the CA that signed the authorization server's cert.
    httpAgent: {
      https: new https.Agent({
        cert: fs.readFileSync(
          process.env.MTLS_CLIENT_CERT || 'client-cert.pem',
        ),
        key: fs.readFileSync(process.env.MTLS_CLIENT_KEY || 'client-key.pem'),
        ca: process.env.MTLS_CA_CERT
          ? fs.readFileSync(process.env.MTLS_CA_CERT)
          : undefined,
      }),
    },
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
