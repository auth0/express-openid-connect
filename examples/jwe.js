const express = require('express');
const { auth } = require('../');

const app = express();

// JWE access token decryption demo.
//
// When Auth0 is configured to encrypt access tokens for an API (Dashboard > APIs >
// your API > Token Encryption), the token returned at the callback is a JWE (five
// dot-separated parts). With `accessTokenDecryptionKey` set, the SDK decrypts it
// before writing it to the session - at both the callback and on token refresh -
// so `req.oidc.accessToken` and `afterCallback` always see a plaintext JWT.
//
// The key-management algorithm is read from the JWE protected header (validated
// against a strong-alg allowlist), so decryption works whether the tenant uses
// RSA-OAEP-256, RSA-OAEP-512, etc. Set `accessTokenDecryptionAlg` only to pin one.
//
// Requires a code flow and an API that encrypts tokens, so this example is not
// runnable against the mock provider (it does not encrypt). It shows the config.

app.use(
  auth({
    authRequired: false,
    clientSecret: '__your_client_secret__',
    authorizationParams: {
      response_type: 'code',
      // Request the API whose access tokens are encrypted.
      audience: 'https://your-api/',
      scope: 'openid profile email offline_access',
    },

    // Private key matching the public key uploaded to the API's Token Encryption
    // settings. Accepts PEM string, Buffer, KeyObject, JWK, or CryptoKey.
    accessTokenDecryptionKey: require('fs').readFileSync(
      './api-decryption-key.pem',
    ),
    // Optional pin. Omit to auto-detect the alg from the JWE header.
    // accessTokenDecryptionAlg: 'RSA-OAEP-512',
  }),
);

app.get('/', (req, res) => {
  if (req.oidc.isAuthenticated()) {
    const token = req.oidc.accessToken?.access_token;
    // A decrypted token is a normal 3-part JWT; a 5-part value means it is still
    // encrypted (decryption key not active).
    const parts = token ? token.split('.').length : 0;
    res.send(
      `<p>Logged in as <strong>${req.oidc.user.sub}</strong></p>` +
        `<p>Access token parts: ${parts} (3 = decrypted JWT)</p>` +
        `<a href="/logout">logout</a>`,
    );
  } else {
    res.send('<a href="/login">login</a>');
  }
});

module.exports = app;
