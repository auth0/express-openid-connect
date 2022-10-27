const { promisify } = require('util');
const crypto = require('crypto');
const express = require('express');
const { auth, requiresAuth } = require('../');
const { logoutTokenTester } = require('../end-to-end/fixture/helpers');

// This custom implementation uses a sessions with an id that matches the
// Identity Provider's session id "sid" (by using the "genid" config).
// When the SDK receives a logout token, it can identify the session that needs
// to be destroyed by the logout token's "sid".

const MemoryStore = require('memorystore')(auth);

const app = express();

const store = new MemoryStore();
const destroy = promisify(store.destroy).bind(store);

const onLogoutToken = async (token) => {
  const { sid } = token;
  // Delete the session - no need to store a logout token.
  await destroy(sid);
};

app.use(
  auth({
    clientID: 'backchannel-logout-client',
    authRequired: false,
    idpLogout: true,
    backchannelLogout: {
      onLogoutToken,
      isLoggedOut: false,
      onLogin: false,
    },
    session: {
      store,
      // If you're using a custom `genid` you should sign the session store cookie
      // to ensure it is a cryptographically secure random string and not guessable.
      signSessionStoreCookie: true,
      genid(req) {
        if (req.oidc && req.oidc.isAuthenticated()) {
          const { sid } = req.oidc.idTokenClaims;
          // Note this must be unique and a cryptographically secure random value.
          return sid;
        } else {
          // Anonymous user sessions (like checkout baskets)
          return crypto.randomBytes(16).toString('hex');
        }
      },
    },
  })
);

app.get('/', async (req, res) => {
  if (req.oidc.isAuthenticated()) {
    res.send(`hello ${req.oidc.user.sub} <a href="/logout">logout</a>`);
  } else {
    res.send('<a href="/login">login</a>');
  }
});

// For testing purposes only
app.get(
  '/logout-token',
  requiresAuth(),
  logoutTokenTester('backchannel-logout-client', true)
);

module.exports = app;
