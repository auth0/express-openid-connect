const express = require('express');
const { auth, requiresAuth } = require('../');
const { logoutTokenTester } = require('../end-to-end/fixture/helpers');
const { promisify } = require('util');

// This custom implementation deals with IDPs that can send logout tokens
// with either an `sid` or a `sub` or both.
// (The default implementation assumes you always get a `sid`)

const MemoryStore = require('memorystore')(auth);

const app = express();

const store = new MemoryStore();
const get = promisify(store.get).bind(store);
const set = promisify(store.set).bind(store);

const storeLogoutToken = async (token) => {
  const {
    token: { sub, sid },
  } = token;
  await Promise.all([sid && set(sid, token), sub && set(sub, token)]);
};

const getLogoutToken = async (req) => {
  const { sid, sub } = req.oidc.user;
  const [logoutSid, logoutSub] = await Promise.all([
    sid && get(sid),
    sub && get(sub),
  ]);
  if (!logoutSid) return logoutSub;
  if (!logoutSub) return logoutSid;
  // Return the most recently issued logout token.
  return logoutSid.token.iat > logoutSub.token.iat ? logoutSid : logoutSub;
};

app.use(
  auth({
    clientID: 'back-channel-logout-client-no-sid',
    authRequired: false,
    idpLogout: true,
    backChannelLogout: true,
    backChannelLogoutStore: store,
    storeLogoutToken,
    getLogoutToken,
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
  logoutTokenTester('back-channel-logout-client-no-sid', true, true)
);

module.exports = app;
