import { promisify } from 'util';
import express from 'express';
import base64url from 'base64url';
import { auth, requiresAuth } from '../index.js';
import { logoutTokenTester } from '../end-to-end/fixture/helpers.js';
import MemoryStore from 'memorystore';

// This implementation assumes you can query all sessions in the store.
// When you receive a Back-Channel logout request it queries you session store
// for sessions that match the logout token's `sub` or `sid` claim and removes them.

const MemorySessionStore = MemoryStore(auth);

const app = express();

const store = new MemorySessionStore();
const all = promisify(store.all).bind(store);
const destroy = promisify(store.destroy).bind(store);

const decodeJWT = (jwt) => {
  const [, payload] = jwt.split('.');
  return JSON.parse(base64url.decode(payload));
};

const onLogoutToken = async (token) => {
  const { sid: logoutSid, sub: logoutSub } = token;
  // Note: you may not be able to access all sessions in your store
  // and this is likely to be an expensive operation if you have lots of sessions.
  const allSessions = await all();
  for (const [key, session] of Object.entries(allSessions)) {
    // Rather than decode every id token in your store,
    // you could store the `sub` and `sid` on the session in `afterCallback`.
    const { sub, sid } = decodeJWT(session.data.id_token);
    if ((logoutSid && logoutSid === sid) || (logoutSub && logoutSub === sub)) {
      await destroy(key);
    }
  }
};

app.use(
  auth({
    clientID: 'backchannel-logout-client-no-sid',
    authRequired: false,
    idpLogout: true,
    session: { store },
    backchannelLogout: {
      onLogoutToken,
      isLoggedOut: false,
      onLogin: false,
    },
  }),
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
  logoutTokenTester('backchannel-logout-client-no-sid', true, true),
);

export default app;
