import express from 'express';
import { auth, requiresAuth } from '../index.js';
import { logoutTokenTester } from '../end-to-end/fixture/helpers.js';
import MemoryStore from 'memorystore';

const MemorySessionStore = MemoryStore(auth);

const app = express();

app.use(
  auth({
    clientID: 'backchannel-logout-client',
    authRequired: false,
    idpLogout: true,
    session: {
      store: new MemorySessionStore(),
    },
    backchannelLogout: true,
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
  logoutTokenTester('backchannel-logout-client', false, true),
);

export default app;
