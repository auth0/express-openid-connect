import express from 'express';
import { auth } from '../index.js';
import MemoryStore from 'memorystore';

const MemorySessionStore = MemoryStore(auth);

const app = express();

app.use(
  auth({
    idpLogout: true,
    session: {
      store: new MemorySessionStore({
        checkPeriod: 24 * 60 * 1000,
      }),
    },
    allowInsecureRequests: true,
  }),
);

app.get('/', (req, res) => {
  res.send(`hello ${req.oidc.user.sub}`);
});

export default app;
