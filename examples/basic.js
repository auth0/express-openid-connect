import express from 'express';
import { auth } from '../index.js';

const app = express();

app.use(
  auth({
    idpLogout: true,
  }),
);

app.get('/', (req, res) => {
  res.send(`hello ${req.oidc.user.sub}`);
});

export default app;
