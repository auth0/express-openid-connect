import express from 'express';
import { auth } from '../index.js';

const app = express();

app.use(
  auth({
    attemptSilentLogin: true,
    authRequired: false,
  }),
);

app.get('/', (req, res) => {
  if (req.oidc.isAuthenticated()) {
    res.send(`hello ${req.oidc.user.sub}`);
  } else {
    res.send('<a href="/login">login</a>');
  }
});

export default app;
