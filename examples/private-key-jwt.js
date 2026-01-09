import express from 'express';
import { auth } from '../index.js';
import { privateJWK } from '../end-to-end/fixture/jwk.js';

const app = express();

app.use(
  auth({
    clientID: 'private-key-jwt-client',
    authRequired: false,
    authorizationParams: {
      response_type: 'code',
    },
    clientAssertionSigningKey: privateJWK,
  }),
);

app.get('/', (req, res) => {
  if (req.oidc.isAuthenticated()) {
    res.send(`hello ${req.oidc.user.sub} <a href="/logout">logout</a>`);
  } else {
    res.send('<a href="/login">login</a>');
  }
});

export default app;
