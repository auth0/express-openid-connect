import express from 'express';
import { auth, requiresAuth } from '../index.js';

const app = express();

app.use(
  auth({
    authRequired: false,
    allowInsecureRequests: true,
  }),
);

// Anyone can access the homepage
app.get('/', (req, res) => {
  res.send('<a href="/admin">Admin Section</a>');
});

// requiresAuth checks authentication.
app.get('/admin', requiresAuth(), (req, res) =>
  res.send(`Hello ${req.oidc.user.sub}, this is the admin section.`),
);

export default app;
