const express = require('express');
const { auth } = require('../');

const app = express();

// Anonymous Sessions give a visitor an Auth0 identity before they log in.
// Enable the feature and keep authRequired off so anonymous visitors can browse.
app.use(
  auth({
    authRequired: false,
    anonymousSession: {
      enabled: true,
    },
  }),
);

// Landing page. Start an anonymous session on first visit (storing some
// metadata, e.g. a cart id), then reuse it on subsequent visits.
app.get('/', async (req, res, next) => {
  try {
    if (!req.anonymousSession.isAnonymous) {
      await req.anonymousSession.start({
        audience: 'https://api.example.com/cart',
        scope: 'read:cart write:cart',
        metadata: { cart_id: 'cart_123' },
      });
    }
    res.send(
      req.oidc.isAuthenticated()
        ? `Logged in as ${req.oidc.user.sub}`
        : 'Browsing anonymously — <a href="/login">log in</a> to keep your cart.',
    );
  } catch (err) {
    next(err);
  }
});

// Call your API with the anonymous access token. getAccessToken() returns the
// cached token while valid and silently renews it when it expires.
app.get('/cart', async (req, res, next) => {
  try {
    const { access_token } = await req.anonymousSession.getAccessToken();
    // await fetch('https://api.example.com/cart', {
    //   headers: { Authorization: `Bearer ${access_token}` },
    // });
    res.json({ access_token });
  } catch (err) {
    next(err);
  }
});

// End the anonymous session explicitly (it is not cleared automatically on login).
app.get('/end-anonymous', async (req, res, next) => {
  try {
    await req.anonymousSession.end();
    res.redirect('/');
  } catch (err) {
    next(err);
  }
});

module.exports = app;
