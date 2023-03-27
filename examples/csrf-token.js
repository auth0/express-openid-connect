const express = require('express');
const { auth } = require('../');
const jose = require('jose');
const crypto = require('crypto');

const app = express();

const genToken = () => crypto.randomBytes(32).toString('hex');

app.use(
  auth({
    idpLogout: true,
    session: {
      cookie: {
        // Added to demonstrate CSRF-token protection in isolation
        sameSite: 'None',
      },
    },
    afterCallback: (req, res, session) => {
      // Replicating some logic from this SDK
      const { sub: newSub } = jose.JWT.decode(session.id_token);      
      let csrfToken;
      if (req.oidc.isAuthenticated()) {
        if (req.oidc.user.sub === newSub) {
          // If it's the same user logging in again, just return the existing CSRF token.
          csrfToken = session.csrfToken;
        } else {
          // If it's a different user, replace the CSRF token
          csrfToken = genToken();
        }
      } else {
        // If a new user is replacing an anonymous session, replace the CSRF token
        csrfToken = genToken();
      }

      return {
        ...session,
        csrfToken,
      };
    },
  })
);

app.get('/', (req, res) => {
  const expectedToken = req.appSession.csrfToken;
  res.send(`Test CSRF-proof form: 
  <form action="/csrf-test" method="post">
  <input type="hidden" name="CSRFToken" value="${expectedToken}">
  <button type="submit">Submit</button>
  </form>
  `);
});

app.post('/csrf-test', express.urlencoded({ extended: false }), (req, res) => {
  const inputToken = req.body['CSRFToken'];
  const expectedToken = req.appSession.csrfToken;
  if (!inputToken) {
    res.send('Error, CSRF token missing');
  } else if (Array.isArray(inputToken)) {
    res.send('Error, too many CSRF tokens');
  } else if (inputToken != expectedToken) {
    res.send('Error, invalid CSRF token');
  } else {
    res.send('Stateful action executed! Hopefully you meant to do that');
  }
});

module.exports = app;
