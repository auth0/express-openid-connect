
# Examples

## 1. Basic setup

The simplest use case for this middleware:

```text
# .env
ISSUER_BASE_URL=https://YOUR_DOMAIN
CLIENT_ID=YOUR_CLIENT_ID
BASE_URL=https://YOUR_APPLICATION_ROOT_URL
APP_SESSION_SECRET=LONG_RANDOM_STRING
```

```javascript
// app.js
const { auth } = require('express-openid-connect');

app.use(auth({
  required: true
}))

app.use('/', (req, res) => {
  res.send(`hello ${req.openid.user.name}`);
});
```

What you get:

- Every route after the `auth()` middleware requires authentication.
- If a user tries to access a resource without being authenticated, the application will redirect the user to log in. After completion the user is redirected back to the resource.
- The application creates `/login` and `/logout` `GET` routes.

## 2. Require authentication for specific routes

If your application has routes accessible to anonymous users, you can enable authorization per route:

```js
const { auth, requiresAuth } = require('express-openid-connect');

app.use(auth({
  required: false
}));

// Anyone can access the homepage
app.use('/', (req, res) => res.render('home'));

// Require routes under the /admin/ prefix to check authentication.
app.use('/admin/users', requiresAuth(), (req, res) => res.render('admin-users'));
app.use('/admin/posts', requiresAuth(), (req, res) => res.render('admin-posts'));
```

Another way to configure this scenario:

```js
const { auth } = require('express-openid-connect');

app.use(auth({
  required: req => req.originalUrl.startsWith('/admin/')
}));

app.use('/', (req, res) => res.render('home'));
app.use('/admin/users', (req, res) => res.render('admin-users'));
app.use('/admin/posts', (req, res) => res.render('admin-posts'));
```

## 3. Route customization

If you need to customize the provided login and logout routes, you can disable the default routes and write your own route handler:

```js
app.use(auth({ routes: false }));

app.get('/account/login', (req, res) => res.openid.login({ returnTo: '/' }));
app.get('/account/logout', (req, res) => res.openid.logout());
```

... or you can define specific routes in configuration keys where the default handler will run:

```js
app.use(auth({
  redirectUriPath: '/custom-callback-path',
  loginPath: '/custom-login-path',
  logoutPath: '/custom-logout-path',
}));
```

Please note that the login and logout routes are not required. Trying to access any protected resource triggers a redirect directly to Auth0 to login. These are helpful if you need to provide user-facing links to login or logout.

## 4. Custom user session handling

By default, this library uses an encrypted and signed cookie to store the user identity claims as an application session. If the size of the user identity is too large or you're concerned about sensitive data being stored, you can provide your own session handling as part of the `getUser` function.

If, for example, you want the user session to be stored on the server, you can use a session middleware like `express-session`. We recommend persisting the data in a session store other than in-memory (which is the default), otherwise all sessions will be lost when the server restarts. The basics of handling the user identity server-side is below:

```js
const session = require('express-session');
app.use(session({
  secret: 'replace this with a long, random, static string',
  cookie: {
    // Sets the session cookie to expire after 7 days.
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

app.use(auth({
  // Setting this configuration key to false will turn off internal session handling.
  appSessionSecret: false,
  handleCallback: async function (req, res, next) {
    // This will store the user identity claims in the session
    req.session.userIdentity = req.openidTokens.claims();
    next();
  },
  getUser: async function (req) {
    return req.session.userIdentity;
  }
}));
```

## 5. Obtaining and storing access tokens to call external APIs

If your application needs to request and store [access tokens](https://auth0.com/docs/tokens/access-tokens) for external APIs, you must provide a method to store the incoming tokens during callback. We recommend to use a persistant store, like a database or Redis, to store these tokens directly associated with the user for which they were requested.

If the tokens only need to be used during the user's session, they can be stored using a session middleware like `express-session`. We recommend persisting the data in a session store other than in-memory (which is the default), otherwise all tokens will be lost when the server restarts. The basics of handling the tokens is below:

```js
const session = require('express-session');
app.use(session({
  secret: 'replace this with a long, random, static string',
  cookie: {
    // Sets the session cookie to expire after 7 days.
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

app.use(auth({
  authorizationParams: {
    response_type: 'code',
    audience: process.env.API_URL,
    scope: 'openid profile email read:reports'
  },
  handleCallback: async function (req, res, next) {
    req.session.openidTokens = req.openidTokens;
    next();
  }
}));
```

On a route that needs to use the access token, pull the token data from the storage and initialize a new `TokenSet` using `makeTokenSet()` method exposed by this library:

```js
app.get('/route-that-calls-an-api', async (req, res, next) => {

  const tokenSet = req.openid.makeTokenSet(req.session.openidTokens);
  let apiData = {};

  // Check for and use tokenSet.access_token for the API call ...
});
```

## 6. Obtaining and using refresh tokens

[Refresh tokens](https://auth0.com/docs/tokens/refresh-token/current) can be requested along with access tokens using the `offline_access` scope during login. Please see the section on access tokens above for information on token storage.

```js
app.use(auth({
  authorizationParams: {
    response_type: 'code id_token',
    response_mode: 'form_post',
    // API identifier to indicate which API this application will be calling.
    audience: process.env.API_URL,
    // Include the required scopes as well as offline_access to generate a refresh token.
    scope: 'openid profile email read:reports offline_access'
  },
  handleCallback: async function (req, res, next) {
    // See the "Using access tokens" section above for token handling.
    next();
  }
}));
```

On a route that calls an API, check for an expired token and attempt a refresh:

```js
app.get('/route-that-calls-an-api', async (req, res, next) => {

  let apiData = {};

  // How the tokenSet is created will depend on how the tokens are stored.
  let tokenSet = req.openid.makeTokenSet(req.session.openidTokens);
  let refreshToken = tokenSet.refresh_token;

  if (tokenSet && tokenSet.expired() && refreshToken) {
    try {
      tokenSet = await req.openid.client.refresh(tokenSet);
    } catch(err) {
      next(err);
    }

    // New tokenSet may not include a new refresh token.
    tokenSet.refresh_token = tokenSet.refresh_token ?? refreshToken;

    // Where you store the refreshed tokenSet will depend on how the tokens are stored.
    req.session.openidTokens = tokenSet;
  }

  // Check for and use tokenSet.access_token for the API call ...
});
```

## 7. Calling userinfo

If your application needs to call the userinfo endpoint for the user's identity instead of the ID token used by default, add a `handleCallback` function during initialization that will make this call. Save the claims retrieved from the userinfo endpoint to the `appSessionName` on the request object (default is `identity`):

```js
app.use(auth({
  handleCallback: async function (req, res, next) {
    const client = req.openid.client;
    req.identity = req.identity || {};
    try {
      req.identity.claims = await client.userinfo(req.openidTokens);
      next();
    } catch(e) {
      next(e);
    }
  },
  authorizationParams: {
    response_type: 'code',
    scope: 'openid profile email'
  }
}));
```
