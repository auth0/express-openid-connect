
# Examples

## 1. Basic Setup

The simplest use case for this middleware:

```text
# .env
ISSUER_BASE_URL=https://YOUR_DOMAIN
CLIENT_ID=YOUR_CLIENT_ID
BASE_URL=https://YOUR_APPLICATION_ROOT_URL
SESSION_SECRET=LONG_RANDOM_STRING
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

If your application has routes accessible to anonymous users, you can enable authorization per routes:

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

## 3. Route Customization

If you need to customize the routes, you can opt-out from the default routes and write your own route handler:

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

Please note that both of these routes are completely optional and not required. Trying to access any protected resource triggers a redirect directly to Auth0 to login.

## 4. Using access tokens

If your application needs to request and store access and/or refresh tokens, you must provide a method to store the incoming tokens during callback. We recommend to use a persistant store, like a database or Redis, to store these tokens directly associated with the user for which they were requested.

If the tokens only need to be used during the user's session, they can be stored using a session middleware like `express-session`. We recommend persisting the session in a session store other than in-memory (default). The basics of handling the tokens is below:

```js
const { auth } = require('./express-openid-connect');
const session = require('express-session');

app.use(session({
  secret: process.env.SESSION_SECRET
}));

app.use(auth({
  authorizationParams: {
    response_type: 'code id_token',
    response_mode: 'form_post',
    audience: process.env.API_URL,
    scope: 'openid profile email read:reports'
  },
  handleCallback: async function (req, res, next) {
    req.session.openIdTokens = req.openIdTokens;
    next();
  }
}));
```

On a route that needs to use the access token, pull the token data from the storage and initialize a new `TokenSet` using `makeTokenSet()` method exposed by this library:

```js
app.get('/route-that-calls-an-api', async (req, res, next) => {

  const tokenSet = req.openid.makeTokenSet(req.session.openIdTokens);
  let apiData = {};

  // Use tokenSet.access_token for the API call.
});
```

## 5. Using refresh tokens

Refresh tokens can be requested along with access tokens using the `offline_access` scope during login:

```js
app.use(auth({
  authorizationParams: {
    response_type: 'code id_token',
    response_mode: 'form_post',
    audience: process.env.API_URL,
    scope: 'openid profile email read:reports offline_access'
  }
}));
```

On a route that calls an API, check for an expired token and attempt a refresh:

```js
app.get('/route-that-calls-an-api', async (req, res, next) => {

  let apiData = {};
  let tokenSet = req.openid.tokens;

  if (tokenSet && tokenSet.expired() && tokenSet.refresh_token) {
    try {
      tokenSet = await req.openid.client.refresh(tokenSet);
    } catch(err) {
      next(err);
    }

    tokenSet.refresh_token = req.openid.tokens.refresh_token;
    req.openid.tokens = tokenSet;
  }

  // Use tokenSet.access_token for the API call.
});
```

## 6. Calling userinfo

If your application needs to call the userinfo endpoint for the user's identity, add a `handleCallback` function during initialization that will make this call. To map the incoming claims to the user identity, also add a `getUser` function.

```js
app.use(auth({
  handleCallback: async function (req, res, next) {
    const client = req.openid.client;
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