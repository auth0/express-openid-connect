
# Examples

## 1. Basic Setup

The simplest use case for this middleware:

```text
# .env
ISSUER_BASE_URL=https://YOUR_DOMAIN
CLIENT_ID=YOUR_CLIENT_ID
BASE_URL=https://YOUR_APPLICATION_ROOT_URL
SESSION_NAME=YOUR_SESSION_NAME
COOKIE_SECRET=LONG_RANDOM_VALUE
```

```javascript
// app.js
const { auth } = require('express-openid-connect');
const session = require('cookie-session');

app.use(express.urlencoded({ extended: false }));

app.use(session({
  name: process.env.SESSION_NAME,
  secret: process.env.COOKIE_SECRET
}));

app.use(auth())

app.use('/', (req, res) => {
  res.send(`hello ${req.openid.user.name}`);
});
```

What you get:

- Every route after the `auth()` middleware requires authentication.
- If a user try to access a resource without being authenticated, the application will trigger the authentication process. After completion the user is redirected back to the resource.
- The application creates `GET /login` and `GET /logout` routes for easy linking.

## 2, Route Customization

If you need to customize the routes, you can opt-out from the default routes and handle this manually:

```js
app.use(auth({ routes: false }));

app.get('/account/login', (req, res) => res.openid.login({ returnTo: '/' }));
app.get('/account/logout', (req, res) => res.openid.logout());
```

... or you can define specific routes for the default handling:

```js
app.use(auth({ 
  redirectUriPath: '/custom-callback-path', 
  loginPath: '/custom-login-path', 
  logoutPath: '/custom-logout-path', 
}));
```

Please note that both of these routes are completely optional and not required. Trying to access any protected resource triggers a redirect directly to Auth0 to login.

## 3. Require auth for specific routes

If your application has routes accessible to anonymous users, you can enable authorization per routes:

```js
const { auth, requiresAuth } = require('express-openid-connect');

app.use(auth({ required: false }));

// Require every route under the /admin prefix to check authentication.
app.use('/admin', requiresAuth());
```

Another way to configure this scenario:

```js
const { auth } = require('express-openid-connect');

//initialization
app.use(auth({
  required: req => req.originalUrl.startsWith('/admin')
}));
```

## 4. Using refresh tokens

Refresh tokens can requested along with access tokens using the `offline_access` scope during login:

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

  if (tokenSet.expired() && tokenSet.refresh_token) {
    try {
      tokenSet = await req.openid.client.refresh(tokenSet);
    } catch(err) {
      next(err);
    }

    tokenSet.refresh_token = req.openid.tokens.refresh_token;
    req.openid.tokens = tokenSet;
  }

  try {
    apiData = await request(
      process.env.API_URL, 
      {
        headers: { authorization: `Bearer ${tokenSet.access_token}` },
        json: true
      }
    );
  } catch(err) {
    next(err);
  }

  res.render('api-data-template', {
    user: req.openid && req.openid.user,
    apiData
  });
});
```