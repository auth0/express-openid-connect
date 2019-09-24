
### Example 1

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
const { auth } = require('express-openid-connect');
const session = require('cookie-session');

app.use(express.urlencoded({
  extended: false
}));

app.use(session({
  name: process.env.SESSION_NAME,
  secret: process.env.COOKIE_SECRET
}));

app.use(auth({
  required: true
}))

app.use('/', (req, res) => {
  res.send(`hello ${req.openid.user.name}`);
});
```

What you get:

- Every route after the `auth()` middleware requires authentication.
- If a user try to access a resource without being authenticated, the application will trigger the authentication process. After completion the user is redirected back to the resource.
- The application creates `GET /login` and `GET /logout` routes for easy linking.

### Example 2

If you need to customize the routes, you can opt-out from the default routes and handle this manually:

```js
app.use(auth({ routes: false }));

app.get('/account/login', (req, res) => res.openid.login({ returnTo: '/' }));
app.get('/account/logout', (req, res) => res.openid.logout());
```

Please note that both of these routes are completely optional and not required. Trying to access any protected resource triggers the authentication process if required.

### Example 3

If your application has routes accessible to anonymous users, you can enable authorization per routes:

```js
const { auth, requiresAuth } = require('express-openid-connect');

app.use(auth({ required: false }));

// Require every route under the /admin prefix to check authentication.
app.use('/admin', requiresAuth());;
```

Another way to configure this scenario:

```js
const { auth } = require('express-openid-connect');

//initialization
app.use(auth({
  required: req => req.originalUrl.startsWith('/admin')
}));
```
