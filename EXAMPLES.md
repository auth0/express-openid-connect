
### Example 1

The simplest use case for this middleware:

```javascript
const { auth } = require('express-openid-connect');

//session and body parser middlewares
// app.use(session());
// app.use(bodyParser());

app.use(auth())

app.use('/', (req, res) => {
  res.send(`hello ${req.openid.user.name}`);
});
```

What you get:
- Every route after the `auth()` middleware requires authentication.
- If a user try to access a resource without being authenticated, the application will trigger the authentication process. After completion the user is redirected back to the resource.
- The application also gets a `GET /login` and `GET /logout` route for easy linking.

This application needs the following environment variables `CLIENT_ID`, `AUTHORITY_URL` and `BASE_URL`.

### Example 2

If you need to customize the routes, you can opt-out from the default routes and handle this manually:

```js
app.use(auth({ routes: false }));

app.get('/Account/SignIn', (req, res) => res.openid.login({ returnTo: '/' }));
app.get('/Account/SignOut', (req, res) => res.openid.logout());
```

Please note that both of these routes are completely optional and not required. Trying to access any protected resource triggers the authentication process if required.

### Example 3

If your application has some resources accessible for anonymous users, you can enable authorization per routes:

```js
const { auth, requiredAuth } = require('express-openid-connect');

//initialization
app.use(auth({ required: false }));

//every route under the /admin prefix requires authentication.
app.use('/admin', requiredAuth());;
```

Another way to configure this scenario:

```js
const { auth } = require('express-openid-connect');

//initialization
app.use(auth({
  required: req => req.originalUrl.startsWith('/admin')
}));
```
