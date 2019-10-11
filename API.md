# API

Please see the [Getting Started section of the README](https://github.com/auth0/express-openid-connect#getting-started) for examples of how to apply configuration options.

## Configuration Keys

The `auth()` middleware has a few configuration keys that are required for initialization:

- **`baseURL`**: The root URL for the application router. This can be set automatically with `BASE_URL` in your `env`.
- **`clientID`**: The Client ID for your application. This can be set automatically with `CLIENT_ID` in your `env`.
- **`issuerBaseURL`**: The root URL for the token issuer. In Auth0, this is your Application's **Domain** prepended with `https://`. This can be set automatically with `ISSUER_BASE_URL` in your `env`.

If you are using a response type that includes `code` (typically combined with an `audience` parameter), you will need an additional key:

- **`clientSecret`**: The Client ID for your application. This can be set automatically with `CLIENT_SECRET` in your `env`. 

Additional configuration keys that can be passed:

- **`auth0Logout`**: Boolean value to enable Auth0's non-compliant logout feature (Auth0 customers should set this to `true`). Default is `false`.
- **`clockTolerance`**: Integer value for the system clock's tolerance (also known as "leeway") in seconds for ID token verification. Default is `60`.
- **`getUser`**: Asynchronous function that receives a tokenset and returns the profile for `req.openid.user`. Default is [here](lib/getUser.js).
- **`errorOnRequiredAuth`**: Boolean value to install a middleware that automatically handles Unauthorized/401 errors by triggering the login process. Default is `false`.
- **`httpOptions`**: Default options object used for all HTTP calls made by the library ([possible options](https://github.com/sindresorhus/got/tree/v9.6.0#options)). Default is empty.
- **`idpLogout`**: Boolean value to log the user out from the identity provider on application logout. Requires the issuer to provide a `end_session_endpoint` value. Default is `false`.
- **`loginPath`**: Relative path to application login. Default is `/login`.
- **`logoutPath`**: Relative path to application logout. Default is `/logout`.
- **`redirectUriPath`**: Relative path to the application callback to process the response from the authorization server. This value is combined with the `baseUrl` and sent to the authorize endpoint as the `redirectUri` parameter. Default is `/callback`.
- **`required`**: Use a boolean value to require authentication for all routes. Pass a function instead to base this value on the request. Default is `true`.
- **`routes`**: Boolean value to install the `GET` `/login` and `/logout` routes.  Default is `true`. See [the examples](EXAMPLES.md) for more information on how this key is used.

Default value for `authorizationParams` is:

```javascript
{
  response_type: 'id_token',
  response_mode: 'form_post',
  scope: 'openid profile email'
}
```

Commonly used `authorizationParams`:

| Name                | Default                | Description                                                                                                  |
|---------------------|------------------------|--------------------------------------------------------------------------------------------------------------|
| response_type       | **Required**           | The desired authorization processing flow, including what parameters are returned from the endpoints used.   |
| response_mode       | `undefined` / optional | The mechanism to be used for returning Authorization Response parameters from the Authorization Endpoint.    |
| scope               | `openid profile email` | The scope of the access token.                                                                               |
| audience            | `undefined` / optional | The audience for the access token.                                                                           |

## openidClient.requiresAuth

The `requiresAuth()` middleware protects specific application routes:

```javascript
const { auth, requiresAuth } = require('express-openid-connect');
app.use( auth( { required: false } ) );
app.use( '/admin', requiresAuth() );
```

If all endpoints require the user to be logged in, the default `auth` middleware protects you from this:

```javascript
app.use( auth( { required: true } ) );
```

## Session and Context

The middleware stores the [openid-client TokenSet](https://github.com/panva/node-openid-client/blob/master/docs/README.md#tokenset) in the user's session.

Every `req` object is augmented with the following properties when the request is authenticated

-  `req.openid.user`: contains the user information, use this if you need display an attribute of the user. You can change what's end up here by using the `getUser` parameter of the `auth` middleware.
-  `req.openid.tokens`: is the instance of [TokenSet](https://github.com/panva/node-openid-client/blob/master/docs/README.md#tokenset).
-  `req.openid.client`: is an instance of te [OpenID Client](https://github.com/panva/node-openid-client/blob/master/docs/README.md#client).
-  `req.isAuthenticated()`: returns true if the request is authenticated.

If the request is not authenticated, `req.openid` is `undefined`.

Every `res` object gets the following methods:

-  `res.openid.login(params)`: trigger an authentication request from any route. It receives the following parameters:
  -  `params.returnTo`: The url to return to after authentication. Defaults to the current url for GETs and `baseURL` for other methods.
  -  `params.authorizationParams`: additional parameters for the authorization call.
-  `res.openid.logout(params)`: trigger the openid connect logout if supporter by the issuer.
  -  `params.returnTo`: The url to return to after sign out. Defaults to the `baseURL` for other methods.

## Authorization handling

By default the library triggers the login process when authentication is required.

An anonymous request to the home page in this case will trigger the login process:

```js
app.use(auth()); // Remember that required is true by default
app.get('/', (req, res) => res.render('home'));
```

The same happens in this case:

```js
app.use(auth()); // Remember that required is true by default
app.get('/', requiresAuth(), (req, res) => res.render('home'));
```

If you remove the `auth()` middleware above like this:

```js
// app.use(auth()); // Remember that required is true by default
app.get('/', requiresAuth(), (req, res) => res.render('home'));
```

Instead of triggering the login process we get a 401 Unauthorized error.

It is a best practice to decouple your application logic from this library. If you need to raise a 401 error on your own logic and `requiresAuth` is not enough, you can add the `unauthorizedHandler` from this library:

```js
const {
  auth,
  requiresAuth,
  unauthorizedHandler
} = require('express-openid-connect');

app.use(auth());

// your routes go here
app.get('/a-route', (req, res, next) => {
  if (condition) {
    return next(new UnauthorizedError('unauthorized because of xyz'));
  }
});

//trigger login transactions on 401 errors.
app.use(unauthorizedHandler());
```

If you need an special logic for handling 401s, including the errors raised by this library, you can set `errorOnRequiredAuth` to `true` like this:

```js
const { auth, requiresAuth } = require('express-openid-connect');

app.use(auth({ errorOnRequiredAuth: true }));

// your routes go here

//handle unauthorized errors with the unauthorizedHandler or
//with your own middleware like this:
app.use((err, req, res, next) => {
 if (err.statusCode === 401) {
    return res.openid.login(); //trigger the login process like the `unauthorizedHandler`.
  }
  next(err);
});
```
