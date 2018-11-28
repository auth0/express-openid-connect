## The auth middleware can be configured with environment varabiles

Settings can be provided by environment variables as follows:

```
ISSUER_BASE_URL=https://my-domain.auth0.com
BASE_URL=https://myapplication.com
CLIENT_ID=xyz
```

then:

```javascript
const { routes: auth } = require('express-openid-connect');
app.use(auth())
```

## openidClient.auth parameters

In general, you won't need to configure this middleware besides the required parameters that can be specified through environment variables.

| Name                | Default                         | Description                                                                    |
|---------------------|---------------------------------|--------------------------------------------------------------------------------|
| issuerBaseURL       | `env.ISSUER_BASE_URL`           | The url address for the token issuer.                                          |
| baseURL             | `env.BASE_URL`                  | The url of the web application where you are installing the router.            |
| clientID            | `env.CLIENT_ID`                 | The client id.                                                                 |
| clientSecret        | `env.CLIENT_SECRET`             | The client secret, only required for some grants.                              |
| clockTolerance      | `5`                             | The clock's tolerance in seconds for token verification.                       |
| getUser             | `tokenSet => tokenSet.claims`   | An async function receiving a tokenset and returning the profile for `req.openid.user`. |
| required            | `true`                            | If true requires authentication for all the routes in the stack. You can also provide a function to determine if is required based on the request.               |
| handleUnauthorizedErrors | `true`                     | Install a middleware that handles Unauthorized/401 errors by triggering the login process. |
| routes              | `true`                          | Installs the `GET /login` and `GET /logout` route.                              |
| authorizationParams | See bellow                      | The parameters for the authorization call.                                      |

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

## openidClient.requiresAuth options

The middleware doesn't have any options

```javascript
const { auth, requiresAuth } = require('express-openid-connect');
app.use('/admin', requiresAuth());
```

If all your endpoints require the user to be logged in, you don't need this middleware. The default `auth` middleware protects you from this:

```javascript
app.use(auth());
```

## Session and Context

The middleware store the [openid-client TokenSet](https://www.npmjs.com/package/openid-client#tokenset) in the user's session.

Every `req` object is augmented with the following properties:

-  `req.openid.user`: contains the user information, use this if you need display an attribute of the user. You can change what's end up here by using the `getUser` parameter of the `auth` middleware.
-  `req.openid.tokens`: is the instance of [TokenSet](https://www.npmjs.com/package/openid-client#tokenset).
-  `req.openid.client`: is an instance of te [OpenID Client](https://www.npmjs.com/package/openid-client).
-  `req.openid.refreshToken()`: in case you request for an offline access you can use this promise-returning function to get a fresh `req.openid.tokens`. Note that this is done for you on every route requiring authentication.

Every `res` object gets the following methods:

-  `res.openid.login(params)`: trigger an authentication request from any route. It receives the following parameters:
  -  `params.returnTo`: The url to return to after authentication. Defaults to the current url for GETs and `baseURL` for other methods.
  -  `params.authorizationParams`: additional parameters for the authorization call.
-  `res.openid.logout(params)`: trigger the openid connect logout if supporter by the issuer.
  -  `params.returnTo`: The url to return to after sign out. Defaults to the `baseURL` for other methods.

## Debugging

Start your application with the following environment variable to make this module output the debug logs.

```
DEBUG=express-openid-connect:*
```

**WARNING:** this feature is intended only for development and must not be used in production since it will log sensitive information.
