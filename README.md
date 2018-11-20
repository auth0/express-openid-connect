Express.js middleware for OpenID Relying Party (aka OAuth 2.0 Client).

This module exposes two middlewares:

-  `.routes()`: install two routes one called `/login` and the other one `/callback`.
-  `.protect()`: is a middleware that redirects to `/login` if req.session.user is empty. This middleware preserves the url that the user tried to access in the session, so the callback can redirect back to it after a succesful login.

## Install

```
npm i express-openid-connect --save
```

## Requirements

Before installing the routes,

-  You need to parse url encoded bodies, eg `app.use(bodyParser.urlencoded({ extended: false }));`
-  You need a session middleware like express-session or cookie-session.

## Usage

```javascript
const auth = require('express-openid-client');

app.use(auth.routes({
  issuer_url: `https://${process.env.AUTH0_DOMAIN}`,
  client_url: 'https://myapplication.com',
  client_id: process.env.AUTH0_CLIENT_ID,
}))

app.use('/user', auth.protect(), (req, res) => {
  res.send(`hello ${req.session.user.name}`);
});

app.get('/', (req, res) => res.send("hello!"));
```

## Configuration through environment variables

Settings can be provided by environment variables as follows:

```
ISSUER_BASE_URL=https://my-domain.auth0.com
BASE_URL=https://myapplication.com
CLIENT_ID=xyz
```

then:

```javascript
const auth = require('express-openid-client');
app.use(auth.routes())
```

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.

