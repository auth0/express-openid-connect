This is an experimental and opinionated middleware for expressjs to handle authentication with openid connect.

This module exposes two middlewares:

-  `.routes()`: install two routes one called `/login` and the other one `/callback`.
-  `.protect()`: is a middleware that redirects to `/login` if req.session.user is empty.

Both middlewares preserve the intended url for the user.

## Install

```
npm i express-openid-connect
```

## Requirements

Before installing the routes,

-  You need to parse url encoded bodies, eg `app.use(bodyParser.urlencoded({ extended: false }));`
-  You need a session middleware like express-session or cookie-session.

## Usage

```
app.use(auth.routes({
  issuer_url: `https://${process.env.AUTH0_DOMAIN}`,
  client_id: process.env.AUTH0_CLIENT_ID,
  authorizationParams: {
    scope: 'openid profile email',
    redirect_uri: `${appUrl}/callback`
  }
}))

app.use('/user', auth.protect(), (req, res) => {
  res.send(`hello ${req.session.user.name}`);
});

app.get('/', (req, res) => res.send("hello!"));
```

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.

