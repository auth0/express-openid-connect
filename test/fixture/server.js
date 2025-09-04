const express = require('express');
const bodyParser = require('body-parser');

module.exports.create = function (router, protect, path) {
  const app = express();

  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(bodyParser.json());

  if (router) {
    app.use(router);
  }

  app.get('/session', (req, res) => {
    res.json(req.appSession);
  });

  app.post('/session', (req, res) => {
    Object.keys(req.appSession).forEach((prop) => {
      delete req.appSession[prop];
    });
    Object.assign(req.appSession, req.body);
    res.json();
  });

  app.get('/user', (req, res) => {
    res.json(req.oidc.user);
  });

  app.get('/tokens', (req, res) => {
    res.json({
      isAuthenticated: req.oidc.isAuthenticated(),
      idToken: req.oidc.idToken,
      refreshToken: req.oidc.refreshToken,
      accessToken: req.oidc.accessToken,
      accessTokenExpired: req.oidc.accessToken
        ? req.oidc.accessToken.isExpired()
        : undefined,
      idTokenClaims: req.oidc.idTokenClaims,
    });
  });

  if (protect) {
    app.get('/protected', protect, (req, res) => {
      res.json({});
    });
  }

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    res
      .status(err.status || 500)
      .json({
        err: {
          message: err.message,
          error: err.error,
          error_description: err.error_description,
        },
      });
  });

  let mainApp;
  if (path) {
    mainApp = express();
    mainApp.use(path, app);
  } else {
    mainApp = app;
  }

  return new Promise((resolve) => {
    const server = mainApp.listen(3000, () => resolve(server));
  });
};
