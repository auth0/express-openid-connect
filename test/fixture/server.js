import express from 'express';
import bodyParser from 'body-parser';

export function create(router, protect, path) {
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
    // Return token information without exposing internal structure
    const response = {
      isAuthenticated: req.oidc.isAuthenticated(),
      // Only expose behavior-relevant properties
      hasIdToken: !!req.oidc.idToken,
      hasAccessToken: !!req.oidc.accessToken,
      hasRefreshToken: !!req.oidc.refreshToken,
      idTokenClaims: req.oidc.idTokenClaims,
    };

    // Include token details for compatibility, but abstract the structure
    if (req.oidc.idToken) {
      response.idToken = req.oidc.idToken;
    }

    if (req.oidc.accessToken) {
      response.accessToken = req.oidc.accessToken;
      response.accessTokenExpired = req.oidc.accessToken.isExpired
        ? req.oidc.accessToken.isExpired()
        : false;
    }

    if (req.oidc.refreshToken) {
      response.refreshToken = req.oidc.refreshToken;
    }

    res.json(response);
  });

  if (protect) {
    app.get('/protected', protect, (req, res) => {
      res.json({});
    });
  }

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    res.status(err.status || 500).json({
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
}
