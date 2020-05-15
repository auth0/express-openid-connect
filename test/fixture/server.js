const express = require('express');
const bodyParser = require('body-parser');
const http = require('http');

module.exports.create = function(router, protect, path) {
  const app = express();

  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(bodyParser.json());

  app.use(router);

  app.get('/session', (req, res) => {
    res.json(req.appSession);
  });

  app.post('/session', (req, res) => {
    req.appSession = req.body;
    res.json();
  });

  app.get('/user', (req, res) => {
    res.json(req.openid.user);
  });

  if (protect) {
    app.get('/protected', protect, (req, res) => {
      res.json(req.openid.tokens);
    });
  }

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    res.status(err.status || 500)
      .json({ err: { message: err.message }});
  });

  let mainApp;
  if (path) {
    mainApp = express();
    mainApp.use(path, app);
  } else {
    mainApp = app;
  }

  const server = http.createServer(mainApp);

  return new Promise((resolve) => {
    server.unref();
    server.listen(0, () => {
      resolve(`http://localhost:${server.address().port}`);
    });
  });
};
