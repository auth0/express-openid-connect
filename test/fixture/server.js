const express = require('express');
const cookieSession = require('cookie-session');
const bodyParser = require('body-parser');
const http = require('http');

module.exports.create = function(router) {
  const app = express();

  app.use(cookieSession({
    name: 'tests',
    secret: 'blabla',
  }));

  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(bodyParser.json());

  app.use(router);

  app.get('/session', (req, res) => {
    res.json(req.session);
  });

  app.post('/session', (req, res) => {
    req.session = req.body;
    res.json(req.body);
  });

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    res.status(err.status || 500)
      .json({ err: { message: err.message }});
  });

  const server = http.createServer(app);

  return new Promise((resolve) => {
    server.unref();
    server.listen(0, () => {
      resolve(`http://localhost:${server.address().port}`);
    });
  });
};
