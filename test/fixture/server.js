const express = require('express')
const cookieSession = require('cookie-session')
const bodyParser = require('body-parser')

module.exports.create = function(router) {
  const app = express();

  app.use(cookieSession({
    name: 'tests',
    secret: 'blabla',
  }));

  app.use(bodyParser.urlencoded({ extended: false }));

  app.use(router);

  return app;
};
