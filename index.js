const express = require('express');
const { Issuer } = require('openid-client');
const crypto = require('crypto');
const urlJoin = require('url-join');
const _ = require('lodash');
const deprecate = require('deprecate');

Issuer.defaultHttpOptions = { timeout: 4000 };

/**
* Returns a middleware that verifies the existence of req.session.user.
* If "user" is not in the session it will redirect to /login,
* otherwise continue to the next middleware in the stack.
*/
module.exports.protect = function() {
  return function(req, res, next) {
    if (req.session.user) { return next(); }
    if (req.method === 'GET') {
      req.session.returnTo = req.originalUrl;
    }
    res.redirect('/login');
  };
};

const defaultAuthorizeParams = {
  response_type: 'id_token',
  response_mode: 'form_post',
  scope: 'openid profile email'
};

const fieldsEnvMap = {
  'issuer_base_url': 'ISSUER_BASE_URL',
  'base_url': 'BASE_URL',
  'client_id': 'CLIENT_ID',
  'client_secret': 'CLIENT_SECRET',
};

function loadFromEnv(params) {
  Object.keys(fieldsEnvMap).forEach(k => {
    if (params[k]) { return; }
    params[k] = process.env[fieldsEnvMap[k]];
  });

  if (!params.base_url &&
      !process.env.BASE_URL &&
      process.env.PORT &&
      process.env.NODE_ENV !== 'production') {
    params.base_url = `http://localhost:${process.env.PORT}`;
  }
}

const requiredParams = ['issuer_base_url', 'base_url', 'client_id'];
/**
* Returns a router with two routes /login and /callback
*
* @param {Object} [params] - The parameters object
* @param {string} [params.issuer_base_url] - The url address for the token issuer.
* @param {string} [params.base_url] - The url of the web application where you are installing the router.
* @param {string} [params.client_id] - The client id.
* @param {string} [params.client_secret] - The client secret, only required for some grants.
* @param {Object} [params.authorizationParams] - The parameters for the authorization call.
* @param {string} [params.authorizationParams.response_type=id_token] - The response type.
* @param {string} [params.authorizationParams.response_mode=form_post] - The response mode.
* @param {string} [params.authorizationParams.scope=openid profile email] - The scope.
* @returns {express.Router} the router
*/
module.exports.routes = function(params) {
  params = typeof params == 'object' ? _.cloneDeep(params) : {};

  //TODO: remove this next major version.
  if (typeof params.client_url !== 'undefined') {
    deprecate('client_url', 'the parameter is deprecated, please use base_url instead');
    params.base_url = params.client_url;
  }

  //TODO: remove this next major version.
  if (typeof params.issuer_url !== 'undefined') {
    deprecate('issuer_url', 'the parameter is deprecated, please use issuer_base_url instead');
    params.issuer_base_url = params.issuer_url;
  }

  loadFromEnv(params);

  requiredParams.forEach(rp => {
    if (params[rp]) { return; }
    throw new Error(`${rp} is required.
It needs to be provided either in the parameters object or as an environment variable ${fieldsEnvMap[rp]}`);
  });

  const authorizeParams = Object.assign({ },
    defaultAuthorizeParams,
    params.authorizationParams || {});

  const router = express.Router();

  const getClient = _.memoize(async function() {
    const issuer = await Issuer.discover(params.issuer_base_url);
    return new issuer.Client({
      client_id: params.client_id,
      client_secret: params.client_secret
    });
  });

  function getRedirectUri(req) {
    return urlJoin(params.base_url, req.baseUrl || '', '/callback');
  }

  router.get('/login', async (req, res, next) => {
    const client = await getClient();
    const redirect_uri = getRedirectUri(req);
    if (typeof req.session === 'undefined') {
      return next(new Error('This router needs the session middleware'));
    }
    req.session.nonce = crypto.randomBytes(8).toString('hex');
    req.session.state = crypto.randomBytes(10).toString('hex');
    const authorizationUrl = client.authorizationUrl(Object.assign({
      nonce: req.session.nonce,
      state: req.session.state,
      redirect_uri
    }, authorizeParams));
    res.redirect(authorizationUrl);
  });

  let callbackMethod;
  let repost;

  switch (authorizeParams.response_mode) {
    case 'form_post':
      callbackMethod = 'post';
      break;
    case 'query':
      callbackMethod = 'get';
      break;
    case 'fragment':
      callbackMethod = 'post';
      repost = true;
      break;
    default:
      if (/token/.test(authorizeParams.response_type)) {
        callbackMethod = 'post';
        repost = true;
      } else {
        callbackMethod = 'get';
      }
  }

  router[callbackMethod]('/callback', async (req, res) => {
    const client = await getClient();
    const { nonce, state } = req.session;
    delete req.session.nonce;
    delete req.session.state;

    const redirect_uri = getRedirectUri(req);

    const callbackParams = client.callbackParams(req); // => parsed url query or body object
    const tokenSet = await client.authorizationCallback(
      redirect_uri,
      callbackParams, {
        nonce,
        state,
        response_type: authorizeParams.response_type,
      });

    req.session.user = tokenSet.claims;
    const returnTo = req.session.returnTo || '/';
    res.redirect(returnTo);
  });

  if (repost) {
    router.get('/callback', async (req, res) => {
      res.set('Content-Type', 'text/html');
      res.send(Buffer.from(`<html>
<head>
  <title>Fragment Repost Form</title>
</head>
<body>
  <script type="text/javascript">
    function parseQuery(queryString) {
      var query = {};
      var pairs = (queryString[0] === '?' ? queryString.substr(1) : queryString).split('&');
      for (var i = 0; i < pairs.length; i++) {
          var pair = pairs[i].split('=');
          query[decodeURIComponent(pair[0])] = decodeURIComponent(pair[1] || '');
      }
      return query;
    }

    var fields = parseQuery(window.location.hash.substring(1));

    var form = document.createElement('form');
    form.method = 'POST';
    Object.keys(fields).forEach((key) => {
      if (key) { // empty fragment will yield {"":""};
        var input = document.createElement('input');
        input.type = 'hidden';
        input.name = key;
        input.value = fields[key];
        form.appendChild(input);
      }
    });
    document.body.appendChild(form);
    form.submit();
  </script>
</body>
</html>`));
    });
  }

  return router;
};
