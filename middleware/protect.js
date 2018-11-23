const UnauthorizedError = require('../lib/UnauthorizedError');

/**
* Returns a middleware that verifies the existence of req.user.
* If "user" is not in the session it will redirect to /login,
* otherwise continue to the next middleware in the stack.
*/
module.exports = function() {
  return async function(req, res, next) {
    if (!req.openid) {
      if (req.method === 'GET') {
        req.session.returnTo = req.originalUrl;
      }
      return res.redirect('/login');
    }

    if (req.openid.tokens.expired() && req.openid.refreshToken) {
      try {
        await req.openid.refreshToken();
      } catch(err) {
        return next(new UnauthorizedError(401, err.message));
      }
    }

    next();
  };
};
