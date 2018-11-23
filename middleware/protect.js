const UnauthorizedError = require('../lib/UnauthorizedError');

/**
* Returns a middleware that verifies the existence of req.user.
* If "user" is not in the session it will redirect to /login,
* otherwise continue to the next middleware in the stack.
*/
module.exports = function() {
  return async function(req, res, next) {

    if (req.user) {
      if (req.tokens.expired()) {
        try {
          req.tokens = await req.openIDClient.refresh(req.tokens);
          req.session.tokens = req.tokens;
        } catch(err) {
          return next(new UnauthorizedError(401, err.message));
        }
      }
      return next();
    }

    if (req.method === 'GET') {
      req.session.returnTo = req.originalUrl;
    }

    res.redirect('/login');
  };
};
