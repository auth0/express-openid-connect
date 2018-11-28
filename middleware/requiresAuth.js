const createError = require('http-errors');

/**
* Returns a middleware that verifies the existence of req.openid.user.
* If "user" is not in the session it will redirect to /login,
* otherwise continue to the next middleware in the stack.
*/
module.exports = function() {
  return async function(req, res, next) {
    const requiresLogin = !req.openid ||
                          !req.openid.user;

    if (requiresLogin) {
      return next(createError.Unauthorized('Authentication is required for this route.'));
    }

    if (req.openid.tokens.refresh_token) {
      try {
        await req.openid.refreshToken();
      } catch(err) {
        return next(err);
      }
    }

    next();
  };
};
