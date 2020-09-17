/**
 * Returns a middleware that start the login transaction on
 * Unauthorized errors (i.e. errors with statusCode === 401)
 *
 * This middleware needs to be included after your application
 * routes.
 */
module.exports = function () {
  return (err, req, res, next) => {
    if (err.statusCode === 401) {
      return res.oidc.login();
    }
    next(err);
  };
};
