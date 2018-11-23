/**
* Returns a middleware that verifies the existence of req.session.user.
* If "user" is not in the session it will redirect to /login,
* otherwise continue to the next middleware in the stack.
*/
module.exports = function() {
  return function(req, res, next) {
    if (req.session.user) { return next(); }
    if (req.method === 'GET') {
      req.session.returnTo = req.originalUrl;
    }
    res.redirect('/login');
  };
};
