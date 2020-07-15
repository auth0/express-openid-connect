const debug = require('../lib/debug');
const COOKIES = require('../lib/cookies');

const COOKIE_NAME = 'silentLoginAttempted';

const cancelSilentLoginAttempts = (req, res) =>
  res.cookie(COOKIE_NAME, true, {
    httpOnly: true,
    secure: req.secure,
  });

module.exports = function attemptSilentLogin() {
  return (req, res, next) => {
    if (!req.oidc) {
      next(
        new Error('req.oidc is not found, did you include the auth middleware?')
      );
      return;
    }

    const silentLoginAttempted = !!(req[COOKIES] || {})[COOKIE_NAME];

    if (
      !silentLoginAttempted &&
      !req.oidc.isAuthenticated() &&
      req.accepts('html')
    ) {
      debug.trace('Attempting silent login');
      cancelSilentLoginAttempts(req, res);
      return res.oidc.silentLogin();
    }
    next();
  };
};

module.exports.cancelSilentLoginAttempts = cancelSilentLoginAttempts;
