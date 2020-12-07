const debug = require('../lib/debug')('attemptSilentLogin');
const COOKIES = require('../lib/cookies');
const weakRef = require('../lib/weakCache');

const COOKIE_NAME = 'skipSilentLogin';

const cancelSilentLogin = (req, res) => {
  const {
    config: {
      session: {
        cookie: { secure, domain, path },
      },
    },
  } = weakRef(req.oidc);
  res.cookie(COOKIE_NAME, true, {
    httpOnly: true,
    secure,
    domain,
    path,
  });
};

const resumeSilentLogin = (req, res) => {
  const {
    config: {
      session: {
        cookie: { domain, path },
      },
    },
  } = weakRef(req.oidc);
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    domain,
    path,
  });
};

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
      debug('Attempting silent login');
      cancelSilentLogin(req, res);
      return res.oidc.silentLogin();
    }
    next();
  };
};

module.exports.cancelSilentLogin = cancelSilentLogin;
module.exports.resumeSilentLogin = resumeSilentLogin;
