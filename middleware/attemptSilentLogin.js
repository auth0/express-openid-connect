import debug from '../lib/debug.js';
import COOKIES from '../lib/cookies.js';
import weakRef from '../lib/weakCache.js';

const debugAttemptSilentLogin = debug('attemptSilentLogin');

const COOKIE_NAME = 'skipSilentLogin';

const cancelSilentLogin = (req, res) => {
  const {
    config: {
      session: {
        cookie: { secure, domain, path, sameSite },
      },
    },
  } = weakRef(req.oidc);
  res.cookie(COOKIE_NAME, true, {
    httpOnly: true,
    secure,
    domain,
    path,
    sameSite,
  });
};

const resumeSilentLogin = (req, res) => {
  const {
    config: {
      session: {
        cookie: { domain, path, sameSite, secure },
      },
    },
  } = weakRef(req.oidc);
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    domain,
    path,
    sameSite,
    secure,
  });
};

export default function attemptSilentLogin() {
  return (req, res, next) => {
    if (!req.oidc) {
      next(
        new Error(
          'req.oidc is not found, did you include the auth middleware?',
        ),
      );
      return;
    }

    const silentLoginAttempted = !!(req[COOKIES] || {})[COOKIE_NAME];

    if (
      !silentLoginAttempted &&
      !req.oidc.isAuthenticated() &&
      req.accepts('html')
    ) {
      debugAttemptSilentLogin('Attempting silent login');
      cancelSilentLogin(req, res);
      return res.oidc.silentLogin();
    }
    next();
  };
}

export { cancelSilentLogin, resumeSilentLogin };
