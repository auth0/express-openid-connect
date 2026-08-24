const auth = require('./middleware/auth');
const requiresAuth = require('./middleware/requiresAuth');
const attemptSilentLogin = require('./middleware/attemptSilentLogin');
const {
  SessionExpiredError,
  MtlsError,
  MtlsErrorCode,
} = require('./lib/errors');
const isFederatedDomain = require('./lib/isFederatedDomain');

module.exports = {
  auth,
  ...requiresAuth,
  attemptSilentLogin,
  SessionExpiredError,
  MtlsError,
  MtlsErrorCode,
  isFederatedDomain,
};
