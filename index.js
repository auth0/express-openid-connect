const auth = require('./middleware/auth');
const requiresAuth = require('./middleware/requiresAuth');
const attemptSilentLogin = require('./middleware/attemptSilentLogin');
const {
  SessionExpiredError,
  MtlsError,
  MtlsErrorCode,
} = require('./lib/errors');

module.exports = {
  auth,
  ...requiresAuth,
  attemptSilentLogin,
  SessionExpiredError,
  MtlsError,
  MtlsErrorCode,
};
