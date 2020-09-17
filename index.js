const auth = require('./middleware/auth');
const requiresAuth = require('./middleware/requiresAuth');
const attemptSilentLogin = require('./middleware/attemptSilentLogin');

module.exports = {
  auth,
  ...requiresAuth,
  attemptSilentLogin,
};
