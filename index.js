const auth = require('./middleware/auth');
const requiresAuth = require('./middleware/requiresAuth');

module.exports = {
  auth,
  ...requiresAuth,
};
