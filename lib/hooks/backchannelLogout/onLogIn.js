const safePromisify = require('../../utils/promisifyCompat');

// Remove any Back-Channel Logout tokens for this `sub` and `sid`
module.exports = async (req, config) => {
  const { session, backchannelLogout } = config;
  const store = (backchannelLogout && backchannelLogout.store) || session.store;
  const destroy = safePromisify(store.destroy, store);

  // Get the issuer, sub and sid from the ID token claims to match what's stored
  const { iss: issuer, sub, sid } = req.oidc.idTokenClaims;

  // Remove both sub and sid based entries
  await Promise.all([
    destroy(`${issuer}|${sub}`),
    sid && destroy(`${issuer}|${sid}`),
  ]);
};
