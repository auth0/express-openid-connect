const safePromisify = require('../../utils/promisifyCompat');
const { get: getClient } = require('../../client');

// Remove any Back-Channel Logout tokens for this `sub` and `sid`
module.exports = async (req, config) => {
  const {
    issuer: { issuer },
  } = await getClient(config);
  const { session, backchannelLogout } = config;
  const store = (backchannelLogout && backchannelLogout.store) || session.store;
  const destroy = safePromisify(store.destroy, store);

  // Get the sub and sid from the ID token claims
  const { sub, sid } = req.oidc.idTokenClaims;

  // Remove both sub and sid based entries
  await Promise.all([
    destroy(`${issuer}|${sub}`),
    sid && destroy(`${issuer}|${sid}`),
  ]);
};
