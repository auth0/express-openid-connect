const safePromisify = require('../../utils/promisifyCompat');

// Default hook that checks if the user has been logged out via Back-Channel Logout
module.exports = async (req, config) => {
  const store =
    (config.backchannelLogout && config.backchannelLogout.store) ||
    config.session.store;
  const get = safePromisify(store.get, store);

  // Use the issuer from the ID token claims to match what's stored in onLogoutToken
  const { iss: issuer, sid, sub } = req.oidc.idTokenClaims;
  if (!sid && !sub) {
    throw new Error(`The session must have a 'sid' or a 'sub'`);
  }
  const [logoutSid, logoutSub] = await Promise.all([
    sid && get(`${issuer}|${sid}`),
    sub && get(`${issuer}|${sub}`),
  ]);
  return !!(logoutSid || logoutSub);
};
