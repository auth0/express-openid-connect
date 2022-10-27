const { promisify } = require('util');
const { get: getClient } = require('../../client');

// Default hook that checks if the user has been logged out via Back-Channel Logout
module.exports = async (req, config) => {
  const store =
    (config.backchannelLogout && config.backchannelLogout.store) ||
    config.session.store;
  const get = promisify(store.get).bind(store);
  const {
    issuer: { issuer },
  } = await getClient(config);
  const { sid, sub } = req.oidc.idTokenClaims;
  if (!sid && !sub) {
    throw new Error(`The session must have a 'sid' or a 'sub'`);
  }
  const [logoutSid, logoutSub] = await Promise.all([
    sid && get(`${issuer}|${sid}`),
    sub && get(`${issuer}|${sub}`),
  ]);
  return !!(logoutSid || logoutSub);
};
