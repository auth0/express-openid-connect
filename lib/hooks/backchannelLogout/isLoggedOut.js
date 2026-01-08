import safePromisify from '../../utils/promisifyCompat.js';
import { get as getClient } from '../../client.js';

// Default hook that checks if the user has been logged out via Back-Channel Logout
export default async (req, config) => {
  const store =
    (config.backchannelLogout && config.backchannelLogout.store) ||
    config.session.store;
  const get = safePromisify(store.get, store);
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
