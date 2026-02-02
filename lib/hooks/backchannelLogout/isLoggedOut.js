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

  // Normalize issuer URL to handle trailing slashes consistently
  const normalizedIssuer = issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;

  if (!sid && !sub) {
    throw new Error(`The session must have a 'sid' or a 'sub'`);
  }

  // Try both normalized and non-normalized issuer URLs to handle inconsistencies
  const [logoutSid, logoutSidAlt, logoutSub, logoutSubAlt] = await Promise.all([
    sid && get(`${normalizedIssuer}|${sid}`),
    sid && get(`${normalizedIssuer}/|${sid}`),
    sub && get(`${normalizedIssuer}|${sub}`),
    sub && get(`${normalizedIssuer}/|${sub}`),
  ]);

  return !!(logoutSid || logoutSidAlt || logoutSub || logoutSubAlt);
};
