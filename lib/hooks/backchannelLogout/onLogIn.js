import safePromisify from '../../utils/promisifyCompat.js';
import { get as getClient } from '../../client.js';

// Remove any Back-Channel Logout tokens for this `sub` and `sid`
export default async (req, config) => {
  console.log('onLogin hook called - cleaning up back-channel logout entries');
  const {
    issuer: { issuer },
  } = await getClient(config);
  const { session, backchannelLogout } = config;
  const store = (backchannelLogout && backchannelLogout.store) || session.store;
  const destroy = safePromisify(store.destroy, store);

  // Get the sub and sid from the ID token claims
  const { sub, sid } = req.oidc.idTokenClaims;
  console.log(
    'Cleaning up entries for sub:',
    sub,
    'sid:',
    sid,
    'issuer:',
    issuer,
  );

  // Normalize issuer URL to handle trailing slashes consistently
  const normalizedIssuer = issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;

  // Remove both sub and sid based entries for both normalized and non-normalized issuer URLs
  const keys = [
    `${normalizedIssuer}|${sub}`,
    `${normalizedIssuer}/|${sub}`,
    sid && `${normalizedIssuer}|${sid}`,
    sid && `${normalizedIssuer}/|${sid}`,
  ].filter(Boolean);

  console.log('Attempting to destroy keys:', keys);

  await Promise.all(keys.map((key) => destroy(key)));

  console.log('onLogin cleanup completed');
};
