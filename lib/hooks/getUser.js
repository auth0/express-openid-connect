/**
 * Default function for mapping a tokenSet to a user.
 * This can be used for adjusting or augmenting profile data.
 */
module.exports = function(req, config) {

  // If there is no sessionSecret, session handing is custom.
  if (!config.sessionSecret || !req[config.sessionName] || !req[config.sessionName].claims) {
    return null;
  }

  let identity = req[config.sessionName].claims;

  // Delete ID token validation claims to lower stored size.
  delete identity.iat;
  delete identity.exp;
  delete identity.aud;
  delete identity.nonce;
  delete identity.iss;
  delete identity.azp;
  delete identity.auth_time;

  return identity;
};
