/**
 * Default function for mapping a tokenSet to a user.
 * This can be used for adjusting or augmenting profile data.
 */
module.exports = function(req, config) {

  // If there is no sessionSecret, session handing is custom.
  if (!config.sessionSecret || !req[config.sessionName] || !req[config.sessionName].claims) {
    return null;
  }

  return req[config.sessionName].claims;
};
