/**
 * Default function for mapping a tokenSet to a user.
 * This can be used for adjusting or augmenting profile data.
 */
module.exports = function(req, config) {

  if (!req[config.appSessionName] || !req[config.appSessionName].claims) {
    return null;
  }

  return req[config.appSessionName].claims;
};
