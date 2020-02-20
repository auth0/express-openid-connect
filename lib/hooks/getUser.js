/**
 * Default function for mapping a tokenSet to a user.
 * This can be used for adjusting or augmenting profile data.
 */
module.exports = function(req, config) {

  if (!config.appSession || !req[config.appSession.name] || !req[config.appSession.name].claims) {
    return null;
  }

  return req[config.appSession.name].claims;
};
