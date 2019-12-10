/**
 * Default function for mapping a tokenSet to a user.
 * This can be used for adjusting or augmenting profile data.
 */
module.exports = function(tokenSet) {
  return tokenSet && tokenSet.claims();
};
