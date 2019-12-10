/**
 * Default function for mapping a tokenSet to a user.
 * This can be used for adjusting or augmenting profile data.
 */
module.exports = function(idClaims) {
  if (!idClaims || typeof idClaims !== 'object') {
    return null;
  }

  delete idClaims.iat;
  delete idClaims.exp;
  delete idClaims.aud;
  delete idClaims.nonce;
  delete idClaims.iss;
  delete idClaims.azp;
  delete idClaims.auth_time;

  return idClaims;
};
