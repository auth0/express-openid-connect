const { createNonce } = require('../transientHandler');

module.exports.generate = generateLoginState;

/**
 * Generate a unique state value for use during login transactions.
 *
 * @param {RequestHandler} req
 * @param {object} options
 */
function generateLoginState(req, options) {
  const state = {
    returnTo: options.returnTo || req.originalUrl,
    nonce: createNonce()
  };

  return req.openid.encodeState(state);
}
