const { createNonce } = require('../transientHandler');
const { encode: base64encode, decode: base64decode } = require('base64url');

module.exports.generate = generateLoginState;
module.exports.prepare = prepareLoginState;
module.exports.decode = decodeLoginState;

/**
 * Generate a unique state value for use during login transactions.
 *
 * @param {RequestHandler} req
 * @param {object} options
 */
function generateLoginState(req, options) {
  let state = {
    returnTo: options.returnTo,
    nonce: createNonce()
  };

  if (req.method === 'GET' && req.originalUrl) {
    state.returnTo = req.originalUrl;
  }

  return prepareLoginState(state);
}

/**
 * Prepare a state object to send.
 *
 * @param {object} stateObject
 */
function prepareLoginState(stateObject) {
  return base64encode(JSON.stringify(stateObject));
}

/**
 * Decode a state value.
 *
 * @param {string} state
 */
function decodeLoginState(state) {
  return JSON.parse(base64decode(state));
}
