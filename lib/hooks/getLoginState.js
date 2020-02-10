const { encode: base64encode, decode: base64decode } = require('base64url');

module.exports.defaultState = defaultState;
module.exports.encodeState = encodeState;
module.exports.decodeState = decodeState;

/**
 * Generate a unique state value for use during login transactions.
 *
 * @param {RequestHandler} req
 * @param {object} options
 *
 * @return {object}
 */
function defaultState(req, options) {
  return {
    returnTo: options.returnTo || req.originalUrl
  };
}

/**
 * Prepare a state object to send.
 *
 * @param {object} stateObject
 *
 * @return {string}
 */
function encodeState(stateObject) {
  return base64encode(JSON.stringify(stateObject));
}

/**
 * Decode a state value.
 *
 * @param {string} stateValue
 *
 * @return {object}
 */
function decodeState(stateValue) {
  return JSON.parse(base64decode(stateValue));
}
