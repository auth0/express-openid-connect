/**
 * Default function for custom callback handling after receiving tokens.
 * This can be used for handling token storage, making userinfo calls, etc.
 */
module.exports = function (req, res, next) {
  next();
};
