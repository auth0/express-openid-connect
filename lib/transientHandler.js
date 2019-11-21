const crypto = require('crypto');

/**
 * Set a cookie with a value or a generated nonce.
 *
 * @param {String} key Cookie name to use.
 * @param {Object} res Current Express reponse object.
 * @param {Object} opts Options for cookie setting.
 *
 * @return {String}
 */
function store(key, res, opts = {}) {
  const sameSiteAttr = opts.sameSite || 'None';
  const isSameSiteNone = sameSiteAttr === 'None';
  const value = opts.value || createNonce();
  const fallbackCookie = opts.legacySameSiteCookie || true;

  const basicAttr = {
    httpOnly: true,
    maxAge: opts.maxAge || 600 * 1000
  };

  res.cookie(key, value, Object.assign({}, basicAttr, {sameSite: sameSiteAttr, secure: isSameSiteNone}));

  if (isSameSiteNone && fallbackCookie) {
    res.cookie('_' + key, value, basicAttr);
  }

  return value;
}

/**
 * Get a cookie value then delete it.
 *
 * @param {String} key Cookie name to use.
 * @param {Object} req Current Express request object.
 * @param {Object} opts Options for cookie setting.
 */
function getOnce(key, req, res, opts = {}) {

  if (!req.cookies && !req.cookies[key]) {
    return undefined;
  }

  let value = req.cookies[key];
  deleteCookie(key, res);

  const fallbackCookie = opts.legacySameSiteCookie || true;
  if (fallbackCookie) {
    const fallbackKey = '_' + key;
    value = value || req.cookies[fallbackKey];
    deleteCookie(fallbackKey, res);
  }

  return value;
}

/**
 * @return {String}
 */
function createNonce() {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * @return {String}
 */
function deleteCookie(key, res) {
  res.cookie(key, '', {maxAge: 0});
}

exports.store = store;
exports.getOnce = getOnce;
exports.createNonce = createNonce;