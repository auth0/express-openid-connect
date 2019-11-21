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
  const fallbackCookie = 'legacySameSiteCookie' in opts ? opts.legacySameSiteCookie : true;

  const basicAttr = {
    httpOnly: true,
    maxAge: 'maxAge' in opts ? parseInt(opts.maxAge, 10) : 600 * 1000 // 10 minutes
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

  if (!req.cookies) {
    return undefined;
  }

  let value = req.cookies[key];
  delete req.cookies[key];
  deleteCookie(key, res);

  if ('legacySameSiteCookie' in opts ? opts.legacySameSiteCookie : true) {
    const fallbackKey = '_' + key;
    value = value || req.cookies[fallbackKey];
    delete req.cookies[fallbackKey];
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