const crypto = require('crypto');

exports.store = store;
exports.getOnce = getOnce;
exports.createNonce = createNonce;

/**
 * Set a cookie with a value or a generated nonce.
 *
 * @param {String} key Cookie name to use.
 * @param {Object} res Express Response object.
 * @param {Object} opts Options object.
 * @param {String} opts.sameSite SameSite attribute of "None," "Lax," or "Strict". Default is "None."
 * @param {String} opts.value Cookie value. Omit this key to store a generated value.
 * @param {Boolean} opts.legacySameSiteCookie Should a fallback cookie be set? Default is true.
 * @param {Boolean} opts.maxAge Cookie MaxAge value, in milliseconds. Default is 600000 (10 minutes).
 *
 * @return {String} Cookie value that was set.
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

  // Set the cookie with the SameSite attribute and, if needed, the Secure flag.
  res.cookie(key, value, Object.assign({}, basicAttr, {sameSite: sameSiteAttr, secure: isSameSiteNone}));

  if (isSameSiteNone && fallbackCookie) {
    // Set the fallback cookie with no SameSite or Secure attributes.
    res.cookie('_' + key, value, basicAttr);
  }

  return value;
}

/**
 * Get a cookie value then delete it.
 *
 * @param {String} key Cookie name to use.
 * @param {Object} req Express Request object.
 * @param {Object} res Express Response object.
 * @param {Object} opts Options object.
 * @param {Boolean} opts.legacySameSiteCookie Should a fallback cookie be checked? Default is true.
 *
 * @return {String|undefined} Cookie value or undefined if cookie was not found.
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
 * Generates a nonce value.
 *
 * @return {String}
 */
function createNonce() {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * Sets a blank value and zero max age cookie.
 *
 * @param {String} name Cookie name
 * @param {Object} res Express Response object
 */
function deleteCookie(name, res) {
  res.cookie(name, '', {maxAge: 0});
}
