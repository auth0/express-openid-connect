class SessionExpiredError extends Error {
  constructor(message = 'The upstream IdP session has expired.') {
    super(message);
    this.name = 'SessionExpiredError';
    this.code = 'ERR_SESSION_EXPIRED';
    this.status = 401;
    this.statusCode = 401;
  }
}

module.exports = { SessionExpiredError };
