module.exports = {
  name: 'express-openid-connect',
  out: './docs/',
  excludeExternals: true,
  excludePrivate: true,
  hideGenerator: true,
  readme: 'none',
  externalSymbolLinkMappings: {
    '@types/express': {
      'Request.originalUrl':
        'https://expressjs.com/en/4x/api.html#req.originalUrl',
    },
    express: {
      'Request.originalUrl':
        'https://expressjs.com/en/4x/api.html#req.originalUrl',
    },
  },
};
