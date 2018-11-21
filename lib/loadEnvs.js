const fieldsEnvMap = {
  'issuer_base_url': 'ISSUER_BASE_URL',
  'base_url': 'BASE_URL',
  'client_id': 'CLIENT_ID',
  'client_secret': 'CLIENT_SECRET',
};

module.exports = function(params) {
  Object.keys(fieldsEnvMap).forEach(k => {
    if (params[k]) {
      return;
    }
    params[k] = process.env[fieldsEnvMap[k]];
  });

  if (!params.base_url &&
    !process.env.BASE_URL &&
    process.env.PORT &&
    process.env.NODE_ENV !== 'production') {
    params.base_url = `http://localhost:${process.env.PORT}`;
  }
};

