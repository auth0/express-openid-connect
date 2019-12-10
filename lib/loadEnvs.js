const fieldsEnvMap = {
  'issuerBaseURL': 'ISSUER_BASE_URL',
  'baseURL': 'BASE_URL',
  'clientID': 'CLIENT_ID',
  'clientSecret': 'CLIENT_SECRET',
  'sessionSecret': 'SESSION_SECRET',
};

module.exports = function(params) {
  Object.keys(fieldsEnvMap).forEach(k => {
    if (params[k]) {
      return;
    }
    params[k] = process.env[fieldsEnvMap[k]];
  });

  if (!params.baseURL &&
    !process.env.BASE_URL &&
    process.env.PORT &&
    process.env.NODE_ENV !== 'production') {
    params.baseURL = `http://localhost:${process.env.PORT}`;
  }
};

