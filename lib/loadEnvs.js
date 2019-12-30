const fieldsEnvMap = {
  'issuerBaseURL': 'ISSUER_BASE_URL',
  'baseURL': 'BASE_URL',
  'clientID': 'CLIENT_ID',
  'clientSecret': 'CLIENT_SECRET',
  'appSessionSecret': 'APP_SESSION_SECRET',
};

module.exports = function(params) {
  Object.keys(fieldsEnvMap).forEach(k => {
    if (typeof params[k] === 'undefined') {
      params[k] = process.env[fieldsEnvMap[k]];
    }
  });
};

