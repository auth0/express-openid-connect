const Joi = require('joi');
const deprecate = require('deprecate');
const clone = require('clone');
const loadEnvs = require('./loadEnvs');
const profileMapper = require('./profileMapper');

const defaultAuthorizeParams = {
  response_type: 'id_token',
  response_mode: 'form_post',
  scope: 'openid profile email'
};

const authorizationParamsSchema = Joi.object().keys({
  response_type: Joi.string().required(),
  response_mode: [Joi.string().optional(), Joi.allow(null).optional()],
  scope: Joi.string().required()
}).unknown(true);

// const requiredParams = ['issuerBaseURL', 'baseURL', 'clientID'];
const paramsSchema = Joi.object().keys({
  issuerBaseURL: Joi.alternatives([ Joi.string().uri(), Joi.string().hostname() ]).required(),
  baseURL: Joi.string().uri().required(),
  clientID: Joi.string().required(),
  clientSecret: Joi.string().optional(),
  authorizationParams: Joi.object().optional(),
  clockTolerance: Joi.number().optional().default(5),
  profileMapper: Joi.func().optional().default(profileMapper)
});

function buildAuthorizeParams(authorizationParams) {
  /*
If the user does not provide authorizationParams we default to "defaultAuthorizeParams" (id_token/form_post).

If the user provides authorizationParams then
    - the default response_mode is DEFAULT (undefined),
    - the default scope is defaultAuthorizeParams.scope
    - response type is required
  */

  authorizationParams = authorizationParams && Object.keys(authorizationParams).length > 0 ?
    authorizationParams :
    clone(defaultAuthorizeParams);

  if (!authorizationParams.scope) {
    authorizationParams.scope = defaultAuthorizeParams.scope;
  }

  const authParamsValidation = Joi.validate(authorizationParams, authorizationParamsSchema);

  if(authParamsValidation.error) {
    throw new Error(authParamsValidation.error.details[0].message);
  }

  return authorizationParams;
}

module.exports.get = function(params) {
  let config = typeof params == 'object' ? clone(params) : {};

  //TODO: remove this next major version.
  if (typeof config.client_url !== 'undefined') {
    deprecate('client_url', 'the parameter is deprecated, please use baseURL instead');
    config.baseURL = config.client_url;
  }

  //TODO: remove this next major version.
  if (typeof config.issuer_url !== 'undefined') {
    deprecate('issuer_url', 'the parameter is deprecated, please use issuerBaseURL instead');
    config.issuerBaseURL = config.issuer_url;
  }

  loadEnvs(config);

  const paramsValidation = Joi.validate(config, paramsSchema);

  if(paramsValidation.error) {
    throw new Error(paramsValidation.error.details[0].message);
  }

  config = paramsValidation.value;

  config.authorizationParams = buildAuthorizeParams(config.authorizationParams);

  const missingClientSecret = !config.clientSecret &&
    config.authorizationParams.response_type.split(' ').includes('code');

  if(missingClientSecret) {
    throw new Error('"clientSecret" is required for response_type code and response_mode query');
  }

  return config;
};
