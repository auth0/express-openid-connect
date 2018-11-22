const Joi = require('joi');
const deprecate = require('deprecate');
const _ = require('lodash');
const loadEnvs = require('./loadEnvs');

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
  authorizationParams: Joi.object().optional()
});

function buildAuthorizeParams(params) {
  /*
If the user does not provide authorizationParams we default to "defaultAuthorizeParams" (id_token/form_post).

If the user provides authorizationParams then
    - the default response_mode is DEFAULT (undefined),
    - the default scope is defaultAuthorizeParams.scope
    - response type is required
  */

  const authorizationParams = params.authorizationParams && Object.keys(params.authorizationParams).length > 0 ?
    params.authorizationParams :
    _.clone(defaultAuthorizeParams);

  if (!authorizationParams.scope) {
    authorizationParams.scope = defaultAuthorizeParams.scope;
  }

  const authParamsValidation = Joi.validate(authorizationParams, authorizationParamsSchema);

  if(authParamsValidation.error) {
    throw new Error(authParamsValidation.error.details[0].message);
  }

  return authorizationParams;
}

module.exports.validate = function(params) {
  params = typeof params == 'object' ? _.cloneDeep(params) : {};

  //TODO: remove this next major version.
  if (typeof params.client_url !== 'undefined') {
    deprecate('client_url', 'the parameter is deprecated, please use baseURL instead');
    params.baseURL = params.client_url;
  }

  //TODO: remove this next major version.
  if (typeof params.issuer_url !== 'undefined') {
    deprecate('issuer_url', 'the parameter is deprecated, please use issuerBaseURL instead');
    params.issuerBaseURL = params.issuer_url;
  }

  loadEnvs(params);

  const paramsValidation = Joi.validate(params, paramsSchema);

  if(paramsValidation.error) {
    throw new Error(paramsValidation.error.details[0].message);
  }

  params.authorizationParams = buildAuthorizeParams(params);

  const missingClientSecret = !params.clientSecret &&
    params.authorizationParams.response_type.split(' ').includes('code');

  if(missingClientSecret) {
    throw new Error('"clientSecret" is required for response_type code and response_mode query');
  }

  return params;
};
