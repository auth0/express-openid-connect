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
  response_type: Joi.string().required().default('id_token'),
  response_mode: Joi.string().default('form_post'),
  scope: Joi.string().required().default('openid profile email')
});

// const requiredParams = ['issuer_base_url', 'base_url', 'client_id'];
const paramsSchema = Joi.object().keys({
  issuer_base_url: Joi.string().uri().required(),
  base_url: Joi.string().uri().required(),
  client_id: Joi.string().required(),
  client_secret: Joi.string().optional(),
  authorizationParams: Joi.object().optional()
});

function buildAutorizeParams(params) {
  const authorizationParams = Object.assign({}, defaultAuthorizeParams, params.authorizationParams || {});
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
    deprecate('client_url', 'the parameter is deprecated, please use base_url instead');
    params.base_url = params.client_url;
  }

  //TODO: remove this next major version.
  if (typeof params.issuer_url !== 'undefined') {
    deprecate('issuer_url', 'the parameter is deprecated, please use issuer_base_url instead');
    params.issuer_base_url = params.issuer_url;
  }

  loadEnvs(params);

  const paramsValidation = Joi.validate(params, paramsSchema);

  if(paramsValidation.error) {
    throw new Error(paramsValidation.error.details[0].message);
  }

  params.authorizeParams = buildAutorizeParams(params);

  return params;
};
