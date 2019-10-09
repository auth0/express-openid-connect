const Joi = require('@hapi/joi');
const clone = require('clone');
const loadEnvs = require('./loadEnvs');
const getUser = require('./getUser');

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
  httpOptions: Joi.object().optional(),
  issuerBaseURL: Joi.alternatives([ Joi.string().uri(), Joi.string().hostname() ]).required(),
  baseURL: Joi.string().uri().required(),
  clientID: Joi.string().required(),
  clientSecret: Joi.string().optional(),
  idTokenAlg: Joi.string().not('none').optional().default('RS256'),
  authorizationParams: Joi.object().optional(),
  clockTolerance: Joi.number().optional().default(5),
  getUser: Joi.func().optional().default(getUser),
  required: Joi.alternatives([ Joi.func(), Joi.boolean()]).optional().default(true),
  routes: Joi.boolean().optional().default(true),
  errorOnRequiredAuth: Joi.boolean().optional().default(false),
  auth0Logout: Joi.boolean().optional().default(false),
  redirectUriPath: Joi.string().optional().default('/callback'),
  loginPath: Joi.string().optional().default('/login'),
  logoutPath: Joi.string().optional().default('/logout'),
  idpLogout: Joi.boolean().optional().default(false)
    .when('auth0Logout', { is: true, then: Joi.boolean().optional().default(true) })
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

  loadEnvs(config);

  const paramsValidation = Joi.validate(config, paramsSchema);

  if(paramsValidation.error) {
    throw new Error(paramsValidation.error.details[0].message);
  }

  config = paramsValidation.value;

  config.authorizationParams = buildAuthorizeParams(config.authorizationParams);

  // Code grant requires a client secret to exchange the code for tokens
  const responseTypeHasCode = config.authorizationParams.response_type.split(' ').includes('code');
  if (responseTypeHasCode && !config.clientSecret) {
    throw new Error('"clientSecret" is required for response_type code');
  }

  // HS256 ID tokens require a client secret to validate the signature.
  if ('HS' === config.idTokenAlg.substring(0,2) && !config.clientSecret) {
    throw new Error('"clientSecret" is required for ID tokens with HS algorithms');
  }

  return config;
};
