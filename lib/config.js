const Joi = require('@hapi/joi');
const clone = require('clone');
const loadEnvs = require('./loadEnvs');
const getUser = require('./hooks/getUser');
const handleCallback = require('./hooks/handleCallback');

const defaultAuthorizeParams = {
  response_mode: 'form_post',
  response_type: 'id_token',
  scope: 'openid profile email'
};

const authorizationParamsSchema = Joi.object().keys({
  response_mode: [Joi.string().optional(), Joi.allow(null).optional()],
  response_type: Joi.string().required(),
  scope: Joi.string().required()
}).unknown(true);

const appSessionCookieSchema = Joi.object().keys({
  domain: Joi.string().optional(),
  httpOnly: Joi.boolean().optional(),
  path: Joi.string().optional(),
  sameSite: Joi.string().valid(['Lax', 'Strict', 'None']).optional(),
  secure: Joi.boolean().optional()
}).unknown(false);

const paramsSchema = Joi.object().keys({
  appSessionCookie: Joi.object().optional(),
  appSessionDuration: Joi.number().integer().optional().default(7 * 24 * 60 * 60),
  appSessionName: Joi.string().token().optional().default('identity'),
  appSessionSecret: Joi.alternatives([
    // Single string key.
    Joi.string(),
    // Array of keys to allow for rotation.
    Joi.array().items(Joi.string()),
    // False to stop client session from being created.
    Joi.boolean().valid([false])
  ]).required(),
  auth0Logout: Joi.boolean().optional().default(false),
  authorizationParams: Joi.object().optional(),
  baseURL: Joi.string().uri().required(),
  clientID: Joi.string().required(),
  clientSecret: Joi.string().optional(),
  clockTolerance: Joi.number().optional().default(60),
  errorOnRequiredAuth: Joi.boolean().optional().default(false),
  getUser: Joi.func().optional().default(getUser),
  handleCallback: Joi.func().optional().default(handleCallback),
  httpOptions: Joi.object().optional(),
  identityClaimFilter: Joi.array().optional().default(['aud', 'iss', 'iat', 'exp', 'nonce', 'azp', 'auth_time']),
  idpLogout: Joi.boolean().optional().default(false).when(
    'auth0Logout', { is: true, then: Joi.boolean().optional().default(true) }
  ),
  idTokenAlg: Joi.string().not('none').optional().default('RS256'),
  issuerBaseURL: Joi.alternatives([ Joi.string().uri(), Joi.string().hostname() ]).required(),
  legacySameSiteCookie: Joi.boolean().optional().default(true),
  loginPath: Joi.string().uri({relativeOnly: true}).optional().default('/login'),
  logoutPath: Joi.string().uri({relativeOnly: true}).optional().default('/logout'),
  redirectUriPath: Joi.string().uri({relativeOnly: true}).optional().default('/callback'),
  required: Joi.alternatives([ Joi.func(), Joi.boolean()]).optional().default(true),
  routes: Joi.boolean().optional().default(true),
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

function buildAppSessionCookieConfig(cookieConfig) {

  cookieConfig = cookieConfig && Object.keys(cookieConfig).length ? cookieConfig : {};
  cookieConfig = Object.assign({ httpOnly: true }, cookieConfig);
  const cookieConfigValidation = Joi.validate(cookieConfig, appSessionCookieSchema);

  if(cookieConfigValidation.error) {
    throw new Error(cookieConfigValidation.error.details[0].message);
  }

  return cookieConfig;
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
  config.appSessionCookie = buildAppSessionCookieConfig(config.appSessionCookie);

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
