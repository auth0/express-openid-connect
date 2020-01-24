const Joi = require('@hapi/joi');
const clone = require('clone');
const getUser = require('./hooks/getUser');
const handleCallback = require('./hooks/handleCallback');

const paramsSchema = Joi.object({
  appSessionCookie: Joi.object({
    domain: Joi.string().optional(),
    ephemeral: Joi.boolean().optional().default(false),
    httpOnly: Joi.boolean().optional().default(true),
    path: Joi.string().optional(),
    sameSite: Joi.string().valid('Lax', 'Strict', 'None').optional().default('Lax'),
    secure: Joi.boolean().optional()
  }).optional().unknown(false).default(),
  appSessionDuration: Joi.number().integer().optional().default(7 * 24 * 60 * 60),
  appSessionName: Joi.string().token().optional().default('identity'),
  appSessionSecret: Joi.alternatives([
    Joi.string(),
    Joi.array().items(Joi.string()),
    Joi.boolean().valid(false)
  ]).required(),
  auth0Logout: Joi.boolean().optional().default(false),
  authorizationParams: Joi.object({
    response_type: Joi.string().optional().default('id_token'),
    scope: Joi.string().optional().default('openid profile email'),
    response_mode: Joi.alternatives([
      Joi.string().optional(),
      Joi.allow(null).optional()
    ]).default(function(parent) {
      const responseType = parent.response_type.split(' ');
      const responseIncludesTokens = responseType.includes('id_token') || responseType.includes('token');
      return responseIncludesTokens ? 'form_post' : undefined;
    }),
  }).optional().unknown(true).default(),
  baseURL: Joi.string().uri().required(),
  clientID: Joi.string().required(),
  clientSecret: Joi.string().when(
    Joi.ref('authorizationParams.response_type', {adjust: (value) => value && value.split(' ').includes('code')}),
    {
      is: true,
      then: Joi.string().required().messages({
        'any.required': '"clientSecret" is required for response_type code'
      }),
      otherwise: Joi.when(
        Joi.ref('idTokenAlg', {adjust: (value) => value && 'HS' === value.substring(0,2)}),
        {
          is: true,
          then: Joi.string().required().messages({
            'any.required': '"clientSecret" is required for ID tokens with HS algorithms'
          })
        }
      )
    }
  ),
  clockTolerance: Joi.number().optional().default(60),
  errorOnRequiredAuth: Joi.boolean().optional().default(false),
  getUser: Joi.function().optional().default(() => getUser),
  handleCallback: Joi.function().optional().default(() => handleCallback),
  httpOptions: Joi.object().optional(),
  identityClaimFilter: Joi.array().optional().default(['aud', 'iss', 'iat', 'exp', 'nonce', 'azp', 'auth_time']),
  idpLogout: Joi.boolean().optional().default((parent) => parent.auth0Logout || false),
  idTokenAlg: Joi.string().not('none').optional().default('RS256'),
  issuerBaseURL: Joi.alternatives([
    Joi.string().uri(),
    Joi.string().hostname()
  ]).required(),
  legacySameSiteCookie: Joi.boolean().optional().default(true),
  loginPath: Joi.string().uri({relativeOnly: true}).optional().default('/login'),
  logoutPath: Joi.string().uri({relativeOnly: true}).optional().default('/logout'),
  postLogoutRedirectUri: Joi.string().uri({allowRelative: true}).optional().default(''),
  redirectUriPath: Joi.string().uri({relativeOnly: true}).optional().default('/callback'),
  required: Joi.alternatives([ Joi.function(), Joi.boolean()]).optional().default(true),
  routes: Joi.boolean().optional().default(true),
});

module.exports.get = function(params) {
  let config = (typeof params == 'object' ? clone(params) : {});
  config = Object.assign({
    issuerBaseURL: process.env.ISSUER_BASE_URL,
    baseURL: process.env.BASE_URL,
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    appSessionSecret: process.env.APP_SESSION_SECRET,
  }, config);

  const paramsValidation = paramsSchema.validate(config);
  if (paramsValidation.error) {
    throw new Error(paramsValidation.error.details[0].message);
  }

  return paramsValidation.value;
};
