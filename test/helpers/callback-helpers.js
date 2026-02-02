import qs from 'querystring';
import { createCallbackTokenMock } from './oidc-mocks.js';
import { createTokenResponse } from './token-helpers.js';

/**
 * Helper for setting up callback test scenarios with reduced OIDC coupling
 */

/**
 * Setup callback test with flexible token handling
 */
export const setupCallbackTest = async (params = {}) => {
  const {
    authOpts = {},
    body = {},
    tokenResponseHandler,
    customTokenResponse = {},
  } = params;

  // Create flexible token endpoint mock
  let tokenReqHeader;
  let tokenReqBody;
  let tokenReqBodyJson;

  const defaultTokenHandler = function (uri, requestBody) {
    tokenReqHeader = this.req.headers;
    tokenReqBody = requestBody;
    tokenReqBodyJson = qs.parse(requestBody);

    const baseResponse = createTokenResponse('default', customTokenResponse);

    // Use id_token from request body if provided
    if (body.id_token) {
      baseResponse.id_token = body.id_token;
    }

    return baseResponse;
  };

  const tokenMock = createCallbackTokenMock(
    authOpts.issuerBaseURL || 'https://op.example.com',
    tokenResponseHandler || defaultTokenHandler,
  );

  return {
    tokenMock,
    getTokenRequest: () => ({
      headers: tokenReqHeader,
      body: tokenReqBody,
      bodyJson: tokenReqBodyJson,
    }),
  };
};

/**
 * Create callback cookies in a version-agnostic way
 */
export const createCallbackCookies = (
  values,
  customTxnCookieName = 'auth_verification',
) => {
  return {
    [customTxnCookieName]: JSON.stringify(values),
  };
};

/**
 * Setup callback test expectations without coupling to specific token shapes
 */
export const expectCallbackSuccess = (result, expectations = {}) => {
  const {
    hasUser = true,
    hasTokens = true,
    isAuthenticated = true,
    redirectStatus = 302,
    userClaims = {},
    tokenTypes = ['id'],
  } = expectations;

  // Basic response checks
  if (result.response.statusCode !== redirectStatus) {
    throw new Error(
      `Expected status ${redirectStatus}, got ${result.response.statusCode}`,
    );
  }

  // User checks
  if (hasUser && !result.currentUser) {
    throw new Error('Expected user to exist');
  }

  if (result.currentUser) {
    for (const [claim, expectedValue] of Object.entries(userClaims)) {
      if (result.currentUser[claim] !== expectedValue) {
        throw new Error(
          `Expected user.${claim} to be ${expectedValue}, got ${result.currentUser[claim]}`,
        );
      }
    }
  }

  // Token checks - focus on behavior, not structure
  if (hasTokens && !result.tokens) {
    throw new Error('Expected tokens to exist');
  }

  if (result.tokens) {
    if (isAuthenticated && !result.tokens.isAuthenticated) {
      throw new Error('Expected to be authenticated');
    }

    // Check for expected token types without checking exact structure
    for (const tokenType of tokenTypes) {
      const tokenKey = `${tokenType}Token`;
      if (!result.tokens[tokenKey] && !result.tokens[`${tokenType}_token`]) {
        throw new Error(`Expected ${tokenType} token to exist`);
      }
    }
  }
};

/**
 * Mock different callback scenarios
 */
export const mockCallbackScenario = (
  scenario = 'success',
  customOptions = {},
) => {
  const scenarios = {
    success: {
      cookies: { state: '__test_state__', nonce: '__test_nonce__' },
      body: { state: '__test_state__', id_token: '__test_id_token__' },
    },
    'code-flow': {
      cookies: { state: '__test_state__', nonce: '__test_nonce__' },
      body: {
        state: '__test_state__',
        code: 'test_code',
        id_token: '__test_id_token__',
      },
    },
    'state-mismatch': {
      cookies: { state: '__test_state__', nonce: '__test_nonce__' },
      body: { state: '__wrong_state__', id_token: '__test_id_token__' },
    },
    'missing-nonce': {
      cookies: { state: '__test_state__' },
      body: { state: '__test_state__', id_token: '__test_id_token__' },
    },
    'invalid-token': {
      cookies: { state: '__test_state__', nonce: '__test_nonce__' },
      body: { state: '__test_state__', id_token: '__invalid_token__' },
    },
  };

  const baseScenario = scenarios[scenario] || scenarios.success;

  return {
    cookies: { ...baseScenario.cookies, ...customOptions.cookies },
    body: { ...baseScenario.body, ...customOptions.body },
    authOpts: customOptions.authOpts || {},
  };
};

/**
 * Validate callback results without checking internal OIDC structures
 */
export const validateCallbackResult = (result, expectedOutcome) => {
  switch (expectedOutcome) {
    case 'success':
      expectCallbackSuccess(result);
      break;
    case 'error':
      if (result.response.statusCode < 400) {
        throw new Error('Expected callback to fail');
      }
      break;
    case 'redirect':
      if (result.response.statusCode !== 302) {
        throw new Error('Expected redirect');
      }
      break;
    default:
      throw new Error(`Unknown expected outcome: ${expectedOutcome}`);
  }
};
