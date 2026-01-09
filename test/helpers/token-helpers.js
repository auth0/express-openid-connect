import { makeIdToken, makeLogoutToken } from '../fixture/cert.js';

/**
 * Token helpers that abstract away version-specific token shapes
 */

/**
 * Create a test token set with consistent interface across OIDC versions
 */
export const createTestTokenSet = (overrides = {}) => {
  const defaults = {
    access_token: '__test_access_token__',
    refresh_token: '__test_refresh_token__',
    id_token: makeIdToken(),
    token_type: 'Bearer',
    expires_in: 3600,
    ...overrides,
  };

  return defaults;
};

/**
 * Assert token existence without checking exact shape
 */
export const assertTokenExists = (tokenSet, tokenType) => {
  const tokenKey = `${tokenType}_token`;
  if (!tokenSet || !tokenSet[tokenKey]) {
    throw new Error(`Expected ${tokenType} token to exist`);
  }
};

/**
 * Assert token properties without being tied to specific implementation
 */
export const assertTokenProperties = (token, expectedProperties) => {
  for (const [key, expectedValue] of Object.entries(expectedProperties)) {
    if (token[key] !== expectedValue) {
      throw new Error(
        `Expected token.${key} to be ${expectedValue}, got ${token[key]}`,
      );
    }
  }
};

/**
 * Create tokens for different test scenarios
 */
export const createTokensFor = {
  /**
   * Tokens for successful authentication flow
   */
  successfulAuth: (customClaims = {}) =>
    createTestTokenSet({
      id_token: makeIdToken({ ...customClaims }),
    }),

  /**
   * Tokens for refresh scenario
   */
  refreshFlow: (customClaims = {}) =>
    createTestTokenSet({
      id_token: makeIdToken({ ...customClaims }),
      refresh_token: '__test_refresh_token__',
    }),

  /**
   * Expired tokens for testing expiry handling
   */
  expiredTokens: (customClaims = {}) =>
    createTestTokenSet({
      id_token: makeIdToken({
        exp: Math.floor(Date.now() / 1000) - 3600,
        ...customClaims,
      }),
      expires_in: -1,
    }),

  /**
   * Tokens for logout scenarios
   */
  logoutScenario: (customClaims = {}) => ({
    logout_token: makeLogoutToken({ ...customClaims }),
  }),
};

/**
 * Version-agnostic token validation helpers
 */
export const validateToken = {
  /**
   * Validate that a token has required claims without checking exact structure
   */
  hasClaims: (token, requiredClaims) => {
    for (const claim of requiredClaims) {
      if (!(claim in token)) {
        throw new Error(`Token missing required claim: ${claim}`);
      }
    }
    return true;
  },

  /**
   * Validate token expiry behavior
   */
  isExpired: (token) => {
    const now = Math.floor(Date.now() / 1000);
    return token.exp && token.exp < now;
  },

  /**
   * Validate token type without being specific to v4/v6 differences
   */
  hasValidType: (tokenSet, expectedType = 'Bearer') => {
    return tokenSet.token_type === expectedType;
  },
};

/**
 * Extract claims from tokens in a version-agnostic way
 */
export const extractClaims = (idToken) => {
  if (typeof idToken === 'string') {
    try {
      // Basic JWT decoding for test purposes
      const payload = idToken.split('.')[1];
      return JSON.parse(Buffer.from(payload, 'base64').toString());
    } catch {
      return null;
    }
  }
  return idToken;
};

/**
 * Create mock token responses for different scenarios
 */
export const createTokenResponse = (scenario = 'default', customData = {}) => {
  const responses = {
    default: {
      access_token: '__test_access_token__',
      refresh_token: '__test_refresh_token__',
      id_token: makeIdToken(),
      token_type: 'Bearer',
      expires_in: 3600,
    },
    'code-flow': {
      access_token: '__test_access_token__',
      id_token: makeIdToken(),
      token_type: 'Bearer',
      expires_in: 3600,
    },
    refresh: {
      access_token: '__test_new_access_token__',
      id_token: makeIdToken(),
      refresh_token: '__test_refresh_token__',
      token_type: 'Bearer',
      expires_in: 3600,
    },
    expired: {
      access_token: '__test_access_token__',
      id_token: makeIdToken({ exp: Math.floor(Date.now() / 1000) - 3600 }),
      token_type: 'Bearer',
      expires_in: -1,
    },
  };

  return { ...responses[scenario], ...customData };
};
