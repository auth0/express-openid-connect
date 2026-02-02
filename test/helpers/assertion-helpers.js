import { assert } from 'chai';

/**
 * Behavior-focused assertion helpers that reduce coupling to OIDC internals
 */

/**
 * Assert authentication state without checking internal token structure
 */
export const assertAuthenticated = (req, expected = true) => {
  const isAuth = req.oidc && req.oidc.isAuthenticated();
  assert.equal(
    isAuth,
    expected,
    `Expected authentication state to be ${expected}`,
  );
};

/**
 * Assert user properties without checking exact token claims structure
 */
export const assertUserProperties = (user, expectedProps) => {
  if (!user) {
    throw new Error('Expected user to exist');
  }

  for (const [key, expectedValue] of Object.entries(expectedProps)) {
    assert.equal(
      user[key],
      expectedValue,
      `Expected user.${key} to be ${expectedValue}`,
    );
  }
};

/**
 * Assert session state without checking internal session structure
 */
export const assertSession = (session, checks = {}) => {
  const {
    exists = true,
    hasIdToken = true,
    hasAccessToken = false,
    hasRefreshToken = false,
  } = checks;

  if (exists) {
    assert.exists(session, 'Expected session to exist');

    if (hasIdToken) {
      assert.exists(
        session.id_token || session.idToken,
        'Expected session to have ID token',
      );
    }

    if (hasAccessToken) {
      assert.exists(
        session.access_token || session.accessToken,
        'Expected session to have access token',
      );
    }

    if (hasRefreshToken) {
      assert.exists(
        session.refresh_token || session.refreshToken,
        'Expected session to have refresh token',
      );
    }
  } else {
    assert.isEmpty(session || {}, 'Expected session to be empty');
  }
};

/**
 * Assert token behavior without checking specific token format
 */
export const assertTokenBehavior = (tokenResponse, expectedBehavior = {}) => {
  const {
    hasAccessToken = true,
    hasIdToken = true,
    hasRefreshToken = false,
    tokenType = 'Bearer',
    isExpired = false,
  } = expectedBehavior;

  if (hasAccessToken) {
    assert.exists(
      tokenResponse.accessToken || tokenResponse.access_token,
      'Expected access token',
    );
  }

  if (hasIdToken) {
    assert.exists(
      tokenResponse.idToken || tokenResponse.id_token,
      'Expected ID token',
    );
  }

  if (hasRefreshToken) {
    assert.exists(
      tokenResponse.refreshToken || tokenResponse.refresh_token,
      'Expected refresh token',
    );
  }

  if (tokenResponse.token_type) {
    assert.equal(
      tokenResponse.token_type,
      tokenType,
      `Expected token type to be ${tokenType}`,
    );
  }

  if (tokenResponse.accessTokenExpired !== undefined) {
    assert.equal(
      tokenResponse.accessTokenExpired,
      isExpired,
      `Expected token expiry state to be ${isExpired}`,
    );
  }
};

/**
 * Assert cookie behavior without checking exact cookie format
 */
export const assertCookieBehavior = (cookies, expectedBehavior = {}) => {
  const {
    hasSessionCookie = true,
    hasTransientCookie = false,
    cookieName = 'appSession',
  } = expectedBehavior;

  if (hasSessionCookie) {
    const sessionCookie = Array.isArray(cookies)
      ? cookies.find((c) => c.key === cookieName || c.name === cookieName)
      : cookies[cookieName];
    assert.exists(sessionCookie, `Expected ${cookieName} cookie to exist`);
  }

  if (hasTransientCookie) {
    const transientCookie = Array.isArray(cookies)
      ? cookies.find(
          (c) =>
            c.key === 'auth_verification' || c.name === 'auth_verification',
        )
      : cookies.auth_verification;
    assert.exists(transientCookie, 'Expected transient cookie to exist');
  }
};

/**
 * Assert redirect behavior without checking exact URLs
 */
export const assertRedirectBehavior = (response, expectedBehavior = {}) => {
  const {
    isRedirect = true,
    statusCode = 302,
    hasLocation = true,
    locationContains = null,
  } = expectedBehavior;

  if (isRedirect) {
    assert.equal(
      response.statusCode,
      statusCode,
      `Expected status code to be ${statusCode}`,
    );
  }

  if (hasLocation) {
    assert.exists(
      response.headers.location,
      'Expected location header to exist',
    );

    if (locationContains) {
      assert.include(
        response.headers.location,
        locationContains,
        `Expected location to contain ${locationContains}`,
      );
    }
  }
};

/**
 * Assert error behavior without checking exact error format
 */
export const assertErrorBehavior = (error, expectedBehavior = {}) => {
  const {
    hasMessage = true,
    messageContains = null,
    statusCode = null,
    errorType = null,
  } = expectedBehavior;

  if (hasMessage) {
    assert.exists(error.message, 'Expected error to have a message');

    if (messageContains) {
      assert.include(
        error.message,
        messageContains,
        `Expected error message to contain ${messageContains}`,
      );
    }
  }

  if (statusCode) {
    assert.equal(
      error.status || error.statusCode,
      statusCode,
      `Expected error status to be ${statusCode}`,
    );
  }

  if (errorType) {
    assert.equal(
      error.error || error.name,
      errorType,
      `Expected error type to be ${errorType}`,
    );
  }
};

/**
 * Assert callback behavior without checking internal flow details
 */
export const assertCallbackBehavior = (result, expectedBehavior = {}) => {
  const {
    isSuccessful = true,
    hasUser = true,
    hasTokens = true,
    isAuthenticated = true,
  } = expectedBehavior;

  if (isSuccessful) {
    assert.equal(
      result.response.statusCode,
      302,
      'Expected successful redirect',
    );
  }

  if (hasUser) {
    assert.exists(result.currentUser, 'Expected user to exist');
    if (result.currentUser) {
      assert.exists(result.currentUser.sub, 'Expected user to have sub claim');
    }
  }

  if (hasTokens) {
    assert.exists(result.tokens, 'Expected tokens to exist');
    assertTokenBehavior(result.tokens);
  }

  if (isAuthenticated) {
    assert.equal(
      result.tokens.isAuthenticated,
      true,
      'Expected to be authenticated',
    );
  }
};
