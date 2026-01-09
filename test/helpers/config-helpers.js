/**
 * Configuration helpers that reduce coupling to specific OIDC implementation details
 */

/**
 * Create base test configuration that works across OIDC versions
 */
export const createBaseConfig = (overrides = {}) => {
  return {
    clientID: '__test_client_id__',
    clientSecret: '__test_client_secret__',
    issuerBaseURL: 'https://op.example.com',
    baseURL: 'https://example.org',
    secret: '__test_session_secret__',
    authRequired: false,
    ...overrides,
  };
};

/**
 * Create configuration for different authentication flows
 */
export const createConfigFor = {
  /**
   * Authorization code flow (v6 default)
   */
  authorizationCode: (overrides = {}) =>
    createBaseConfig({
      authorizationParams: {
        response_type: 'code',
        scope: 'openid profile email',
      },
      ...overrides,
    }),

  /**
   * Hybrid flow configuration
   */
  hybrid: (overrides = {}) =>
    createBaseConfig({
      authorizationParams: {
        response_type: 'code id_token',
        scope: 'openid profile email',
      },
      ...overrides,
    }),

  /**
   * ID Token flow configuration
   */
  idToken: (overrides = {}) =>
    createBaseConfig({
      authorizationParams: {
        response_type: 'id_token',
        scope: 'openid profile email',
      },
      ...overrides,
    }),

  /**
   * Configuration with custom session handling
   */
  customSession: (sessionConfig = {}) =>
    createBaseConfig({
      session: {
        name: 'appSession',
        rolling: true,
        rollingDuration: 86400,
        ...sessionConfig,
      },
    }),

  /**
   * Configuration for back-channel logout testing
   */
  backChannelLogout: (logoutConfig = {}) =>
    createBaseConfig({
      backchannelLogout: {
        onLogoutToken: () => {},
        onLogin: () => {},
        ...logoutConfig,
      },
    }),

  /**
   * Auth0-specific configuration
   */
  auth0: (overrides = {}) =>
    createBaseConfig({
      issuerBaseURL: 'https://test.eu.auth0.com',
      authorizationParams: {
        scope: 'openid profile email',
      },
      ...overrides,
    }),

  /**
   * Configuration with API access
   */
  withApi: (audience = 'https://api.example.com/', overrides = {}) =>
    createBaseConfig({
      authorizationParams: {
        response_type: 'code id_token',
        audience,
        scope: 'openid profile email read:reports',
      },
      ...overrides,
    }),
};

/**
 * Configuration validation helpers that don't depend on specific OIDC version
 */
export const validateConfig = {
  /**
   * Ensure required configuration properties exist
   */
  hasRequired: (
    config,
    requiredProps = ['clientID', 'issuerBaseURL', 'baseURL', 'secret'],
  ) => {
    for (const prop of requiredProps) {
      if (!config[prop]) {
        throw new Error(`Configuration missing required property: ${prop}`);
      }
    }
    return true;
  },

  /**
   * Validate URL format without being specific to implementation
   */
  hasValidUrls: (config) => {
    const urlProps = ['issuerBaseURL', 'baseURL'];
    for (const prop of urlProps) {
      if (config[prop] && !config[prop].match(/^https?:\/\//)) {
        throw new Error(`Configuration property ${prop} must be a valid URL`);
      }
    }
    return true;
  },
};

/**
 * Create test-specific configurations
 */
export const getTestConfig = (scenario = 'default') => {
  const configs = {
    default: createBaseConfig(),
    callback: createConfigFor.authorizationCode(),
    login: createConfigFor.idToken(),
    logout: createBaseConfig({ idpLogout: true }),
    session: createConfigFor.customSession({ rolling: false }),
    auth0: createConfigFor.auth0(),
    api: createConfigFor.withApi(),
  };

  return configs[scenario] || configs.default;
};

/**
 * Merge configurations with proper handling of nested objects
 */
export const mergeConfigs = (base, override) => {
  const result = { ...base };

  for (const [key, value] of Object.entries(override)) {
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      result[key] = { ...result[key], ...value };
    } else {
      result[key] = value;
    }
  }

  return result;
};
