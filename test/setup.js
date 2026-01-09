import sinon from 'sinon';
import { setupOIDCMocks, cleanupOIDCMocks } from './helpers/oidc-mocks.js';

let warn;

beforeEach(function () {
  warn = sinon.stub(global.console, 'warn');

  // Use centralized OIDC mocks, but exclude token endpoint since many tests need precise control
  setupOIDCMocks({
    includeAuth0: true,
    includeIntrospection: true,
    includeTokenEndpoint: false,
  });
});

afterEach(function () {
  cleanupOIDCMocks();
  warn.restore();
});
