const assert = require('chai').assert;
const expressOpenid = require('..');

describe('with an unsupported response type', function () {
  it('should return an error', async function () {
    assert.throws(() => {
      expressOpenid.auth({
        secret: '__test_session_secret__',
        clientID: '__test_client_id__',
        baseURL: 'https://example.org',
        issuerBaseURL: 'https://op.example.com',
        authorizationParams: {
          response_type: '__invalid_response_type__',
        },
      });
    }, '"authorizationParams.response_type" must be one of [id_token, code id_token, code]');
  });
});
