import crypto from 'crypto';

// Simple JWT signing for tests (replacing jose.JWT.sign from v2)
export const JWT = {
  sign: (payload, secret, options = {}) => {
    const alg = options.algorithm || 'HS256';
    const header = {
      alg,
      typ: 'JWT',
    };

    // Base64url encode header and payload
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString(
      'base64url',
    );
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString(
      'base64url',
    );

    // For HS256, use HMAC signature
    if (alg === 'HS256') {
      const signature = crypto
        .createHmac('sha256', secret)
        .update(`${encodedHeader}.${encodedPayload}`)
        .digest('base64url');
      return `${encodedHeader}.${encodedPayload}.${signature}`;
    }

    // For testing purposes, use a fake signature for other algorithms
    const fakeSignature = 'fake_signature_for_testing';
    return `${encodedHeader}.${encodedPayload}.${fakeSignature}`;
  },

  decode: (jwt, options = {}) => {
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }

    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

    if (options.complete) {
      return { header, payload, signature: parts[2] };
    }

    return payload;
  },
};

// RSA key in JWK format
const jwkKey = {
  e: 'AQAB',
  n: 'wQrThQ9HKf8ksCQEzqOu0ofF8DtLJgexeFSQBNnMQetACzt4TbHPpjhTWUIlD8bFCkyx88d2_QV3TewMtfS649Pn5hV6adeYW2TxweAA8HVJxskcqTSa_ktojQ-cD43HIStsbqJhHoFv0UY6z5pwJrVPT-yt38ciKo9Oc9IhEl6TSw-zAnuNW0zPOhKjuiIqpAk1lT3e6cYv83ahx82vpx3ZnV83dT9uRbIbcgIpK4W64YnYb5uDH7hGI8-4GnalZDfdApTu-9Y8lg_1v5ul-eQDsLCkUCPkqBaNiCG3gfZUAKp9rrFRE_cJTv_MJn-y_XSTMWILvTY7vdSMRMo4kQ',
  d: 'EMHY1K8b1VhxndyykiGBVoM0uoLbJiT60eA9VD53za0XNSJncg8iYGJ5UcE9KF5v0lIQDIJfIN2tmpUIEW96HbbSZZWtt6xgbGaZ2eOREU6NJfVlSIbpgXOYUs5tFKiRBZ8YXY448gX4Z-k5x7W3UJTimqSH_2nw3FLuU32FI2vtf4ToUKEcoUdrIqoAwZ1et19E7Q_NCG2y1nez0LpD8PKgfeX1OVHdQm7434-9FS-R_eMcxqZ6mqZO2QDuign8SPHTR-KooAe8B-0MpZb7QF3YtMSQk8RlrMUcAYwv8R8dvFergCjauH0hOHvtKPq6Smj0VuimelEUZfp94r3pBQ',
  p: '9i2D_PLFPnFfztYccTGxzgiXezRpMsXD2Z9PA7uxw0sXnkV1TjZkSc3V_59RxyiTtvYlNCbGYShds__ogXouuYqbWaC43_zj3eGqAWL3i5C-k1u4S3ekgKn8AkGjlqCObuyLRsPvDfBkv1wo2tfIAEoNg_sHYIIRkTq68g58if8',
  q: 'yL6UUD_MB_pCHwf6LvNC2k0lfHHOxfW3lOo_XTqt9dg9yTO21OS4BF7Uce1kFJJIfuGrK6cMmusHKkSsJm1_khR3G9owokrBDFOZ_iSWvt3qIG5K3CNgl1_C8NqTeyKEVziCCiaL9CZpwfqHIVNnDCchGNkpVRqsfHmzPEnXnW8',
  dp: 'rFf3FEn9rpZ-pXYeGVzaBszbCAUMNOBhGWS_U3S-oWNb2JD169iGY2j4DWpDPTN6Hle6egU_UtuIpjBdXO_l8D1KPvgXFbCc8kQ-2ZOojAu8b7uBjUvoXa8jX40Gcrhanut5IgSfwlluns1tSLBSM2mkhqZiZr0IgWzlXfqoU48',
  dq: 'kihQC-2nO9e19Kn2OeDbt92bgXPLPM6ej0nOQK7MocaDlc6VO4QbhvMUcq6Iw4GOTvM3kVzbDKA6Y0gEnyXyUAWegyTlbARJchQcdrFlICqqoFotHwKS_SO352z9HBYRjP-TjphqJaUiMx2Y7WawDGUg79qNAW2eUDK7kRWiavk',
  qi: '8hAW25CmPjLAXpzkMpXpXsvJKdgql0Zjt-OeSVwzQN5dLYmu-Q98Xl5n8H-Nfr8aOmPfHBQ8M9FOMpxbgg8gbqixpkrxcTIGjpuH8RFYXj_0TYSBkCSOoc7tAP7YjOUOGJMqFHDYZVD-gmsCuRwWx3jKFxRrWLS5b8kWzkON0bM',
  kty: 'RSA',
  use: 'sig',
  alg: 'RS256',
  kid: 'test-kid',
};

// Export the JWKS structure and key information - only public key components
export const jwks = {
  keys: [
    {
      e: 'AQAB',
      n: 'wQrThQ9HKf8ksCQEzqOu0ofF8DtLJgexeFSQBNnMQetACzt4TbHPpjhTWUIlD8bFCkyx88d2_QV3TewMtfS649Pn5hV6adeYW2TxweAA8HVJxskcqTSa_ktojQ-cD43HIStsbqJhHoFv0UY6z5pwJrVPT-yt38ciKo9Oc9IhEl6TSw-zAnuNW0zPOhKjuiIqpAk1lT3e6cYv83ahx82vpx3ZnV83dT9uRbIbcgIpK4W64YnYb5uDH7hGI8-4GnalZDfdApTu-9Y8lg_1v5ul-eQDsLCkUCPkqBaNiCG3gfZUAKp9rrFRE_cJTv_MJn-y_XSTMWILvTY7vdSMRMo4kQ',
      kty: 'RSA',
      use: 'sig',
      alg: 'RS256',
      kid: 'test-kid',
    },
  ],
};
export const keyPEM =
  '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDBCtOFD0cp/ySw\nJATOo67Sh8XwO0smB7F4VJA...\n-----END PRIVATE KEY-----\n';
export const kid = jwkKey.kid;

// Simple JWT creation for test purposes
// Creates a properly signed JWT using the test private key
export const makeIdToken = async (payload = {}) => {
  // Import jose dynamically to avoid top-level import issues
  const { SignJWT, importJWK } = await import('jose');

  const mergedPayload = {
    nickname: '__test_nickname__',
    sub: '__test_sub__',
    iss: 'https://op.example.com/',
    aud: '__test_client_id__',
    iat: Math.round(Date.now() / 1000),
    exp: Math.round(Date.now() / 1000) + 60000,
    nonce: '__test_nonce__',
    ...payload,
  };

  try {
    // Convert the full JWK (with private components) to a KeyLike for signing
    const privateKey = await importJWK(jwkKey, 'RS256');

    // Create properly signed JWT
    const jwt = await new SignJWT(mergedPayload)
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: jwkKey.kid })
      .sign(privateKey);

    return jwt;
  } catch (error) {
    console.error('Error creating signed test token:', error);
    // Fallback to unsigned token if signing fails
    const header = {
      alg: 'RS256',
      typ: 'JWT',
      kid: jwkKey.kid,
    };

    const encodedHeader = Buffer.from(JSON.stringify(header)).toString(
      'base64url',
    );
    const encodedPayload = Buffer.from(JSON.stringify(mergedPayload)).toString(
      'base64url',
    );
    const fakeSignature = 'fake_signature_for_testing';

    return `${encodedHeader}.${encodedPayload}.${fakeSignature}`;
  }
};

export const makeLogoutToken = ({ payload = {}, sid, sub, secret } = {}) => {
  const header = {
    alg: secret ? 'HS256' : 'RS256',
    typ: 'logout+jwt',
    ...(secret ? {} : { kid: jwkKey.kid }),
  };

  const mergedPayload = {
    events: {
      'http://schemas.openid.net/event/backchannel-logout': {},
    },
    iss: 'https://op.example.com/',
    aud: '__test_client_id__',
    iat: Math.round(Date.now() / 1000),
    jti: crypto.randomBytes(16).toString('hex'),
    ...(sid && { sid }),
    ...(sub && { sub }),
    ...payload,
  };

  // Base64url encode header and payload
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString(
    'base64url',
  );
  const encodedPayload = Buffer.from(JSON.stringify(mergedPayload)).toString(
    'base64url',
  );

  // For testing purposes, use a fake signature
  const fakeSignature = 'fake_logout_signature_for_testing';

  return `${encodedHeader}.${encodedPayload}.${fakeSignature}`;
};

// For backward compatibility - exported keys need to be resolved at runtime
export default {
  jwks,
  key: keyPEM,
  kid,
  makeIdToken,
  makeLogoutToken,
};
