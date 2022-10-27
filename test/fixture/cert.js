const { JWK, JWKS, JWT } = require('jose');
const crypto = require('crypto');

const key = JWK.asKey({
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
});

module.exports.jwks = new JWKS.KeyStore(key).toJWKS(false);

module.exports.key = key.toPEM(true);
module.exports.kid = key.kid;

module.exports.makeIdToken = (payload) => {
  payload = Object.assign(
    {
      nickname: '__test_nickname__',
      sub: '__test_sub__',
      iss: 'https://op.example.com/',
      aud: '__test_client_id__',
      iat: Math.round(Date.now() / 1000),
      exp: Math.round(Date.now() / 1000) + 60000,
      nonce: '__test_nonce__',
    },
    payload
  );

  return JWT.sign(payload, key.toPEM(true), {
    algorithm: 'RS256',
    header: { kid: key.kid },
  });
};

module.exports.makeLogoutToken = ({ payload, sid, sub, secret } = {}) => {
  return JWT.sign(
    {
      events: {
        'http://schemas.openid.net/event/backchannel-logout': {},
      },
      ...(sid && { sid }),
      ...(sub && { sub }),
    },
    secret || key.toPEM(true),
    {
      issuer: 'https://op.example.com/',
      audience: '__test_client_id__',
      iat: true,
      jti: crypto.randomBytes(16).toString('hex'),
      algorithm: secret ? 'HS256' : 'RS256',
      header: { typ: 'logout+jwt' },
      ...payload,
    }
  );
};
