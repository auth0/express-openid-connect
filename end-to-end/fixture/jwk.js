import { JWK } from 'jose';

const key = JWK.generateSync('RSA', 2048, {
  alg: 'RS256',
  kid: 'key-1',
  use: 'sig',
});

export const privateJWK = key.toJWK(true);
export const publicJWK = key.toJWK();
export const privatePEM = key.toPEM(true);
export const publicPEM = key.toPEM();
