import * as jose from 'jose';

// Cache for generated keys
let keysCache = null;

// Generate key pair asynchronously
const generateKeys = async () => {
  if (keysCache) {
    return keysCache;
  }

  const { publicKey, privateKey } = await jose.generateKeyPair('RS256', {
    extractable: true,
  });

  const privateJWK = await jose.exportJWK(privateKey);
  const publicJWK = await jose.exportJWK(publicKey);

  // Add required fields
  privateJWK.alg = 'RS256';
  privateJWK.kid = 'key-1';
  privateJWK.use = 'sig';

  publicJWK.alg = 'RS256';
  publicJWK.kid = 'key-1';
  publicJWK.use = 'sig';

  const privatePEM = await jose.exportPKCS8(privateKey);
  const publicPEM = await jose.exportSPKI(publicKey);

  keysCache = { privateJWK, publicJWK, privatePEM, publicPEM };
  return keysCache;
};

// Export getters that generate keys on first access
export const getPrivateJWK = async () => {
  const keys = await generateKeys();
  return keys.privateJWK;
};

export const getPublicJWK = async () => {
  const keys = await generateKeys();
  return keys.publicJWK;
};

export const getPrivatePEM = async () => {
  const keys = await generateKeys();
  return keys.privatePEM;
};

export const getPublicPEM = async () => {
  const keys = await generateKeys();
  return keys.publicPEM;
};

// For backward compatibility, also export direct references
// These will be undefined initially but can be set after calling generate
export let privateJWK, publicJWK, privatePEM, publicPEM;
