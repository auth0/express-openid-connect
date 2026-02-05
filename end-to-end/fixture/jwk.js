const { generateKeyPair, exportJWK, exportPKCS8, exportSPKI } = require('jose');

let privateJWK;
let publicJWK;
let privatePEM;
let publicPEM;

const init = (async () => {
  const { privateKey, publicKey } = await generateKeyPair('RS256', {
    extractable: true,
  });

  const privateJwk = await exportJWK(privateKey);
  privateJwk.alg = 'RS256';
  privateJwk.kid = 'key-1';
  privateJwk.use = 'sig';

  const publicJwk = await exportJWK(publicKey);
  publicJwk.alg = 'RS256';
  publicJwk.kid = 'key-1';
  publicJwk.use = 'sig';

  privateJWK = privateJwk;
  publicJWK = publicJwk;
  privatePEM = await exportPKCS8(privateKey);
  publicPEM = await exportSPKI(publicKey);
})();

module.exports = {
  get privateJWK() {
    return privateJWK;
  },
  get publicJWK() {
    return publicJWK;
  },
  get privatePEM() {
    return privatePEM;
  },
  get publicPEM() {
    return publicPEM;
  },
  init,
};
