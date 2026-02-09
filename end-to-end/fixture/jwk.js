const { JWK } = require('jose');

const key = JWK.generateSync('RSA', 2048, {
  alg: 'RS256',
  kid: 'key-1',
  use: 'sig',
});

module.exports.privateJWK = key.toJWK(true);
module.exports.publicJWK = key.toJWK();
module.exports.privatePEM = key.toPEM(true);
module.exports.publicPEM = key.toPEM();
