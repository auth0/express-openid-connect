const selfsigned = require('selfsigned');
const { pem2jwk } = require('pem-jwk');

const attrs = [
  {
    name: 'commonName',
    value: 'flosser.auth0.com'
  }
];

const extensions = [{
  name: 'basicConstraints',
  cA: true,
  critical: true
}, {
  name: 'subjectKeyIdentifier'
}, {
  name: 'keyUsage',
  digitalSignature: true,
  keyCertSign: true,
  critical: true
}];


const ss = selfsigned.generate(attrs, {
  pkcs7: true,
  days: 5000,
  algorithm: 'sha256',
  extensions: extensions
});


module.exports.jwks = [{
  alg: 'RS256',
  kty: 'RSA',
  use: 'sig',
  kid: ss.fingerprint,
  x5t: ss.fingerprint,
  ...pem2jwk(ss.public)
}];

module.exports.cert = ss.cert;
module.exports.key = ss.private;
module.exports.kid = ss.fingerprint;
