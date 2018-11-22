const selfsigned = require('selfsigned');
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

function pemToCert(pem) {
  // if certificate doesn't have ---- begin cert --- just return the pem
  if (!/-----BEGIN CERTIFICATE-----/.test(pem.toString())) {
    return pem.toString();
  }

  var cert = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(pem.toString());
  if (cert.length > 0) {
    return cert[1].replace(/[\n|\r\n]/g, '');
  }

  return null;
}

module.exports.jwks = [{
  alg: 'RS256',
  kty: 'RSA',
  use: 'sig',
  x5c: [
    pemToCert(ss.cert)
  ]
}];

module.exports.key = ss.private;
