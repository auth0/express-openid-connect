const Debug = require('debug');

const levels = ['trace', 'debug', 'info', 'warn', 'error'];
const debug = {};

for (const level of levels) {
  Object.defineProperty(debug, level, {
    value: new Debug(`express-openid-connect:${level}`),
    enumerable: true,
  });
}

module.exports = debug;
