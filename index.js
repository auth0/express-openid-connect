const ResponseMode = require('./lib/ResponseMode');
const routes = require('./middleware/routes');
const protect = require('./middleware/protect');

module.exports = {
  routes,
  protect,
  ResponseMode,
};
