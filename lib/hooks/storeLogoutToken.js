const { promisify } = require('util');

module.exports = async (payload, store /*, config */) => {
  const set = promisify(store.set).bind(store);
  const { iss, sid } = payload.token;
  if (!sid) {
    throw new Error(
      `The default implementation of Back-Channel Logout requires an 'sid'`
    );
  }
  await set(`${iss}|${sid}`, payload);
};
