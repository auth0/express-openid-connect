const safePromisify = require('../../utils/promisifyCompat');

// Default hook stores an entry in the logout store for `sid` (if available) and `sub` (if available).
module.exports = async (token, config) => {
  const {
    session: {
      absoluteDuration,
      rolling: rollingEnabled,
      rollingDuration,
      store,
    },
    backchannelLogout,
  } = config;
  const backchannelLogoutStore =
    (backchannelLogout && backchannelLogout.store) || store;
  const maxAge =
    (rollingEnabled
      ? Math.min(absoluteDuration, rollingDuration)
      : absoluteDuration) * 1000;
  const payload = {
    // The "cookie" prop makes the payload compatible with
    // `express-session` stores.
    cookie: {
      expires: Date.now() + maxAge,
      maxAge,
    },
  };
  const set = safePromisify(backchannelLogoutStore.set, backchannelLogoutStore);
  const { iss, sid, sub } = token;
  if (!sid && !sub) {
    throw new Error(`The Logout Token must have a 'sid' or a 'sub'`);
  }
  await Promise.all([
    sid && set(`${iss}|${sid}`, payload),
    sub && set(`${iss}|${sub}`, payload),
  ]);
};
