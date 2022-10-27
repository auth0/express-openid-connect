module.exports = (config) => {
  const { getLogoutToken } = config;

  return async (req, res, next) => {
    if (!req.oidc.isAuthenticated()) {
      next();
      return;
    }
    try {
      const logoutToken = await getLogoutToken(
        req,
        config.backChannelLogoutStore,
        config
      );
      if (logoutToken) {
        const { iat: idTokenIat } = req.oidc.idTokenClaims;
        const {
          token: { iat: logoutTokenIat },
        } = logoutToken;
        // Only invalidate the session if the ID token was issued
        // before the logout token (in case the user logged in again
        // after they were logged out by the back-channel)
        if (idTokenIat <= logoutTokenIat) {
          req[config.session.name] = undefined;
        }
      }
      next();
    } catch (e) {
      next(e);
    }
  };
};
