import auth from './middleware/auth.js';
import * as requiresAuthExports from './middleware/requiresAuth.js';
import attemptSilentLogin from './middleware/attemptSilentLogin.js';

const { requiresAuth, claimEquals, claimIncludes, claimCheck } =
  requiresAuthExports;

export default {
  auth,
  requiresAuth,
  claimEquals,
  claimIncludes,
  claimCheck,
  attemptSilentLogin,
};

export {
  auth,
  attemptSilentLogin,
  requiresAuth,
  claimEquals,
  claimIncludes,
  claimCheck,
};
