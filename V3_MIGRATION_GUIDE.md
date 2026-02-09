# V3 Migration Guide

`v3.x` upgrades the underlying OpenID Connect and JWT dependencies (`openid-client` v4 → v6, `jose` v2 → v6) to their latest major versions, bringing improved security, performance, and standards compliance.

**Important:** While this is a major version bump for the library, **there are ZERO breaking changes to the public API**. Your application code does not need to change.

---

**Public API:** No breaking changes - all configuration, middleware, and context APIs work exactly the same  
**Node.js Version:** Now requires `^20.19.0 || ^22.12.0 || >= 23.0.0` (previously Node.js 14+)  
**Module Support:** Works with BOTH CommonJS and ESM apps

---

## Breaking Changes

### Node.js Version Requirement

**The only breaking change is the specific Node.js version requirement.**

| Version | Minimum Node.js                         | Status  |
| ------- | --------------------------------------- | ------- |
| v2.x    | Node.js 14+                             | Old     |
| v3.x    | `^20.19.0 \|\| ^22.12.0 \|\| >= 23.0.0` | **New** |

#### Why These Specific Versions?

The updated dependencies (`openid-client` v6 and `jose` v6) are **ESM-only packages**.

Node.js added `require(ESM)` support in:

- **v20.19.0** (backported to v20.x LTS)
- **v22.12.0** (backported to v22.x LTS)
- **v23.0.0+** (included by default)

There is **no workaround** - you must upgrade to a supported Node.js version.

#### Module System Support

**Works with BOTH CommonJS and ESM apps** - same Node.js requirements for both:

```javascript
// CommonJS - Works on supported Node.js versions
const { auth } = require('express-openid-connect');

// ESM - Works on supported Node.js versions
import { auth } from 'express-openid-connect';
```

**Note:** ESM apps need `"type": "module"` in `package.json` but have identical Node.js version requirements as CommonJS apps.

### Configuration

All configuration options work exactly as before. No changes needed.

```js
const { auth } = require('express-openid-connect');

// This configuration works EXACTLY the same in v3.x
app.use(
  auth({
    authRequired: false,
    auth0Logout: true,
    baseURL: 'https://example.com',
    clientID: 'YOUR_CLIENT_ID',
    issuerBaseURL: 'https://YOUR_DOMAIN',
    secret: 'LONG_RANDOM_STRING',

    // All these options still work
    idpLogout: true,
    idTokenSigningAlg: 'RS256',
    clientAuthMethod: 'client_secret_post',
    pushedAuthorizationRequests: true,
    // ... etc
  }),
);
```

### Middleware

All middleware functions work identically.

```js
const { auth, requiresAuth } = require('express-openid-connect');

// All these work EXACTLY the same
app.use(auth(config));
app.get('/admin', requiresAuth(), (req, res) => {
  res.send('Admin page');
});
```

### Request Context (req.oidc)

The entire `req.oidc` API remains unchanged.

```js
// Before (v2.x)
app.get('/profile', async (req, res) => {
  const user = req.oidc.user;
  const claims = req.oidc.idTokenClaims;
  const isAuthenticated = req.oidc.isAuthenticated();
  const idToken = req.oidc.idToken;
  const accessToken = req.oidc.accessToken;
  const refreshToken = req.oidc.refreshToken;
  const userInfo = await req.oidc.fetchUserInfo();

  res.oidc.login({});
  res.oidc.logout({});
});

// After (v3.x) - SAME
app.get('/profile', async (req, res) => {
  const user = req.oidc.user;
  const claims = req.oidc.idTokenClaims;
  const isAuthenticated = req.oidc.isAuthenticated();
  const idToken = req.oidc.idToken;
  const accessToken = req.oidc.accessToken;
  const refreshToken = req.oidc.refreshToken;
  const userInfo = await req.oidc.fetchUserInfo();

  res.oidc.login({});
  res.oidc.logout({});
});
```

### Routes

Custom route configuration remains unchanged.

```js
// This works the same in v3.x
app.use(
  auth({
    routes: {
      login: '/custom/login',
      logout: '/custom/logout',
      callback: '/custom/callback',
      postLogoutRedirect: '/custom/post-logout',
    },
  }),
);
```

### Session Handling

Session configuration, custom stores, and lifecycle hooks all work the same.

```js
// Session configuration - UNCHANGED
app.use(
  auth({
    session: {
      rolling: true,
      rollingDuration: 86400,
      absoluteDuration: 86400 * 7,
      store: customStore, // Custom session stores still work
    },
  }),
);
```

### Authentication Methods

All client authentication methods continue to work:

```js
// All these still work in v3.x
const config = {
  clientAuthMethod: 'client_secret_basic',
  clientAuthMethod: 'client_secret_post',
  clientAuthMethod: 'client_secret_jwt',
  clientAuthMethod: 'private_key_jwt',
  clientAuthMethod: 'none',
};
```

---

### Step 1: Check Your Node.js Version

```bash
node --version
```

**Required:** `v20.19.0+`, `v22.12.0+`, or `v23.0.0+`

If your version is older:

- **v20.0.0 - v20.18.0** → Upgrade to v20.19.0+
- **v22.0.0 - v22.11.0** → Upgrade to v22.12.0+
- **v18.x or earlier** → Upgrade to v22.12.0+ (recommended LTS)

### Step 2: Upgrade express-openid-connect
