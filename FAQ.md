# FAQs

## I'm getting the warning "Using 'form_post' for response_mode may cause issues for you logging in over http" on localhost

If you use `form_post` response mode (the default for this library) you are relying on a cross-site POST request with cookies - these will only be attached to the POST request if they were set with `SameSite=None; Secure` properties.

If your server is running over `http:` protocol, your cookie with the `Secure` property will not be attached under current browser SameSite behavior.

However, there is [an exception](<(https://www.chromestatus.com/feature/5088147346030592)>) for "Lax+POST" that Chrome makes for such cookies for the first 2 minutes after they are stored. This means that your login requests will work in Chrome over `http` as long as the end-user takes less than 2 minutes to authenticate, otherwise it will fail. This special exception will be phased out in future Chrome releases.

This should not be an issue in production, because your application will be running over `https`

To resolve this, you should [run your local development server over https](https://auth0.com/docs/libraries/secure-local-development).

## I'm getting `"auth_verification" cookie not found` — login fails intermittently or only on certain browsers

This error means the SDK's transaction cookie was absent when the OAuth callback was processed. The transaction cookie (`auth_verification` by default) is a short-lived, one-time-use cookie that the SDK sets at the start of every login flow and consumes at the callback. When it is missing, the SDK cannot verify the `state` and `nonce` values agreed upon at login.

There are four distinct root causes that produce this error. Identify which one applies to your setup:

### 1. The callback URL was opened directly without going through `/login` first

If a user (or a test script) navigates directly to `/callback?code=...&state=...` without first hitting the login route, the transaction cookie was never set.

**Fix:** Always initiate login through the SDK's `/login` route. Do not construct or bookmark callback URLs manually.

---

### 2. The app is running over HTTP, not HTTPS, and the browser dropped the cookie

The transaction cookie is set with `SameSite=None; Secure` because the OAuth callback is a cross-site redirect from your Identity Provider back to your app. Browsers require the `Secure` flag to honour `SameSite=None`, and `Secure` cookies are only sent over HTTPS. On an HTTP origin the browser silently discards the cookie before it is ever stored — so by the time the callback fires, there is nothing to read.

This could be the most common cause in **local development**.

**Fix:** Run your local server over HTTPS. See [Secure Local Development](https://auth0.com/docs/libraries/secure-local-development) for a step-by-step guide using a trusted local certificate.

Alternatively, for local development only, you can switch to `response_type: 'code'` with `response_mode: 'query'`, which allows the SDK to use `SameSite=Lax` instead of `SameSite=None`.

---

### 3. `legacySameSiteCookie` is set to `false` and the user's browser mishandles `SameSite=None`

By default, the SDK sets two cookies on every login: the primary `auth_verification` cookie (`SameSite=None; Secure`) for modern browsers, and a fallback `_auth_verification` cookie (no `SameSite` attribute) for older browsers that incorrectly treat `SameSite=None` as `SameSite=Strict` — notably Safari 12 and Chrome versions before 80.

When you opt out of this fallback by setting `legacySameSiteCookie: false`, users on those older browsers will have their primary cookie blocked on the cross-site return from the Identity Provider, with no fallback to recover from.

**Fix:** Leave `legacySameSiteCookie` at its default (`true`) unless you are certain your entire user base is on browsers that correctly implement `SameSite=None`.

---

### 4. Multiple apps on the same domain are overwriting each other's transaction cookie

This is the most subtle cause and the one most likely to appear intermittently in production. When two or more applications that use this SDK are hosted on the same domain with different paths (e.g. `example.com/app1` and `example.com/app2`), they share the same cookie namespace by default. If a user starts a login flow on App 1 and then starts one on App 2 before completing App 1's callback, App 2's `Set-Cookie: auth_verification=...` overwrites App 1's cookie in the browser. When App 1's callback eventually fires it finds the wrong cookie — or no cookie at all if App 2's callback already consumed it.

**Example of the collision:**

```
1. User starts login on App 1
   → Browser stores: auth_verification=<state1, nonce1>; Path=/

2. Before completing App 1's login, user starts login on App 2
   → Browser stores: auth_verification=<state2, nonce2>; Path=/
   → This overwrites App 1's cookie

3. App 1's IdP redirects to /callback?state=<state1>
   → Browser sends: auth_verification=<state2, nonce2>  ← wrong cookie
   → SDK finds state mismatch, or cookie was already consumed → error
```

**Fix:** Give each application a unique cookie name and a scoped cookie path so their cookies do not collide.

```js
// App 1 — mounted at /app1
app.use(
  '/app1',
  auth({
    baseURL: 'https://example.com/app1',
    session: {
      name: 'app1Session',
      cookie: { path: '/app1' },
    },
    transactionCookie: { name: 'app1_auth_verification' },
  }),
);

// App 2 — mounted at /app2
app.use(
  '/app2',
  auth({
    baseURL: 'https://example.com/app2',
    session: {
      name: 'app2Session',
      cookie: { path: '/app2' },
    },
    transactionCookie: { name: 'app2_auth_verification' },
  }),
);
```

Setting both `session.cookie.path` and `transactionCookie.name` is recommended. The path scopes the cookies so the browser only sends each app's cookie to requests under its own path, and the unique name ensures that even if the paths overlap, the cookies cannot silently overwrite each other.

---

## Login calls are failing with 'RequestError: The "listener" argument must be of type function. Received an instance of Object'

This module depends indirectly on a newer version of the `agent-base` module. If an unrelated module depends on a version of the `agent-base` older than 5.0, that older dependency is monkeypatching the global `http.request` object, causing this module to fail. You can check if you have this problem by running this check:

```
npm list agent-base
```

The solution is to upgrade the other dependencies which depend on `agent-base` to at least version 5 to resolve the issue.
