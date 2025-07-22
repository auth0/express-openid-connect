# FAQs

## I'm getting the warning "Using 'form_post' for response_mode may cause issues for you logging in over http" on localhost

If you use `form_post` response mode (the default for this library) you are relying on a cross-site POST request with cookies - these will only be attached to the POST request if they were set with `SameSite=None; Secure` properties.

If your server is running over `http:` protocol, your cookie with the `Secure` property will not be attached under current browser SameSite behavior.

However, there is [an exception](<(https://www.chromestatus.com/feature/5088147346030592)>) for "Lax+POST" that Chrome makes for such cookies for the first 2 minutes after they are stored. This means that your login requests will work in Chrome over `http` as long as the end-user takes less than 2 minutes to authenticate, otherwise it will fail. This special exception will be phased out in future Chrome releases.

This should not be an issue in production, because your application will be running over `https`

To resolve this, you should [run your local development server over https](https://auth0.com/docs/libraries/secure-local-development).

## Login calls are failing with 'RequestError: The "listener" argument must be of type function. Received an instance of Object'

This module depends indirectly on a newer version of the `agent-base` module. If an unrelated module depends on a version of the `agent-base` older than 5.0, that older dependency is monkeypatching the global `http.request` object, causing this module to fail. You can check if you have this problem by running this check:

```
npm list agent-base
```

The solution is to upgrade the other dependencies which depend on `agent-base` to at least version 5 to resolve the issue.
