# FAQs

## I'm getting the warning "Using 'form_post' for response_mode may cause issues for you logging in over http" on localhost

If you use `form_post` response mode (the default for this library) you are relying on a cross-site POST request with cookies - these will only be sent if they specify `SameSite=None; Secure` properties.

If your server is running over `http`, your cookie will not be sent with the `Secure` attribute and, under the new SameSite behavior, will be blocked.

However, there is [an exception](<(https://www.chromestatus.com/feature/5088147346030592)>) for "Lax+POST" that Chrome makes for such cookies for the first 2 minutes after they are created. This means that your logins will work in Chrome over `http` as long as they take less than 2 minutes, longer logins will fail. This special exception will be phased out in future Chrome releases.

This should not be an issue on production, because your application will be running on `https`

To resolve this, you could [run your local development server over https](https://auth0.com/docs/libraries/secure-local-development) or use the [code flow](https://auth0.com/docs/flows/authorization-code-flow).
