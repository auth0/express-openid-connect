# Examples

To run an example `npm run start:example -- "name of example"`. Eg to run the basic example at `./basic.js`:

```shell script
$ npm run start:example -- basic
```

To run the example against your authorization server add the following items to your `./examples/.env`

```shell script
# For the example app
PORT=3000
# For the auth config
ISSUER_BASE_URL=https://YOUR_DOMAIN
CLIENT_ID=YOUR_CLIENT_ID
BASE_URL=https://YOUR_APPLICATION_ROOT_URL
SECRET=LONG_RANDOM_VALUE
# For response_type values that include 'code'
CLIENT_SECRET=YOUR_CLIENT_SECRET
```

If you do not specify an env file, we will configure one for you and start a mock authorisation server. To login to this authorisation server, use any credentials, and the username will be reflected in the `sub` claim of the ID Token.
