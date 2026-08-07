import { Request } from 'express';
import { RequestHandler } from 'express';
import { expectType } from 'tsd';
import { auth } from '.';

expectType<RequestHandler>(auth());
expectType<RequestHandler>(auth({ session: { name: 'foo' } }));
expectType<RequestHandler>(auth({ session: { cookie: { secure: true } } }));
expectType<RequestHandler>(auth({ routes: { login: '' } }));

// JAR (JWT-Secured Authorization Requests)
expectType<RequestHandler>(
  auth({
    requestObjectSigningKey: '-----BEGIN PRIVATE KEY-----',
    requestObjectSigningAlg: 'RS256',
    requestObjectSigningKeyId: 'kid-1',
  }),
);

// Anonymous Sessions config
expectType<RequestHandler>(auth({ anonymousSession: { enabled: true } }));
expectType<RequestHandler>(
  auth({
    anonymousSession: {
      enabled: true,
      cookie: {
        name: 'auth0_anon',
        sameSite: 'Lax',
        secure: true,
        httpOnly: true,
        path: '/',
        domain: 'example.org',
      },
    },
  }),
);

// Anonymous Sessions request context
const req = {} as Request;
expectType<boolean | undefined>(req.anonymousSession?.isAnonymous);
expectType<string | null | undefined>(req.anonymousSession?.token);
expectType<string | undefined>(
  (await req.anonymousSession?.getAccessToken())?.access_token,
);
expectType<string | undefined>(
  (
    await req.anonymousSession?.start({
      audience: 'https://api.example.com',
      scope: 'read:cart',
      metadata: { cart_id: 'cart_123' },
    })
  )?.access_token,
);
expectType<void | undefined>(await req.anonymousSession?.end());
