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
