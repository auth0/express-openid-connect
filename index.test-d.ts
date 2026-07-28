import { RequestHandler } from 'express';
import { expectType, expectAssignable } from 'tsd';
import { auth, MtlsError, MtlsErrorCode } from '.';

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

// mTLS
expectType<RequestHandler>(
  auth({ useMtls: true, customFetch: (url, options) => fetch(url, options) }),
);

// mTLS error handling surface
expectType<'mtls_requires_custom_fetch'>(
  MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH,
);
expectType<'mtls_endpoint_aliases_missing'>(
  MtlsErrorCode.MTLS_ENDPOINT_ALIASES_MISSING,
);
expectType<'mtls_incompatible_client_auth'>(
  MtlsErrorCode.MTLS_INCOMPATIBLE_CLIENT_AUTH,
);
expectAssignable<Error>(new MtlsError('some_code', 'message'));
