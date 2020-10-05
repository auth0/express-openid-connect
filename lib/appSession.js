const { strict: assert, AssertionError } = require('assert');
const {
  JWK,
  JWKS,
  JWE,
  errors: { JOSEError },
} = require('jose');
const onHeaders = require('on-headers');
const cookie = require('cookie');
const COOKIES = require('./cookies');
const { encryption: deriveKey } = require('./hkdf');
const debug = require('./debug')('appSession');

const epoch = () => (Date.now() / 1000) | 0;
const CHUNK_BYTE_SIZE = 4000;

function attachSessionObject(sessionStore, sessionName, value) {
  Object.defineProperty(sessionStore, sessionName, {
    enumerable: true,
    get() {
      return value;
    },
    set(arg) {
      if (arg === null || arg === undefined) {
        value = arg;
      } else {
        throw new TypeError('session object cannot be reassigned');
      }
      return undefined;
    },
  });
}

const appSession = (config) => {
  let current;

  const alg = 'dir';
  const enc = 'A256GCM';
  const secrets = Array.isArray(config.secret)
    ? config.secret
    : [config.secret];
  const sessionName = config.session.name;
  const cookieConfig = config.session.cookie;
  const {
    absoluteDuration,
    rolling: rollingEnabled,
    rollingDuration,
  } = config.session;

  let keystore = new JWKS.KeyStore();

  secrets.forEach((secretString, i) => {
    const key = JWK.asKey(deriveKey(secretString));
    if (i === 0) {
      current = key;
    }
    keystore.add(key);
  });

  if (keystore.size === 1) {
    keystore = current;
  }

  function encrypt(payload, headers) {
    return JWE.encrypt(payload, current, { alg, enc, ...headers });
  }

  function decrypt(jwe) {
    return JWE.decrypt(jwe, keystore, {
      complete: true,
      contentEncryptionAlgorithms: [enc],
      keyManagementAlgorithms: [alg],
    });
  }

  function calculateExp(iat, uat) {
    if (!rollingEnabled) {
      return iat + absoluteDuration;
    }

    return Math.min(
      ...[uat + rollingDuration, iat + absoluteDuration].filter(Boolean)
    );
  }

  function setCookie(
    { uat = epoch(), iat = uat, exp = calculateExp(iat, uat) },
    sessionStore,
    cookieStore,
    cookies,
    isSecure
  ) {
    const cookieOptions = {
      ...cookieConfig,
      expires: cookieConfig.transient ? 0 : new Date(exp * 1000),
      secure:
        typeof cookieConfig.secure === 'boolean'
          ? cookieConfig.secure
          : isSecure,
    };
    delete cookieOptions.transient;

    // session was deleted or is empty, this matches all session cookies (chunked or unchunked)
    // and clears them, essentially cleaning up what we've set in the past that is now trash
    if (
      !sessionStore[sessionName] ||
      !Object.keys(sessionStore[sessionName]).length
    ) {
      debug(
        'session was deleted or is empty, clearing all matching session cookies'
      );
      for (const cookieName of Object.keys(cookieStore)) {
        if (cookieName.match(`^${sessionName}(?:\\.\\d)?$`)) {
          cookies.clear(cookieName, {
            domain: cookieOptions.domain,
            path: cookieOptions.path,
          });
        }
      }
    } else {
      debug(
        'found session, creating signed session cookie(s) with name %o(.i)',
        sessionName
      );
      const value = encrypt(JSON.stringify(sessionStore[sessionName]), {
        iat,
        uat,
        exp,
      });

      const chunkCount = Math.ceil(value.length / CHUNK_BYTE_SIZE);
      if (chunkCount > 1) {
        debug('cookie size greater than %d, chunking', CHUNK_BYTE_SIZE);
        for (let i = 0; i < chunkCount; i++) {
          const chunkValue = value.slice(
            i * CHUNK_BYTE_SIZE,
            (i + 1) * CHUNK_BYTE_SIZE
          );
          const chunkCookieName = `${sessionName}.${i}`;
          cookies.set(chunkCookieName, chunkValue, cookieOptions);
        }
      } else {
        cookies.set(sessionName, value, cookieOptions);
      }
    }
  }

  return (res, sessionStore, cookieStore, cookies, isSecure, next) => {
    if (sessionStore.hasOwnProperty(sessionName)) {
      debug(
        'sessionStore already has %o property, this is indicative of a middleware setup problem',
        sessionName
      );
      return next(
        new Error(
          `sessionStore[${sessionName}] is already set, did you run this middleware twice?`
        )
      );
    }

    let iat;
    let uat;
    let exp;
    let existingSessionValue;

    try {
      if (cookieStore.hasOwnProperty(sessionName)) {
        // get JWE from unchunked session cookie
        debug('reading session from %s cookie', sessionName);
        existingSessionValue = cookieStore[sessionName];
      } else if (cookieStore.hasOwnProperty(`${sessionName}.0`)) {
        // get JWE from chunked session cookie
        // iterate all cookie names
        // match and filter for the ones that match sessionName.<number>
        // sort by chunk index
        // concat
        existingSessionValue = Object.entries(cookieStore)
          .map(([cookie, value]) => {
            const match = cookie.match(`^${sessionName}\\.(\\d+)$`);
            if (match) {
              return [match[1], value];
            }
          })
          .filter(Boolean)
          .sort(([a], [b]) => {
            return parseInt(a, 10) - parseInt(b, 10);
          })
          .map(([i, chunk]) => {
            debug('reading session chunk from %s.%d cookie', sessionName, i);
            return chunk;
          })
          .join('');
      }
      if (existingSessionValue) {
        const { protected: header, cleartext } = decrypt(existingSessionValue);
        ({ iat, uat, exp } = header);

        // check that the existing session isn't expired based on options when it was established
        assert(
          exp > epoch(),
          'it is expired based on options when it was established'
        );

        // check that the existing session isn't expired based on current rollingDuration rules
        if (rollingDuration) {
          assert(
            uat + rollingDuration > epoch(),
            'it is expired based on current rollingDuration rules'
          );
        }

        // check that the existing session isn't expired based on current absoluteDuration rules
        if (absoluteDuration) {
          assert(
            iat + absoluteDuration > epoch(),
            'it is expired based on current absoluteDuration rules'
          );
        }

        attachSessionObject(sessionStore, sessionName, JSON.parse(cleartext));
      }
    } catch (err) {
      if (err instanceof AssertionError) {
        debug('existing session was rejected because', err.message);
      } else if (err instanceof JOSEError) {
        debug(
          'existing session was rejected because it could not be decrypted',
          err
        );
      } else {
        debug('unexpected error handling session', err);
      }
    }

    if (
      !sessionStore.hasOwnProperty(sessionName) ||
      !sessionStore[sessionName]
    ) {
      attachSessionObject(sessionStore, sessionName, {});
    }

    onHeaders(
      res,
      setCookie.bind(
        undefined,
        { iat },
        sessionStore,
        cookieStore,
        cookies,
        isSecure
      )
    );

    return next();
  };
};

const expressAppSession = (config) => {
  return (req, res, next) => {
    const sessionStore = req;
    const cookieStore = cookie.parse(req.get('cookie') || '');
    const cookies = {
      set: res.cookie.bind(res),
      clear: res.clearCookie.bind(res),
    };

    req[COOKIES] = cookieStore;

    appSession(config)(
      res,
      sessionStore,
      cookieStore,
      cookies,
      req.secure,
      (error) => next(error)
    );
  };
};

module.exports = expressAppSession;
