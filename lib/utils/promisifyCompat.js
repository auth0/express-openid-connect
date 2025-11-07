const { promisify } = require('util');

// Non-invasive promisification: avoids dummy invocations that can mutate stores.
// Callback tokens are limited to common conventional names.
const CALLBACK_TOKENS = new Set([
  'cb',
  'callback',
  'done',
  'next',
  'fn',
  'finish',
  'complete',
  'errback',
  'doneCallback',
  'cbk',
]);

// Unicode identifier support (fallback to ASCII if engine lacks \p properties)
let IDENTIFIER_REGEX = /^[$A-Za-z_][\w$]*$/; // fallback
try {
  // ID_Start + ID_Continue per ECMAScript spec (exclude \u200C \u200D here for simplicity)
  IDENTIFIER_REGEX = new RegExp(
    '^(?:[$A-Za-z_]|\\p{ID_Start})(?:[$0-9A-Za-z_]|\\p{ID_Continue})*$',
    'u',
  );
} catch {
  /* older engine without unicode property escapes */
}

const MAX_SOURCE_LENGTH = 100000; // Prevent ReDoS with pathologically long sources
const MAX_PARSE_LENGTH = 50000; // Bail out for suspiciously long function signatures

/**
 * Safe promisification with multiple detection strategies (in precedence order):
 * 1. Async functions → bind directly (already return promises)
 * 2. Functions with util.promisify.custom → use custom implementation
 * 3. Native functions → bind directly (cannot inspect source)
 * 4. Callback-style (last param matches CALLBACK_TOKENS) → util.promisify
 * 5. Promise/sync functions → arity-preserving wrapper (detects thenable returns)
 */
function safePromisify(method, context) {
  validateFunction(method);
  if (isAsync(method)) return method.bind(context);
  if (typeof method[promisify.custom] === 'function')
    return method[promisify.custom].bind(context);

  let src = '';
  try {
    src = Function.prototype.toString.call(method);
  } catch {
    // Cannot obtain source (e.g., Proxy, cross-realm functions, or redefined toString)
    // Fallback to safe wrapper that handles both sync and promise-returning methods
    return arityPreservingWrapper(method, context);
  }
  if (!src) {
    return arityPreservingWrapper(method, context);
  }
  // Prevent ReDoS: bail out early for extremely long sources
  if (src.length > MAX_SOURCE_LENGTH) {
    return arityPreservingWrapper(method, context);
  }
  const isNative = /\[native code\]/.test(src);
  if (isNative) return method.bind(context);

  const params = extractParams(src);
  // Explicitly handle parameterless functions: they are not callback style.
  if (params.length === 0) {
    return arityPreservingWrapper(method, context);
  }
  const last = params[params.length - 1];
  const isCallbackStyle = last && CALLBACK_TOKENS.has(last);
  if (isCallbackStyle) return promisify(method).bind(context);

  // Fallback wrapper: supports sync or promise-returning methods without probing.
  return arityPreservingWrapper(method, context);
}

function arityPreservingWrapper(method, context) {
  // Preserve arity (.length) by generating a wrapper with the same formal parameter count.
  // Parameters are intentionally unused as we forward the actual arguments object.
  const len =
    typeof method.length === 'number' &&
    method.length >= 0 &&
    method.length < 100
      ? Math.floor(method.length)
      : 0;
  let wrapper;
  switch (len) {
    case 0:
      wrapper = function () {
        return invokeAndNormalize(method, context, arguments);
      };
      break;
    case 1:
      // eslint-disable-next-line no-unused-vars
      wrapper = function (_a) {
        return invokeAndNormalize(method, context, arguments);
      };
      break;
    case 2:
      // eslint-disable-next-line no-unused-vars
      wrapper = function (_a, _b) {
        return invokeAndNormalize(method, context, arguments);
      };
      break;
    case 3:
      // eslint-disable-next-line no-unused-vars
      wrapper = function (_a, _b, _c) {
        return invokeAndNormalize(method, context, arguments);
      };
      break;
    case 4:
      // eslint-disable-next-line no-unused-vars
      wrapper = function (_a, _b, _c, _d) {
        return invokeAndNormalize(method, context, arguments);
      };
      break;
    case 5:
      // eslint-disable-next-line no-unused-vars
      wrapper = function (_a, _b, _c, _d, _e) {
        return invokeAndNormalize(method, context, arguments);
      };
      break;
    default:
      wrapper = function (...args) {
        return invokeAndNormalize(method, context, args);
      };
      break;
  }
  Object.defineProperty(wrapper, 'name', {
    value: `promisified_${method.name || 'anonymous'}`,
    configurable: true,
  });
  return wrapper;
}

function invokeAndNormalize(method, context, argsLike) {
  // We do NOT attempt to infer callback expectation from throws; legitimate sync errors are propagated as promise rejections.
  // Note: argsLike is an arguments object (array-like). Function.apply accepts array-like objects for performance.
  try {
    const result = method.apply(context, argsLike);
    return isThenable(result) ? result : Promise.resolve(result);
  } catch (e) {
    return Promise.reject(e);
  }
}

function validateFunction(fn) {
  if (typeof fn !== 'function')
    throw new TypeError('Expected method to be a function');
}
function isAsync(fn) {
  return (
    typeof fn === 'function' &&
    fn.constructor &&
    fn.constructor.name === 'AsyncFunction'
  );
}
function isThenable(v) {
  // Duck-typing for thenable (any object with a .then function)
  // Intentionally permissive to support various Promise implementations
  return v && typeof v.then === 'function';
}

function extractParams(src) {
  src = String(src);
  // Bail out for suspiciously long function signatures to prevent performance issues
  if (src.length > MAX_PARSE_LENGTH) return [];

  // Arrow single param without parens: x => ... (ensure no type annotation present e.g. x: T)
  // More restrictive pattern to prevent catastrophic backtracking
  const singleArrow = src.match(
    /^\s{0,100}([A-Za-z_$][\w$]{0,100})\s{0,100}=>/,
  );
  if (singleArrow && !/^\s*function\b/.test(src)) return [singleArrow[1]];

  // Find outer parameter list manually to tolerate nested parentheses / default expressions.
  const firstParen = src.indexOf('(');
  if (firstParen === -1) return [];
  let i = firstParen + 1;
  let depth = 1;
  let inStr = false;
  let strQuote = '';
  let escaped = false; // Track escape state for efficient string parsing
  let paramsSrc = '';
  while (i < src.length) {
    const ch = src[i];
    if (inStr) {
      if (ch === strQuote && !escaped) {
        inStr = false;
        strQuote = '';
      }
      escaped = !escaped && ch === '\\';
      paramsSrc += ch;
      i++;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      inStr = true;
      strQuote = ch;
      escaped = false;
      paramsSrc += ch;
      i++;
      continue;
    }
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) {
        break;
      }
    }
    paramsSrc += ch;
    i++;
  }
  const raw = paramsSrc.trim();
  if (!raw) return [];
  // Split respecting nested structures, strings etc.
  const parts = [];
  let token = '';
  let depthBrace = 0,
    depthBracket = 0,
    depthParen = 0;
  inStr = false;
  let q = '';
  escaped = false;
  for (let idx = 0; idx < raw.length; idx++) {
    const ch = raw[idx];
    if (inStr) {
      if (ch === q && !escaped) {
        inStr = false;
        q = '';
      }
      escaped = !escaped && ch === '\\';
      token += ch;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      inStr = true;
      q = ch;
      escaped = false;
      token += ch;
      continue;
    }
    switch (ch) {
      case '{':
        depthBrace++;
        break;
      case '}':
        depthBrace--;
        break;
      case '[':
        depthBracket++;
        break;
      case ']':
        depthBracket--;
        break;
      case '(':
        depthParen++;
        break;
      case ')':
        depthParen--;
        break;
      case ',':
        if (depthBrace === 0 && depthBracket === 0 && depthParen === 0) {
          pushParam(parts, token);
          token = '';
          continue;
        }
        break;
    }
    token += ch;
  }
  pushParam(parts, token);
  return parts;
}
function pushParam(list, raw) {
  raw = raw.trim();
  if (!raw) return;
  // Strip leading comments (multi-line comments only; single-line comments unlikely in param lists)
  raw = raw.replace(/^\/\*.*?\*\/\s*/s, '').trim();
  if (!raw) return;
  raw = raw.replace(/^\.\.\./, '').trim();
  // Remove default value
  const eq = raw.indexOf('=');
  if (eq !== -1) raw = raw.slice(0, eq).trim();
  // Remove simple TypeScript type annotations (identifier: type)
  // More precise pattern that stops at = if present
  if (/^[A-Za-z_$][\w$]*\s*:\s*/.test(raw)) {
    raw = raw.replace(/:\s*[^=]+/, '').trim();
  }
  // Ignore destructured / member / complex patterns
  // Fixed regex: properly escaped brackets - checks for {, [, ], }, or .
  if (/[{[]}.]/.test(raw)) return; // ignore destructured or member params for callback detection
  if (!IDENTIFIER_REGEX.test(raw)) return;
  list.push(raw);
}

module.exports = safePromisify;
