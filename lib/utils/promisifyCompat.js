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

function safePromisify(method, context) {
  validateFunction(method);
  if (isAsync(method)) return method.bind(context);
  if (typeof method[promisify.custom] === 'function')
    return method[promisify.custom].bind(context);

  let src = '';
  try {
    src = Function.prototype.toString.call(method);
  } catch {
    // If we cannot obtain a source representation, return a conservative wrapper
    return arityPreservingWrapper(method, context);
  }
  if (!src) {
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
  const len = typeof method.length === 'number' ? method.length : 0;
  let wrapper;
  switch (len) {
    case 0:
      wrapper = function () {
        return invokeAndNormalize(method, context, arguments);
      };
      break;
    case 1:
      wrapper = function (a) {
        void a; // reference to satisfy lint
        return invokeAndNormalize(method, context, arguments);
      };
      break;
    case 2:
      wrapper = function (a, b) {
        void a;
        void b;
        return invokeAndNormalize(method, context, arguments);
      };
      break;
    case 3:
      wrapper = function (a, b, c) {
        void a;
        void b;
        void c;
        return invokeAndNormalize(method, context, arguments);
      };
      break;
    case 4:
      wrapper = function (a, b, c, d) {
        void a;
        void b;
        void c;
        void d;
        return invokeAndNormalize(method, context, arguments);
      };
      break;
    case 5:
      wrapper = function (a, b, c, d, e) {
        void a;
        void b;
        void c;
        void d;
        void e;
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
  return v && typeof v.then === 'function';
}

function extractParams(src) {
  src = String(src);
  // Arrow single param without parens: x => ... (ensure no type annotation present e.g. x: T)
  const singleArrow = src.match(/^\s*([A-Za-z_$][\w$]*)\s*=>/);
  if (singleArrow && !/^\s*function\b/.test(src)) return [singleArrow[1]];

  // Find outer parameter list manually to tolerate nested parentheses / default expressions.
  const firstParen = src.indexOf('(');
  if (firstParen === -1) return [];
  let i = firstParen + 1;
  let depth = 1;
  let inStr = false;
  let strQuote = '';
  let paramsSrc = '';
  while (i < src.length) {
    const ch = src[i];
    if (inStr) {
      if (ch === strQuote) {
        // Count preceding backslashes to determine if quote is escaped.
        let bs = 0;
        for (let k = i - 1; k >= 0 && src[k] === '\\'; k--) bs++;
        if (bs % 2 === 0) {
          inStr = false;
          strQuote = '';
        }
      }
      paramsSrc += ch;
      i++;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      inStr = true;
      strQuote = ch;
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
  for (let idx = 0; idx < raw.length; idx++) {
    const ch = raw[idx];
    if (inStr) {
      if (ch === q) {
        let bs = 0;
        for (let k = idx - 1; k >= 0 && raw[k] === '\\'; k--) bs++;
        if (bs % 2 === 0) {
          inStr = false;
          q = '';
        }
      }
      token += ch;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      inStr = true;
      q = ch;
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
  // Strip leading comments
  raw = raw
    .replace(/^\/\/.*$/, '')
    .replace(/^\/\*.*?\*\/\s*/s, '')
    .trim();
  if (!raw) return;
  raw = raw.replace(/^\.\.\./, '').trim();
  // Remove default value
  const eq = raw.indexOf('=');
  if (eq !== -1) raw = raw.slice(0, eq).trim();
  // Remove simple TypeScript type annotations (identifier: type)
  if (/^[A-Za-z_$][\w$]*\s*:\s*/.test(raw)) {
    raw = raw.replace(/:\s*.*$/, '').trim();
  }
  // Ignore destructured / member / complex patterns
  if (/[{[}.]/.test(raw)) return; // ignore destructured or member params for callback detection
  if (!IDENTIFIER_REGEX.test(raw)) return;
  list.push(raw);
}

module.exports = safePromisify;
