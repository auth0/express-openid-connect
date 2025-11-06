const { promisify } = require('util');

function safePromisify(method, context) {
  validateFunction(method);
  if (isAsync(method)) return method.bind(context);

  // Capture source once (may be native or minified). Avoid heavy parsing.
  let src;
  try {
    src = Function.prototype.toString.call(method);
  } catch {
    src = '';
  }
  const isNative = /\[native code\]/.test(src);

  // Extract parameter tokens (best-effort). If native, skip.
  const names = isNative ? [] : extractParamNames(src);
  const callbackTokens = new Set([
    'cb',
    'callback',
    'done',
    'next',
    'fn',
    'finish',
    'complete',
  ]);
  const last = names[names.length - 1];

  // Callback style only if any exact token matches; no arity assumption.
  const hasCallbackToken = names.some((n) => callbackTokens.has(n));
  const callbackStyle = !!last && hasCallbackToken;
  if (callbackStyle) return promisify(method).bind(context);

  // Fallback: normalize sync or promise-returning function without probing.
  const wrapper = function (...args) {
    try {
      const result = method.apply(context, args);
      return isThenable(result) ? result : Promise.resolve(result);
    } catch (e) {
      return Promise.reject(e);
    }
  };
  Object.defineProperty(wrapper, 'name', {
    value: `promisified_${method.name || 'anonymous'}`,
    configurable: true,
  });
  return wrapper;
}

function validateFunction(fn) {
  if (typeof fn !== 'function')
    throw new TypeError('Expected method to be a function');
}
function isAsync(fn) {
  return fn && fn.constructor && fn.constructor.name === 'AsyncFunction';
}
function isThenable(obj) {
  return obj && typeof obj.then === 'function';
}

function extractParamNames(src) {
  src = String(src);
  // Handle single-arg arrow without parens: x => ...
  const singleArrow = src.match(/^\s*([a-zA-Z_$][\w$]*)\s*=>/);
  if (singleArrow && !/^\s*function\b/.test(src)) return [singleArrow[1]];

  const match = src.match(/^[^(]*\(([^)]*)\)/);
  if (!match) return [];
  const rawParams = match[1];
  if (!rawParams.trim()) return [];

  const parts = [];
  let token = '';
  let depthBrace = 0,
    depthBracket = 0,
    depthParen = 0;
  let inString = false;
  let quote = '';
  for (let i = 0; i < rawParams.length; i++) {
    const ch = rawParams[i];
    if (inString) {
      // Close string if not escaped (odd backslashes before quote are treated as escape)
      if (ch === quote && !isEscaped(rawParams, i)) {
        inString = false;
        quote = '';
      }
      token += ch;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      inString = true;
      quote = ch;
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

function isEscaped(str, idx) {
  let backslashes = 0;
  for (let i = idx - 1; i >= 0 && str[i] === '\\'; i--) backslashes++;
  return backslashes % 2 === 1; // odd count means escaped
}

function pushParam(list, raw) {
  raw = raw.trim();
  if (!raw) return;
  // Remove rest token prefix
  raw = raw.replace(/^\.{3}/, '').trim();
  // Strip default value (non-greedy up to first '=')
  const eq = raw.indexOf('=');
  if (eq !== -1) raw = raw.slice(0, eq).trim();
  // Drop destructured patterns {..} or [..] entirely (not useful for callback detection)
  if (/^[{[]/.test(raw)) return;
  // Validate identifier form
  if (!/^[$A-Za-z_][\w$]*$/.test(raw)) return;
  list.push(raw);
}

module.exports = safePromisify;
