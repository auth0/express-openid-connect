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

function safePromisify(method, context) {
  validateFunction(method);
  if (isAsync(method)) return method.bind(context);
  if (typeof method[promisify.custom] === 'function')
    return method[promisify.custom].bind(context);

  let src = '';
  try {
    src = Function.prototype.toString.call(method);
  } catch {}
  const isNative = /\[native code\]/.test(src);
  if (isNative) return method.bind(context);

  const params = extractParams(src);
  const last = params[params.length - 1];
  const isCallbackStyle = last && CALLBACK_TOKENS.has(last);
  if (isCallbackStyle) return promisify(method).bind(context);

  // Fallback wrapper: supports sync or promise-returning methods without probing.
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
function isThenable(v) {
  return v && typeof v.then === 'function';
}

function extractParams(src) {
  src = String(src);
  // Arrow single param without parens: x => ...
  const singleArrow = src.match(/^\s*([A-Za-z_$][\w$]*)\s*=>/);
  if (singleArrow && !/^\s*function\b/.test(src)) return [singleArrow[1]];
  const head = src.match(/^[^(]*\(([^)]*)\)/);
  if (!head) return [];
  const raw = head[1].trim();
  if (!raw) return [];
  const parts = [];
  let token = '';
  let depthBrace = 0,
    depthBracket = 0,
    depthParen = 0;
  let inStr = false;
  let q = '';
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (inStr) {
      if (ch === q && raw[i - 1] !== '\\') {
        inStr = false;
        q = '';
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
  raw = raw.replace(/^\.\.\./, '').trim();
  const eq = raw.indexOf('=');
  if (eq !== -1) raw = raw.slice(0, eq).trim();
  if (/^[{[]/.test(raw)) return; // ignore destructured params for callback detection
  if (!/^[$A-Za-z_][\w$]*$/.test(raw)) return;
  list.push(raw);
}

module.exports = safePromisify;
