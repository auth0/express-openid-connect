const { promisify } = require('util');

const CALLBACK_TOKENS = new Set([
  'cb',
  'callback',
  'done',
  'next',
  'fn',
  'finish',
  'complete',
  'cbk',
  'errback',
  'doneCallback',
]);
const DESTRUCTURED_CALLBACK_REGEX = new RegExp(
  '(^|[\n\r, \t])(?:' +
    [...CALLBACK_TOKENS].sort((a, b) => b.length - a.length).join('|') +
    ')([ \t]*:|[ \t]*[,}])',
);
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const paramCache = new WeakMap();

function safePromisify(method, context) {
  validateFunction(method);
  if (isAsync(method)) return method.bind(context);
  if (typeof method[promisify.custom] === 'function') {
    const custom = method[promisify.custom].bind(context);
    try {
      Object.defineProperty(custom, 'promisifyMode', { value: 'custom' });
    } catch {}
    return custom;
  }
  let src;
  try {
    src = Function.prototype.toString.call(method);
  } catch {
    src = '';
  }
  const isNative = /\[native code\]/.test(src);
  const { names, rawLast } = isNative
    ? { names: [], rawLast: '' }
    : extractParamNames(src, method);
  const last = names[names.length - 1];
  let callbackStyle = false;
  if (last && CALLBACK_TOKENS.has(last)) {
    callbackStyle = true;
  } else if (
    rawLast &&
    /^[{[]/.test(rawLast) &&
    DESTRUCTURED_CALLBACK_REGEX.test(rawLast)
  ) {
    callbackStyle = true;
  }
  if (callbackStyle) {
    const p = promisify(method).bind(context);
    try {
      Object.defineProperty(p, 'promisifyMode', { value: 'callback' });
    } catch {}
    return p;
  }
  const wrapper = function (...args) {
    try {
      const result = method.apply(context, args);
      return isThenable(result) ? result : Promise.resolve(result);
    } catch (e) {
      return Promise.reject(e);
    }
  };
  try {
    Object.defineProperty(wrapper, 'name', {
      value: `promisified_${method.name || 'anonymous'}`,
      configurable: true,
    });
  } catch {}
  try {
    Object.defineProperty(wrapper, 'promisifyMode', { value: 'syncOrPromise' });
  } catch {}
  return wrapper;
}

function validateFunction(fn) {
  if (typeof fn !== 'function')
    throw new TypeError(
      'Expected method to be a function, received ' + typeof fn,
    );
}
function isAsync(fn) {
  return fn instanceof AsyncFunction;
}
function isThenable(obj) {
  return obj && typeof obj.then === 'function';
}

function extractParamNames(src, fn) {
  if (paramCache.has(fn)) return paramCache.get(fn);
  src = String(src);
  const singleArrow = src.match(/^\s*([A-Za-z_$][\w$]*)\s*=>/u);
  if (singleArrow && !/^\s*function\b/.test(src)) {
    const data = { names: [singleArrow[1]], rawLast: singleArrow[1] };
    paramCache.set(fn, data);
    return data;
  }
  const match = src.match(/^[^(]*\(([^)]*)\)/);
  if (!match) {
    const data = { names: [], rawLast: '' };
    paramCache.set(fn, data);
    return data;
  }
  const rawParams = match[1];
  if (!rawParams.trim()) {
    const data = { names: [], rawLast: '' };
    paramCache.set(fn, data);
    return data;
  }
  const parts = [];
  const rawParts = [];
  let token = '';
  let depthBrace = 0,
    depthBracket = 0,
    depthParen = 0;
  let inString = false;
  let quote = '';
  for (let i = 0; i < rawParams.length; i++) {
    const ch = rawParams[i];
    if (inString) {
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
          rawParts.push(token.trim());
          token = '';
          continue;
        }
        break;
    }
    token += ch;
  }
  pushParam(parts, token);
  rawParts.push(token.trim());
  const data = { names: parts, rawLast: rawParts[rawParts.length - 1] || '' };
  paramCache.set(fn, data);
  return data;
}

function isEscaped(str, idx) {
  let backslashes = 0;
  for (let i = idx - 1; i >= 0 && str[i] === '\\'; i--) backslashes++;
  return backslashes % 2 === 1;
}

function pushParam(list, raw) {
  raw = raw.trim();
  if (!raw) return;
  raw = raw.replace(/^\.{3}/, '').trim();
  const eq = raw.indexOf('=');
  if (eq !== -1) raw = raw.slice(0, eq).trim();
  if (/^[{[]/.test(raw)) return;
  if (!/^[$A-Za-z_][\w$]*$/u.test(raw)) return;
  list.push(raw);
}

module.exports = safePromisify;
