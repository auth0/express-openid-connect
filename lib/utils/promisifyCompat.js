const { promisify } = require('util');

const ORIGINAL_TO_STRING = Function.prototype.toString;
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
const DESTRUCTURED_CALLBACK_REGEX =
  /\{[^}]*\b(cb|callback|done|errback|doneCallback|cbk)\b[^}]*}$/;
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const paramCache = new WeakMap();
const paramCacheOrder = [];
const MAX_PARAM_CACHE = 1000;

function safePromisify(method, context) {
  validateFunction(method);
  if (isAsync(method)) return method.bind(context);
  if (typeof method[promisify.custom] === 'function') {
    const custom = method[promisify.custom].bind(context);
    defineMeta(custom, 'promisifyMode', 'custom');
    return custom;
  }
  let src = '';
  try {
    if (Function.prototype.toString === ORIGINAL_TO_STRING) {
      src = ORIGINAL_TO_STRING.call(method);
    }
  } catch {}
  const isNative = /\[native code\]/.test(src);
  const { names, rawParamsString } = isNative
    ? { names: [], rawParamsString: '' }
    : extractParamNames(src, method);
  const last = names[names.length - 1];
  let callbackStyle = false;
  if (last && CALLBACK_TOKENS.has(last)) callbackStyle = true;
  else if (
    !last &&
    rawParamsString &&
    DESTRUCTURED_CALLBACK_REGEX.test(rawParamsString.trim())
  )
    callbackStyle = true;
  if (callbackStyle) {
    const p = promisify(method).bind(context);
    defineMeta(p, 'promisifyMode', 'callback');
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
  defineMeta(wrapper, 'name', `promisified_${method.name || 'anonymous'}`);
  defineMeta(wrapper, 'promisifyMode', 'syncOrPromise');
  return wrapper;
}

function defineMeta(obj, prop, value) {
  try {
    Object.defineProperty(obj, prop, { value, configurable: true });
  } catch {}
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
  let paramsMatch = src.match(/^[^(]*\(([^)]*)\)/);
  if (!paramsMatch) {
    const data = { names: [], rawParamsString: '' };
    cacheParams(fn, data);
    return data;
  }
  const raw = paramsMatch[1].trim();
  if (!raw) {
    const data = { names: [], rawParamsString: '' };
    cacheParams(fn, data);
    return data;
  }
  if (/^[{[]/.test(raw)) {
    const data = { names: [], rawParamsString: raw };
    cacheParams(fn, data);
    return data;
  }
  const parts = raw
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) =>
      p
        .replace(/^\.\.\./, '')
        .split('=')[0]
        .trim(),
    )
    .filter((p) => /^[$A-Za-z_\p{L}][\w$\p{L}\p{N}]*$/u.test(p));
  const data = { names: parts, rawParamsString: raw };
  cacheParams(fn, data);
  return data;
}

function cacheParams(fn, data) {
  paramCache.set(fn, data);
  paramCacheOrder.push(fn);
  if (paramCacheOrder.length > MAX_PARAM_CACHE) {
    const evict = paramCacheOrder.shift();
    if (evict) paramCache.delete(evict);
  }
}

module.exports = safePromisify;
