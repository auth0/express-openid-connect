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
const DESTRUCTURED_CALLBACK_REGEX = new RegExp(
  '(^|[\n\r, \t])(?:' +
    [...CALLBACK_TOKENS].sort((a, b) => b.length - a.length).join('|') +
    ')([ \t]*:|[ \t]*[,}])',
);
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
  if (last && CALLBACK_TOKENS.has(last)) {
    callbackStyle = true;
  } else if (
    rawParamsString &&
    /[{[]/.test(rawParamsString) &&
    DESTRUCTURED_CALLBACK_REGEX.test(rawParamsString)
  ) {
    callbackStyle = true;
  }

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
  let paramsSection = '';
  const firstParen = src.indexOf('(');
  if (firstParen !== -1) {
    let depth = 0;
    let inString = false;
    let quote = '';
    let inTemplate = false;
    let templateDepth = 0;
    for (let i = firstParen; i < src.length; i++) {
      const ch = src[i];
      if (inString) {
        if (ch === quote && !isQuoteEscaped(src, i)) {
          inString = false;
          quote = '';
        }
        paramsSection += ch;
        continue;
      }
      if (inTemplate) {
        if (ch === '`' && templateDepth === 0) {
          inTemplate = false;
        } else if (ch === '{') {
          templateDepth++;
        } else if (ch === '}' && templateDepth > 0) {
          templateDepth--;
        }
        paramsSection += ch;
        continue;
      }
      if (ch === '"' || ch === "'") {
        inString = true;
        quote = ch;
        paramsSection += ch;
        continue;
      }
      if (ch === '`') {
        inTemplate = true;
        templateDepth = 0;
        paramsSection += ch;
        continue;
      }
      if (ch === '(') {
        depth++;
        paramsSection += ch;
        continue;
      }
      if (ch === ')') {
        depth--;
        if (depth < 0) depth = 0;
        paramsSection += ch;
        if (depth === 0) {
          break;
        }
        continue;
      }
      paramsSection += ch;
    }
  }
  const headerMatch =
    /^\s*(?:async\s+)?(?:function\b[^(]*|\([^)]*\)|[A-Za-z_$\p{L}][\w$\p{L}\p{N}]*)\s*\(/u.exec(
      src,
    );
  if (!paramsSection || !headerMatch) {
    const data = { names: [], rawParamsString: '' };
    cacheParams(fn, data);
    return data;
  }
  const rawParams = paramsSection.slice(1, -1); // strip outer parens
  if (!rawParams.trim()) {
    const data = { names: [], rawParamsString: '' };
    cacheParams(fn, data);
    return data;
  }

  const parts = [];
  let current = '';
  let depthBrace = 0,
    depthBracket = 0,
    depthParen = 0;
  let inString = false;
  let quote = '';
  let inTemplate = false;
  let templateDepth = 0;
  for (let i = 0; i < rawParams.length; i++) {
    const ch = rawParams[i];
    if (inString) {
      if (ch === quote && !isQuoteEscaped(rawParams, i)) {
        inString = false;
        quote = '';
      }
      current += ch;
      continue;
    }
    if (inTemplate) {
      if (ch === '`' && templateDepth === 0) {
        inTemplate = false;
      } else {
        if (ch === '{') {
          templateDepth++;
        } else if (ch === '}' && templateDepth > 0) {
          templateDepth--;
        }
      }
      current += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      inString = true;
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === '`') {
      inTemplate = true;
      templateDepth = 0;
      current += ch;
      continue;
    }
    switch (ch) {
      case '{':
        depthBrace++;
        break;
      case '}':
        depthBrace = Math.max(0, depthBrace - 1);
        break;
      case '[':
        depthBracket++;
        break;
      case ']':
        depthBracket = Math.max(0, depthBracket - 1);
        break;
      case '(':
        depthParen++;
        break;
      case ')':
        depthParen = Math.max(0, depthParen - 1);
        break;
      case ',':
        if (depthBrace === 0 && depthBracket === 0 && depthParen === 0) {
          pushParam(parts, current);
          current = '';
          continue;
        }
        break;
    }
    current += ch;
  }
  pushParam(parts, current);
  const data = { names: parts, rawParamsString: rawParams };
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

function isQuoteEscaped(str, idx) {
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
  if (/^[{[]/.test(raw)) {
    // destructured param: attempt simple extraction of identifiers
    const identifiers = raw.match(/[$A-Za-z_\p{L}][\w$\p{L}\p{N}]*/gu);
    if (identifiers) {
      for (const id of identifiers) {
        if (CALLBACK_TOKENS.has(id)) {
          list.push(id);
        }
      }
    }
    return;
  }
  if (!/^[$A-Za-z_\p{L}][\w$\p{L}\p{N}]*$/u.test(raw)) return;
  list.push(raw);
}

module.exports = safePromisify;
