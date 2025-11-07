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
  if (isNative) return method.bind(context); // native pass-through
  const { params, lastParamIsDestructured, lastParamSource } = extractParams(
    src,
    method,
  );
  const last = params[params.length - 1];
  let callbackStyle = false;
  if (last && CALLBACK_TOKENS.has(last)) {
    callbackStyle = true;
  } else if (lastParamIsDestructured && lastParamSource) {
    for (const token of CALLBACK_TOKENS) {
      if (
        new RegExp('(^|[\\s,{])' + token + '(?=\\s*:)', 'm').test(
          lastParamSource,
        )
      ) {
        callbackStyle = true;
        break;
      }
    }
  }
  if (callbackStyle) {
    const p = promisify(method).bind(context);
    defineMeta(p, 'promisifyMode', 'callback');
    return p;
  }
  const wrapper = function (...args) {
    try {
      const result = method.apply(context, args);
      return isThenable(result) ? result : result; // preserve sync semantics
    } catch (e) {
      return Promise.reject(e); // only wrap thrown errors
    }
  };
  const bound = wrapper.bind(context); // consistent binding
  defineMeta(bound, 'name', `promisified_${method.name || 'anonymous'}`);
  defineMeta(bound, 'promisifyMode', 'syncOrPromise');
  return bound;
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

function extractParams(src, fn) {
  if (paramCache.has(fn)) return paramCache.get(fn);
  src = String(src);
  const start = src.indexOf('(');
  if (start === -1) {
    const data = {
      params: [],
      lastParamIsDestructured: false,
      lastParamSource: '',
    };
    cacheParams(fn, data);
    return data;
  }
  let depthParen = 0;
  let inString = false;
  let quote = '';
  let inTemplate = false;
  let templateDepth = 0;
  let i = start;
  let paramsSection = '';
  for (; i < src.length; i++) {
    const ch = src[i];
    if (inString) {
      if (ch === quote && src[i - 1] !== '\\') {
        inString = false;
        quote = '';
      }
      paramsSection += ch;
      continue;
    }
    if (inTemplate) {
      if (ch === '`' && templateDepth === 0) {
        inTemplate = false;
      } else {
        if (ch === '{') templateDepth++;
        else if (ch === '}' && templateDepth > 0) templateDepth--;
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
      depthParen++;
      paramsSection += ch;
      continue;
    }
    if (ch === ')') {
      depthParen--;
      paramsSection += ch;
      if (depthParen === 0) {
        i++;
        break;
      }
      continue;
    }
    paramsSection += ch;
  }
  if (!paramsSection) {
    const data = {
      params: [],
      lastParamIsDestructured: false,
      lastParamSource: '',
    };
    cacheParams(fn, data);
    return data;
  }
  const inner = paramsSection.slice(1, -1); // drop outer parens
  if (!inner.trim()) {
    const data = {
      params: [],
      lastParamIsDestructured: false,
      lastParamSource: '',
    };
    cacheParams(fn, data);
    return data;
  }
  const parts = [];
  let current = '';
  let depthBrace = 0;
  let depthBracket = 0;
  inString = false;
  quote = '';
  inTemplate = false;
  templateDepth = 0;
  for (let idx = 0; idx < inner.length; idx++) {
    const ch = inner[idx];
    if (inString) {
      if (ch === quote && inner[idx - 1] !== '\\') {
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
        if (ch === '{') templateDepth++;
        else if (ch === '}' && templateDepth > 0) templateDepth--;
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
      case ',':
        if (depthBrace === 0 && depthBracket === 0 && templateDepth === 0) {
          pushSimpleParam(parts, current);
          current = '';
          continue;
        }
        break;
    }
    current += ch;
  }
  pushSimpleParam(parts, current);
  const params = [];
  let lastParamIsDestructured = false;
  let lastParamSource = '';
  for (let pIdx = 0; pIdx < parts.length; pIdx++) {
    let p = parts[pIdx].trim();
    if (!p) continue;
    if (/^\.\.\./.test(p)) p = p.replace(/^\.\.\./, '').trim();
    const eq = p.indexOf('=');
    if (eq !== -1) p = p.slice(0, eq).trim();
    if (/^[{[]/.test(p)) {
      if (pIdx === parts.length - 1) {
        lastParamIsDestructured = true;
        lastParamSource = p;
      }
      continue;
    }
    if (/^[$A-Za-z_\p{L}][\w$\p{L}\p{N}]*$/u.test(p)) params.push(p);
  }
  const data = { params, lastParamIsDestructured, lastParamSource };
  cacheParams(fn, data);
  return data;
}

function pushSimpleParam(list, raw) {
  list.push(raw);
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
