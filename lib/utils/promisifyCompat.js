const { promisify } = require('util');

function safePromisify(method, context) {
  validateFunction(method);
  if (isAsync(method)) return method.bind(context);

  const src = Function.prototype.toString.call(method);
  const isNative = /\[native code\]/.test(src);

  // Strip line & block comments and string/template literals for safer regex checks
  const scrubbed = scrubSource(src);

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

  // Promise detection: returning a Promise or invoking static Promise helpers
  const promiseSource =
    /\breturn\s+(?:await\s+)?(?:new\s+)?Promise\b|\bPromise\.(?:resolve|reject|all|race|any|allSettled)\s*\(/.test(
      scrubbed,
    );

  // Callback detection (exact token match only, avoids partial matches like nextStep)
  const lastIsCb = !!last && callbackTokens.has(last);
  const anyIsCb = names.length >= 2 && names.some((n) => callbackTokens.has(n));
  // Heuristic: if >=3 params and not detected as promise source treat as callback style
  const aritySuggestsCb = names.length >= 3 && !promiseSource;
  const callbackStyle =
    !promiseSource && (lastIsCb || anyIsCb || aritySuggestsCb);

  if (callbackStyle) return promisify(method).bind(context);

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

// Remove strings and comments for safer pattern matching (best-effort, non exhaustive)
function scrubSource(src) {
  return (
    src
      // remove block comments
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      // remove line comments
      .replace(/([^\\:]|^)\/\/.*$/gm, ' ')
      // remove template literals (basic)
      .replace(/`(?:[^`\\]|\\[\s\S])*`/g, ' ')
      // remove single & double quoted strings (basic, ignores escaped quotes inside)
      .replace(/'(?:[^'\\]|\\.)*'/g, ' ') // single
      .replace(/"(?:[^"\\]|\\.)*"/g, ' ')
  ); // double
}

// Robust-ish param extraction: handles defaults, nested parens/brackets/braces at top level
function extractParamNames(src) {
  src = String(src);
  // Arrow single param without parens
  const arrowSingle = src.match(/^\s*([a-zA-Z_$][\w$]*)\s*=>/);
  if (arrowSingle && !src.startsWith('function')) return [arrowSingle[1]];

  const firstParen = src.indexOf('(');
  if (firstParen === -1) return [];
  let depth = 0;
  let params = '';
  for (let i = firstParen; i < src.length; i++) {
    const ch = src[i];
    if (ch === '(') {
      depth++;
      if (depth === 1) continue; // skip outer
    } else if (ch === ')') {
      depth--;
      if (depth === 0) break;
    }
    if (depth > 0) params += ch;
  }
  if (!params) return [];

  const result = [];
  let token = '';
  let brace = 0,
    bracket = 0,
    paren = 0;
  let inString = false;
  let stringQuote = '';
  for (let i = 0; i < params.length; i++) {
    const ch = params[i];
    if (inString) {
      if (ch === stringQuote && params[i - 1] !== '\\') {
        inString = false;
        stringQuote = '';
      }
      token += ch;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      inString = true;
      stringQuote = ch;
      token += ch;
      continue;
    }
    switch (ch) {
      case '{':
        brace++;
        break;
      case '}':
        brace--;
        break;
      case '[':
        bracket++;
        break;
      case ']':
        bracket--;
        break;
      case '(':
        paren++;
        break;
      case ')':
        paren--;
        break;
      case ',':
        if (brace === 0 && bracket === 0 && paren === 0) {
          pushParam(result, token);
          token = '';
          continue;
        }
        break;
    }
    token += ch;
  }
  pushParam(result, token);
  return result;
}

function pushParam(list, raw) {
  raw = raw.trim();
  if (!raw) return;
  const eq = raw.indexOf('=');
  if (eq !== -1) raw = raw.slice(0, eq).trim();
  // Ignore destructuring/rest as callback hints
  if (/^[.]{3}/.test(raw)) raw = raw.replace(/^\.{3}/, '').trim();
  if (!raw) return;
  list.push(raw);
}

module.exports = safePromisify;
