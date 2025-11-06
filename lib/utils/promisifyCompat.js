const { promisify } = require('util');

function safePromisify(method, context) {
  validateFunction(method);
  if (isAsync(method)) return method.bind(context);

  const src = Function.prototype.toString.call(method); // single capture
  const names = getParamNamesFromSource(src);
  const callbackNameRe = /^(cb|callback|done|next|fn)$/i;
  const last = names[names.length - 1];
  // Improved promise source detection (avoid literals/comments): matches actual return Promise or Promise.resolve/reject invocation
  const promiseSource =
    /\breturn\s+(?:new\s+)?Promise\b|Promise\.(?:resolve|reject)\s*\(/.test(
      src,
    );
  const lastIsCb = !!last && callbackNameRe.test(last);
  const anyIsCb =
    names.length >= 2 && names.some((n) => callbackNameRe.test(n));
  const callbackStyle = !promiseSource && (lastIsCb || anyIsCb);
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

function getParamNamesFromSource(src) {
  src = String(src);
  let paramsSection = '';
  // Try standard function/arrow-with-parens form
  const firstParen = src.indexOf('(');
  if (firstParen !== -1) {
    let depth = 0;
    for (let i = firstParen; i < src.length; i++) {
      const ch = src[i];
      if (ch === '(') {
        depth++;
        // skip adding the very first opening paren
        if (depth > 1) paramsSection += ch;
        continue;
      }
      if (ch === ')') {
        depth--;
        if (depth === 0) break; // finished top-level params
        paramsSection += ch;
        continue;
      }
      if (depth > 0) paramsSection += ch;
    }
  } else {
    // Single-arg arrow without parens: e.g. x => x+1
    const arrowMatch = src.match(/^\s*([a-zA-Z_$][\w$]*)\s*=>/);
    if (arrowMatch) paramsSection = arrowMatch[1];
  }
  if (!paramsSection) return [];

  return paramsSection
    .split(',')
    .map((p) => p.replace(/=.*/, '').trim())
    .filter(Boolean);
}

module.exports = safePromisify;
