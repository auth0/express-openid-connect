const { promisify } = require('util');

function safePromisify(method, context) {
  validateFunction(method);
  if (isAsync(method)) return method.bind(context);

  const names = getParamNames(method);
  const callbackNameRe = /^(cb|callback|done|next|fn)$/i;
  const last = names[names.length - 1];
  const src = Function.prototype.toString.call(method);
  const promiseSource =
    /Promise\.resolve|return\s+new\s+Promise|Promise\.reject/.test(src);
  const lastIsCb = !!last && callbackNameRe.test(last);
  const anyIsCb =
    names.length >= 2 && names.some((n) => callbackNameRe.test(n));
  const callbackStyle = !promiseSource && (lastIsCb || anyIsCb);
  if (callbackStyle) return promisify(method).bind(context);

  return function (...args) {
    try {
      const result = method.apply(context, args);
      return isThenable(result) ? result : Promise.resolve(result);
    } catch (e) {
      return Promise.reject(e);
    }
  };
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
function getParamNames(fn) {
  const src = Function.prototype.toString.call(fn);
  const match = src.match(/^[^(]*\(([^)]*)\)/);
  if (!match) return [];
  return match[1]
    .split(',')
    .map((p) => p.replace(/=.*/, '').trim())
    .filter(Boolean);
}

module.exports = safePromisify;
