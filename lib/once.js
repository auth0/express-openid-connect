/**
 * Given a callback, return a wrapped callback that will only run once regardless of calls.
 */
function once(callback) {
  let called = false;
  let value;

  return (...args) => {
    if (!called) {
      value = callback(...args);
    }

    called = true;

    return value;
  };
}

module.exports = { once };
