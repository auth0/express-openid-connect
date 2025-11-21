const map = new WeakMap();

function weakRef(ctx) {
  if (!map.has(ctx)) map.set(ctx, {});
  return map.get(ctx);
}

module.exports = {
  weakRef,
};
