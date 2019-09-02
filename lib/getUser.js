//This is the default function for mapping a tokenSet to a user.
module.exports = function(tokenSet) {
  return tokenSet && tokenSet.claims();
};
