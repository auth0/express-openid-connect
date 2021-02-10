const express = require('express');
const { auth } = require('../');

const app = express();
const IN_MEMORY_SESSION = {};

app.use(
  auth({
    idpLogout: true,
    sessionStore: {
      get: function get(id, cb) {
        const val = IN_MEMORY_SESSION[id];
        console.log('sessionStoreget', id, val);
        process.nextTick(() => cb(null, val));
      },
      set: function set(id, data, cb) {
        console.log('sessionstoreSave', id, data);
        IN_MEMORY_SESSION[id] = data;
        process.nextTick(() => cb());
      },
      destroy: function set(id, cb) {
        console.log('sessionstoreDestroy', id);
        delete IN_MEMORY_SESSION[id];
        process.nextTick(() => cb());
      },
    },
  })
);

app.get('/', (req, res) => {
  res.send(`hello ${req.oidc.user.sub}`);
});

module.exports = app;
