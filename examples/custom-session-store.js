const express = require('express');
const { EventEmitter } = require('events');
const { auth } = require('../');

const app = express();
const IN_MEMORY_SESSION = {};

class Store extends EventEmitter {
  get (id, cb) {
    const val = IN_MEMORY_SESSION[id];
    console.log('sessionStoreget', id, val);
    process.nextTick(() => cb(null, val));
  }
  set (id, data, cb) {
    console.log('sessionstoreSave', id, data);
    IN_MEMORY_SESSION[id] = data;
    process.nextTick(() => cb());
  }
  destroy (id, cb) {
    console.log('sessionstoreDestroy', id);
    delete IN_MEMORY_SESSION[id];
    process.nextTick(() => cb());
  }
}

app.use(
  auth({
    idpLogout: true,
    sessionStore: Store
  })
);

app.get('/', (req, res) => {
  res.send(`hello ${req.oidc.user.sub}`);
});

module.exports = app;
