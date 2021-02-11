const express = require('express');
const { auth } = require('../');

const app = express();

class Store {
  constructor() {
    this.sessions = {};
  }
  get(id, cb) {
    const val = this.sessions[id];
    console.log('sessionStoreget', id, val);
    process.nextTick(() => cb(null, val));
  }
  set(id, data, cb) {
    console.log('sessionstoreSave', id, data);
    this.sessions[id] = data;
    process.nextTick(() => cb());
  }
  destroy(id, cb) {
    console.log('sessionstoreDestroy', id);
    delete this.sessions[id];
    process.nextTick(() => cb());
  }
}

app.use(
  auth({
    idpLogout: true,
    sessionStore: new Store(),
  })
);

app.get('/', (req, res) => {
  res.send(`hello ${req.oidc.user.sub}`);
});

module.exports = app;
