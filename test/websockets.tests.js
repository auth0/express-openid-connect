const { assert } = require('chai');
const sinon = require('sinon');
const { create: createServer } = require('./fixture/server');
const { makeIdToken } = require('./fixture/cert');
const WebSocket = require('ws');
const WebSocketAsPromised = require('websocket-as-promised');
const { auth, requiresAuth } = require('..');
const request = require('request-promise-native').defaults({
  simple: false,
  resolveWithFullResponse: true,
  followRedirect: false,
});

const baseUrl = 'http://localhost:3000';
const wsUrl = 'ws://localhost:3000';
const HR_MS = 60 * 60 * 1000;

const defaultConfig = {
  secret: '__test_session_secret__',
  clientID: '__test_client_id__',
  baseURL: 'https://example.org',
  issuerBaseURL: 'https://op.example.com',
};

const createWebSocketClient = (options) =>
  new WebSocketAsPromised(wsUrl, {
    createWebSocket: (url) => new WebSocket(url, options),
    packMessage: (msg) => JSON.stringify(msg),
    unpackMessage: (msg) => JSON.parse(msg),
    attachRequestId: (data, id) => ({ id, data }),
    extractRequestId: (data) => data && data.id,
    extractMessageData: (data) => data,
  });

const createWebSocketClientWithJar = (jar) =>
  createWebSocketClient({ headers: { Cookie: jar.getCookieString(baseUrl) } });

const createWebSocketServer = (server, webSocketAuthenticate) => {
  const wss = new WebSocket.Server({ noServer: true });
  server.on('upgrade', (req, socket, head) => {
    webSocketAuthenticate(req, (err, oidc) => {
      if (err || !oidc) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
      } else {
        wss.handleUpgrade(req, socket, head, (ws) => {
          wss.emit('connection', ws, request, oidc);
        });
      }
    });
  });

  wss.on('connection', (ws, req, oidc) => {
    ws.on('message', async (msg) => {
      const { id, data } = JSON.parse(msg);
      if (data == 'profile') {
        const reply = JSON.stringify({ id, data: oidc.user });
        ws.send(reply);
      }
    });
  });
  return wss;
};

const login = async (claims) => {
  const jar = request.jar();
  await request.post('/session', {
    baseUrl,
    jar,
    json: {
      id_token: makeIdToken(claims),
    },
  });
  return jar;
};

describe('webSocketAuthenticate', () => {
  let server;
  let wss;
  let ws;

  afterEach(async () => {
    if (server) {
      server.close();
    }
    if (wss) {
      wss.close();
    }
    if (ws) {
      ws.close();
    }
  });

  it('should allow logged in users to connect', async () => {
    const { expressAuthRouter, webSocketAuthenticate } = auth({
      ...defaultConfig,
      authRequired: false,
      webSocket: true,
    });
    server = await createServer(expressAuthRouter, requiresAuth());
    wss = createWebSocketServer(server, webSocketAuthenticate);

    const jar = await login();
    ws = createWebSocketClientWithJar(jar);

    await assert.isFulfilled(ws.open());
  });

  it('should allow authenticated users to retrieve their profile', async () => {
    const { expressAuthRouter, webSocketAuthenticate } = auth({
      ...defaultConfig,
      authRequired: false,
      webSocket: true,
    });
    server = await createServer(expressAuthRouter, requiresAuth());
    wss = createWebSocketServer(server, webSocketAuthenticate);

    const jar = await login();
    ws = createWebSocketClientWithJar(jar);

    await ws.open();
    const { data: user } = await ws.sendRequest('profile');
    assert.equal(user.nickname, '__test_nickname__');
  });

  it('should block unauthenticated users', async () => {
    const { expressAuthRouter, webSocketAuthenticate } = auth({
      ...defaultConfig,
      authRequired: false,
      webSocket: true,
    });
    server = await createServer(expressAuthRouter, requiresAuth());
    wss = createWebSocketServer(server, webSocketAuthenticate);
    ws = createWebSocketClient();

    await assert.isRejected(ws.open());
  });

  it('should block new connections from users with an expired cookie', async () => {
    const clock = sinon.useFakeTimers({ toFake: ['Date'] });
    const { expressAuthRouter, webSocketAuthenticate } = auth({
      ...defaultConfig,
      authRequired: false,
      webSocket: true,
    });
    server = await createServer(expressAuthRouter, requiresAuth());
    wss = createWebSocketServer(server, webSocketAuthenticate);

    const jar = await login();

    clock.tick(23 * HR_MS);
    ws = createWebSocketClientWithJar(jar);
    await assert.isFulfilled(ws.open());
    await ws.close();
    clock.tick(25 * HR_MS);
    ws = createWebSocketClientWithJar(jar);
    await assert.isRejected(ws.open());
    clock.restore();
  });
});
