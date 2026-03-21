import test from 'node:test';
import assert from 'node:assert/strict';

function createStorage() {
  const map = new Map();
  return {
    getItem(key) {
      return map.has(key) ? map.get(key) : null;
    },
    setItem(key, value) {
      map.set(key, String(value));
    },
    removeItem(key) {
      map.delete(key);
    },
    clear() {
      map.clear();
    }
  };
}

test('fetchSessions sends auth header when token is set', { concurrency: false }, async () => {
  globalThis.localStorage = createStorage();
  const events = [];
  globalThis.window = { dispatchEvent: (evt) => events.push(evt.type) };
  globalThis.CustomEvent = class {
    constructor(type) { this.type = type; }
  };

  let seenHeaders = null;
  globalThis.fetch = async (_url, options = {}) => {
    seenHeaders = options.headers || {};
    return {
      ok: true,
      status: 200,
      json: async () => ({ items: [] }),
      text: async () => ''
    };
  };

  const api = await import('../src/api.js');
  api.setAuthToken('eft_test');
  await api.fetchSessions();

  assert.equal(seenHeaders.Authorization, 'Bearer eft_test');
  assert.equal(events.length, 0);
});

test('fetchSessions handles 401 by clearing auth and throwing session-expired error', { concurrency: false }, async () => {
  globalThis.localStorage = createStorage();
  globalThis.localStorage.setItem('endoriumfort_auth', JSON.stringify({ token: 'eft_old' }));
  const events = [];
  globalThis.window = { dispatchEvent: (evt) => events.push(evt.type) };
  globalThis.CustomEvent = class {
    constructor(type) { this.type = type; }
  };

  globalThis.fetch = async () => ({
    ok: false,
    status: 401,
    json: async () => ({}),
    text: async () => 'Unauthorized'
  });

  const api = await import('../src/api.js');
  api.setAuthToken('eft_expired');

  await assert.rejects(
    async () => {
      await api.fetchSessions();
    },
    (error) => {
      assert.match(String(error.message), /Session expired/i);
      return true;
    }
  );

  assert.equal(globalThis.localStorage.getItem('endoriumfort_auth'), null);
  assert.ok(events.includes('endoriumfort:unauthorized'));
});

test('setMfaPreference sends JSON body and auth header', { concurrency: false }, async () => {
  globalThis.localStorage = createStorage();
  globalThis.window = { dispatchEvent: () => {} };
  globalThis.CustomEvent = class {
    constructor(type) { this.type = type; }
  };

  let seenHeaders = null;
  let seenBody = null;
  let seenMethod = null;
  globalThis.fetch = async (_url, options = {}) => {
    seenHeaders = options.headers || {};
    seenBody = options.body;
    seenMethod = options.method;
    return {
      ok: true,
      status: 200,
      json: async () => ({ status: 'ok', preferredMfaMethod: 'webauthn' }),
      text: async () => ''
    };
  };

  const api = await import('../src/api.js');
  api.setAuthToken('eft_pref');
  const result = await api.setMfaPreference('webauthn');

  assert.equal(seenMethod, 'POST');
  assert.equal(seenHeaders.Authorization, 'Bearer eft_pref');
  assert.equal(seenHeaders['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(seenBody), { method: 'webauthn' });
  assert.equal(result.preferredMfaMethod, 'webauthn');
});

test('deleteWebAuthnCredential uses DELETE with auth header', { concurrency: false }, async () => {
  globalThis.localStorage = createStorage();
  globalThis.window = { dispatchEvent: () => {} };
  globalThis.CustomEvent = class {
    constructor(type) { this.type = type; }
  };

  let seenUrl = '';
  let seenMethod = '';
  let seenHeaders = null;
  globalThis.fetch = async (url, options = {}) => {
    seenUrl = url;
    seenMethod = options.method;
    seenHeaders = options.headers || {};
    return {
      ok: true,
      status: 200,
      json: async () => ({ status: 'ok', credentials: [] }),
      text: async () => ''
    };
  };

  const api = await import('../src/api.js');
  api.setAuthToken('eft_passkey');
  await api.deleteWebAuthnCredential(7);

  assert.equal(seenUrl, '/api/auth/webauthn/credentials/7');
  assert.equal(seenMethod, 'DELETE');
  assert.equal(seenHeaders.Authorization, 'Bearer eft_passkey');
});
