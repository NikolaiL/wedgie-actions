import test from 'node:test';
import assert from 'node:assert/strict';
import { WedgieSigner } from '../src/browser.js';

test('connect installs a missing app once and reuses the chosen port; refusal never retries installation', async (t) => {
  let incoming, installed = false, installs = 0, selections = 0;
  const port = {
    get readable() { return new ReadableStream({ start(controller) { incoming = controller; } }); },
    writable: new WritableStream({ write(bytes) {
      const { id } = JSON.parse(new TextDecoder().decode(bytes));
      incoming.enqueue(new TextEncoder().encode(JSON.stringify(installed ? { id, type: 'airlock_identity', protocol: 'airlock/v1', cert: 'public', appVersion: '2' } : { id, type: 'error', error: 'unknown type' }) + '\n'));
    } }),
    async open() {}, async close() {},
  };
  Object.defineProperty(navigator, 'serial', { configurable: true, value: { requestPort: async () => { selections++; return port; } } });
  t.after(() => delete navigator.serial);
  const signer = new WedgieSigner('airlock');
  await signer.connect({ version: '2', install: async (chosen) => { assert.equal(chosen, port); assert.equal(signer.port, null); installed = true; installs++; } });
  assert.equal(installs, 1); assert.equal(selections, 1); assert.equal(signer.cert, 'public');
  await signer.disconnect();
  installed = false;
  await assert.rejects(signer.connect({ install: async () => { installs++; throw new Error('Declined installation'); } }), /Declined installation/);
  assert.equal(installs, 2); assert.equal(signer.port, null);
});

test('a restarting installer can return the same device on a replacement port without another picker', async (t) => {
  let selections = 0, installs = 0;
  const opened = [], closed = [];
  function makePort(name, identity) {
    let incoming;
    return {
      get readable() { return new ReadableStream({ start(c) { incoming = c; } }); },
      writable: new WritableStream({ write(bytes) {
        const { id } = JSON.parse(new TextDecoder().decode(bytes));
        incoming.enqueue(new TextEncoder().encode(JSON.stringify({ id, ...identity }) + '\n'));
      } }),
      async open() { opened.push(name); }, async close() { closed.push(name); },
    };
  }
  const before = makePort('before', { type: 'error', error: 'unknown type' });
  const after = makePort('after', { type: 'airlock_identity', protocol: 'airlock/v1', cert: 'public', appVersion: '2' });
  Object.defineProperty(navigator, 'serial', { configurable: true, value: { requestPort: async () => { selections++; return before; } } });
  t.after(() => delete navigator.serial);
  const signer = new WedgieSigner('airlock');
  await signer.connect({ version: '2', install: async (port) => {
    installs++; assert.equal(port, before); assert.equal(signer.port, null); return after;
  } });
  assert.equal(signer.port, after); assert.equal(signer.cert, 'public');
  assert.equal(selections, 1); assert.equal(installs, 1);
  assert.deepEqual(opened, ['before', 'after']);
  await signer.disconnect();
  assert.deepEqual(closed, ['before', 'after']);
});

test('browser cancellation reaches the pending device request and a late proof cannot answer a new one', async (t) => {
  let incoming;
  const writes = [], encoder = new TextEncoder();
  const reply = (value) => incoming.enqueue(encoder.encode(JSON.stringify(value) + '\n'));
  const port = {
    readable: new ReadableStream({ start(controller) { incoming = controller; } }),
    writable: new WritableStream({ write(bytes) {
      const request = JSON.parse(new TextDecoder().decode(bytes)); writes.push(request);
      if (request.type === 'airlock_hello') reply({ id: request.id, type: 'airlock_identity', protocol: 'airlock/v1', cert: 'public', cancel: true });
      if (request.type === 'airlock_cancel') {
        reply({ id: request.id, type: 'airlock_cancelled', cancelled: true });
        reply({ id: request.request, type: 'refused' });
      }
    } }),
    async open() {}, async close() {},
  };
  Object.defineProperty(navigator, 'serial', { configurable: true, value: { requestPort: async () => port } });
  t.after(() => delete navigator.serial);
  const signer = new WedgieSigner('airlock');
  await signer.connect();
  assert.equal(await signer.cancelAction(), false);
  const signing = assert.rejects(signer.signAction({ text: 'first' }), /Declined/);
  // Cancel immediately, including while the first serial write is queued.
  assert.equal(await signer.cancelAction(), true);
  await signing;
  const first = writes.find((value) => value.type === 'airlock_sign');
  assert.equal(writes.find((value) => value.type === 'airlock_cancel').request, first.id);
  reply({ id: first.id, type: 'airlock_signature', r: 'stale', s: 'stale' });
  const next = signer.signAction({ text: 'second' });
  await signer.writing;
  reply({ id: writes.at(-1).id, type: 'airlock_signature', r: 'new', s: 'new' });
  assert.deepEqual(await next, { r: 'new', s: 'new' });
  await signer.disconnect();
});

test('browser transport uses another app namespace, handles split lines and physical refusal', async (t) => {
  let incoming, writes = [], opens = 0, closes = 0;
  const encoder = new TextEncoder();
  const port = {
    readable: new ReadableStream({ start(controller) { incoming = controller; } }),
    writable: new WritableStream({ write(bytes) {
      const request = JSON.parse(new TextDecoder().decode(bytes)); writes.push(request);
      if (request.type === 'airlock_hello') {
        incoming.enqueue(encoder.encode('boot log\n{"id":' + request.id));
        incoming.enqueue(encoder.encode(',"type":"airlock_identity","protocol":"airlock/v1","cert":"public"}\n'));
      } else incoming.enqueue(encoder.encode(JSON.stringify({ id: request.id, type: 'refused' }) + '\n'));
    } }),
    async open() { opens++; }, async close() { closes++; },
  };
  Object.defineProperty(navigator, 'serial', { configurable: true, value: { requestPort: async () => port } });
  t.after(() => delete navigator.serial);
  assert.throws(() => new WedgieSigner('bad name'));
  const signer = new WedgieSigner('airlock');
  await signer.connect();
  assert.equal(opens, 1); assert.equal(signer.cert, 'public');
  await assert.rejects(signer.signAction({ text: 'airlock/v1\naction=open' }), /Declined/);
  assert.deepEqual(writes.map((item) => item.type), ['airlock_hello', 'airlock_sign']);
  await signer.disconnect();
  assert.equal(closes, 1); assert.equal(signer.port, null);
});

test('a device-side disconnect closes the port so connect() starts fresh; fields cannot replace id or type', async (t) => {
  let incoming, opens = 0, closes = 0;
  const encoder = new TextEncoder();
  const makePort = () => ({
    readable: new ReadableStream({ start(controller) { incoming = controller; } }),
    writable: new WritableStream({ write(bytes) {
      const request = JSON.parse(new TextDecoder().decode(bytes));
      incoming.enqueue(encoder.encode(JSON.stringify({ id: request.id, type: 'airlock_identity', protocol: 'airlock/v1', cert: 'public', echo: request.type }) + '\n'));
    } }),
    async open() { opens++; }, async close() { closes++; },
  });
  Object.defineProperty(navigator, 'serial', { configurable: true, value: { requestPort: async () => makePort() } });
  t.after(() => delete navigator.serial);
  const signer = new WedgieSigner('airlock');
  await signer.connect();
  incoming.close();
  await signer.reading;
  assert.equal(signer.port, null); assert.equal(signer.cert, null); assert.equal(closes, 1);
  await signer.connect();
  assert.equal(opens, 2); assert.equal(signer.cert, 'public');
  assert.equal((await signer.request('airlock_ping', { id: 99, type: 'other' }, 500)).echo, 'airlock_ping');
  await signer.disconnect();
  assert.equal(closes, 2);
});

test('unknown app request closes the serial port and gives setup guidance', async (t) => {
  let incoming, closed = false;
  const port = {
    readable: new ReadableStream({ start(controller) { incoming = controller; } }),
    writable: new WritableStream({ write(bytes) { const request = JSON.parse(new TextDecoder().decode(bytes)); incoming.enqueue(new TextEncoder().encode(JSON.stringify({ id: request.id, type: 'error', error: 'unknown type' }) + '\n')); } }),
    async open() {}, async close() { closed = true; },
  };
  Object.defineProperty(navigator, 'serial', { configurable: true, value: { requestPort: async () => port } });
  t.after(() => delete navigator.serial);
  await assert.rejects(new WedgieSigner('airlock').connect(), /Install the airlock app/);
  assert.equal(closed, true);
});

test('unsolicited joystick input is validated and cannot complete a signing request', async (t) => {
  let incoming;
  const send = value => incoming.enqueue(new TextEncoder().encode(JSON.stringify(value) + '\n'));
  const port = {
    readable: new ReadableStream({ start(c) { incoming = c; } }),
    writable: new WritableStream({ write(bytes) { const {id,type}=JSON.parse(new TextDecoder().decode(bytes)); if(type==='airlock_hello')send({id,type:'airlock_identity',protocol:'airlock/v1',cert:'public'}); } }),
    async open() {}, async close() {},
  };
  Object.defineProperty(navigator,'serial',{configurable:true,value:{requestPort:async()=>port}});
  t.after(()=>delete navigator.serial);
  const signer = new WedgieSigner('airlock'), events=[];
  signer.addEventListener('input', event=>events.push(event.detail));
  await signer.connect();
  const signing = assert.rejects(signer.signAction({text:'pending'}), /disconnected/);
  await signer.writing;
  send({type:'airlock_input',dx:1,dy:-1,scan:true});
  send({type:'airlock_input',dx:999,dy:0,scan:false});
  for (const action of ['go', 'refuel', 'scavenge', 'info']) send({type:'airlock_input',dx:0,dy:0,scan:false,action});
  send({type:'airlock_input',dx:0,dy:0,scan:false,action:'approve'});
  send({type:'another_input',dx:0,dy:0,scan:true});
  await new Promise(resolve=>setImmediate(resolve));
  assert.deepEqual(events,[{dx:1,dy:-1,scan:true}, ...['go','refuel','scavenge','info'].map(action=>({dx:0,dy:0,scan:false,action}))]);
  assert.equal(signer.pending.size,1);
  await signer.disconnect(); await signing;
});
