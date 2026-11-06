import test from 'node:test';
import assert from 'node:assert/strict';
import { WedgieSigner } from '../src/browser.js';

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
