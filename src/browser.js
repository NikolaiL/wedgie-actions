export class WedgieSigner extends EventTarget {
  constructor(app) {
    super();
    if (typeof app !== 'string' || !/^[a-z][a-z0-9_]{1,19}$/.test(app)) throw new Error('Use your Wedgie app module name.');
    this.app = app;
    this.port = null;
    this.reader = null;
    this.pending = new Map();
    this.nextId = 1;
    this.cert = null;
  }

  async connect() {
    if (!navigator.serial) throw new Error('Open this page in desktop Chrome or Edge to connect a Wedgie.');
    if (this.port) return;
    const port = await navigator.serial.requestPort({ filters: [{ usbVendorId: 0x2e8a }] });
    await port.open({ baudRate: 115200 });
    this.port = port;
    this.reader = port.readable.getReader();
    this.reading = this.readLoop();
    try {
      const reply = await this.request(`${this.app}_hello`, {}, 8000);
      if (reply.protocol !== `${this.app}/v1` || !reply.cert) throw new Error(`Install the ${this.app} Wedgie app first.`);
      this.cert = reply.cert;
    } catch (error) {
      await this.disconnect();
      if (/unknown type|unknown request|not handled/i.test(error.message)) {
        throw new Error(`Install the ${this.app} app on your Wedgie first, then reconnect. Its current app does not recognize these requests.`);
      }
      throw error;
    }
  }

  async readLoop() {
    const decoder = new TextDecoder(); let buffer = '';
    try {
      while (true) {
        const { value, done } = await this.reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let end;
        while ((end = buffer.indexOf('\n')) !== -1) {
          const line = buffer.slice(0, end).trim(); buffer = buffer.slice(end + 1);
          if (!line.startsWith('{') || line.length > 8192) continue;
          let reply;
          try { reply = JSON.parse(line); } catch { continue; }
          const pending = this.pending.get(reply.id);
          if (!pending) continue;
          clearTimeout(pending.timer); this.pending.delete(reply.id);
          if (reply.type === 'refused') pending.reject(new Error('Declined on Wedgie. No action was taken.'));
          else if (reply.type === 'error') pending.reject(new Error(reply.error || 'Wedgie could not sign.'));
          else pending.resolve(reply);
        }
        if (buffer.length > 8192) throw new Error('Device sent an oversized response.');
      }
    } catch (error) { this.readError = error.message; }
    finally {
      this.reader.releaseLock();
      for (const pending of this.pending.values()) { clearTimeout(pending.timer); pending.reject(new Error(this.readError || 'Wedgie disconnected.')); }
      this.pending.clear(); this.cert = null;
      this.dispatchEvent(new Event('disconnect'));
    }
  }

  async request(type, fields = {}, timeout = 75_000) {
    if (!this.port?.writable) throw new Error('Connect your Wedgie first.');
    if (this.pending.size) throw new Error('Finish the current device request first.');
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error('Device timed out. Reconnect it before trying again.')); }, timeout);
      this.pending.set(id, { resolve, reject, timer });
      void (async () => {
        const writer = this.port.writable.getWriter();
        try { await writer.write(new TextEncoder().encode(JSON.stringify({ id, type, ...fields }) + '\n')); }
        finally { writer.releaseLock(); }
      })().catch((error) => { clearTimeout(timer); this.pending.delete(id); reject(error); });
    });
  }

  async signAction(challenge) {
    if (!this.cert) throw new Error(`Connect a Wedgie running ${this.app} first.`);
    const reply = await this.request(`${this.app}_sign`, { text: challenge.text });
    if (reply.type !== `${this.app}_signature`) throw new Error('Unexpected signing response.');
    return { r: reply.r, s: reply.s };
  }

  async disconnect() {
    const port = this.port;
    if (!port) return;
    await this.reader?.cancel().catch(() => {});
    await this.reading;
    await port.close().catch(() => {});
    this.port = null; this.reader = null; this.cert = null;
  }
}
