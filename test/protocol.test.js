import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { encodeAction } from '../src/protocol.js';

test('versioned action envelope is app-scoped and rejects ambiguous encodings', () => {
  assert.equal(encodeAction('airlock', { action: 'open', sequence: 3 }), 'airlock/v1\naction=open\nsequence=3');
  for (const app of ['', 'x', 'Other App', 'a\nb', 'a'.repeat(21)]) assert.throws(() => encodeAction(app, { action: 'open' }));
  for (const fields of [{}, [], null, { action: 'open\ncost=0' }, { action: 'é' }, { 'bad=key': 'open' }, { action: '' }, { value: 1.5 }, { value: true }, { value: {} }, { value: Number.MAX_SAFE_INTEGER + 1 }, { action: 'x'.repeat(1024) }]) {
    assert.throws(() => encodeAction('airlock', fields));
  }
});

test('JavaScript encoding matches MicroPython; decline cannot call the chip', () => {
  const text = encodeAction('airlock', { action: 'open', sequence: 3 });
  const python = `import sys,types,json,hashlib\nsys.path.insert(0,'device')\nfrom wedgie_actions import decode_fields,confirm_action\ntext=json.load(sys.stdin)['text']\nassert decode_fields(text,'airlock',('action','sequence'))=={'action':'open','sequence':'3'}\nfor bad in (text+'\\n',text.replace('airlock/v1','other/v1'),text.replace('action=open','action=é')):\n try: decode_fields(bad,'airlock',('action','sequence'))\n except ValueError: pass\n else: raise AssertionError('invalid action accepted')\ncalls=[]\nclass Chip:\n def sign(self,slot,digest):\n  calls.append((slot,digest))\n  return (1,2)\nui=types.ModuleType('ui')\ndef decline(*args,**kwargs):\n assert 'keys' not in kwargs, 'use ui.ask physical-only default'\n return False\nui.ask=decline\nui.progress=lambda *a,**k:None\nsys.modules['ui']=ui\nsys.modules['optiga']=types.SimpleNamespace(FACTORY_KEY=0xe0f0)\nassert confirm_action(Chip(),None,text,'Open airlock?',[]) is None\nassert not calls\nui.ask=lambda *a,**k:True\nresult=confirm_action(Chip(),None,text,'Open airlock?',[])\nassert result=={'r':'%064x'%1,'s':'%064x'%2}\nassert calls==[(0xe0f0,hashlib.sha256(text.encode()).digest())]\nprint('MicroPython helpers OK')`;
  assert.match(execFileSync('python3', ['-c', python], { cwd: new URL('..', import.meta.url), input: JSON.stringify({ text }), encoding: 'utf8' }), /helpers OK/);
});
