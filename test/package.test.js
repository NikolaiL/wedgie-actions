import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';

test('packed distribution contains only runtime source, documentation and public CA certificates', () => {
  const [packed] = JSON.parse(execFileSync('npm', ['pack', '--dry-run', '--json'], { cwd: new URL('..', import.meta.url), encoding: 'utf8' }));
  const paths = packed.files.map((file) => file.path);
  assert.ok(paths.includes('device/wedgie_actions.py'));
  for (const path of paths) {
    assert.match(path, /^(src\/[a-z]+\.js|device\/wedgie_actions\.py|certs\/(ca101|ca300|ca306|rootC|root2)\.crt|certs\/README\.md|README\.md|PROTOCOL\.md|THREAT_MODEL\.md|LICENSE|package\.json)$/);
    if (path.endsWith('.crt')) assert.equal(new X509Certificate(readFileSync(new URL('../' + path, import.meta.url))).ca, true);
  }
});
