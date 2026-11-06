import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { X509Certificate, sign, generateKeyPairSync } from 'node:crypto';
import { createTrustVerifier, trustM, certificateFromHex } from '../src/verifier.js';

const dir = mkdtempSync(join(tmpdir(), 'starproof-tests-'));
after(() => rmSync(dir, { recursive: true, force: true }));
const openssl = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: 'pipe' });
openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', 'root.key', '-out', 'root.pem', '-subj', '/CN=Starproof TEST ROOT', '-days', '2', '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:1', '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
for (const [name, subject] of [['issuer', '/CN=Starproof TEST ISSUER'], ['device', '/CN=Starproof TEST DEVICE']]) {
  openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', name + '.key', '-out', name + '.csr', '-subj', subject);
  writeFileSync(join(dir, name + '.ext'), name === 'issuer' ? 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' : 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n');
  const parent = name === 'issuer' ? 'root' : 'issuer';
  openssl('x509', '-req', '-in', name + '.csr', '-CA', parent + '.pem', '-CAkey', parent + '.key', '-CAcreateserial', '-out', name + '.pem', '-days', '1', '-extfile', name + '.ext');
}
const cert = (name) => new X509Certificate(readFileSync(join(dir, name + '.pem')));
const device = cert('device'), root = cert('root'), issuer = cert('issuer');
const certificate = device.raw.toString('hex');
const key = readFileSync(join(dir, 'device.key'));
const verifier = createTrustVerifier([root], [issuer]);
const signText = (text, signingKey = key) => {
  const signature = sign('sha256', Buffer.from(text, 'ascii'), { key: signingKey, dsaEncoding: 'ieee-p1363' });
  return { r: signature.subarray(0, 32).toString('hex'), s: signature.subarray(32).toString('hex') };
};
test('production verifier rejects a software-generated PKI, copied certificate alone and malformed data', () => {
  assert.throws(() => trustM.identity(certificate), /pinned Infineon/);
  assert.throws(() => trustM.identity('gg'.repeat(400)), /Malformed/);
  const identity = verifier.identity(certificate);
  assert.throws(() => verifier.signature(identity, 'launch', {}), /Malformed/);
  const attacker = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  assert.throws(() => verifier.signature(identity, 'launch', signText('launch', attacker.privateKey)), /did not sign/);
  assert.throws(() => verifier.identity(certificate, Date.parse(device.validTo) + 1000), /expired/);
  assert.throws(() => createTrustVerifier([root], []).identity(certificate), /pinned/);
  const proof = signText('launch');
  verifier.signature(identity, 'launch', proof);
  assert.throws(() => verifier.signature(identity, '\u016caunch', proof), /ASCII/);
  assert.throws(() => verifier.signature(identity, 'launch\u0000', proof), /ASCII/);
});

test('DER certificate wrappers are handled without trusting certificate names', () => {
  assert.equal(certificateFromHex('c00000' + certificate).fingerprint256, device.fingerprint256);
  assert.throws(() => verifier.identity(root.raw.toString('hex')), /device certificate/);
  assert.throws(() => certificateFromHex('00'.repeat(300)), /decode/);
});

