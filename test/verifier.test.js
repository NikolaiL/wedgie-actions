import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { X509Certificate, sign, generateKeyPairSync, createHash } from 'node:crypto';
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

function alternateCertificateSignature(cert) {
  const field = (bytes, at = 0) => {
    const start = at++;
    let length = bytes[at++];
    if (length & 0x80) {
      let count = length & 0x7f; length = 0;
      while (count--) length = length * 256 + bytes[at++];
    }
    return { content: at, end: at + length, raw: bytes.subarray(start, at + length), value: bytes.subarray(at, at + length) };
  };
  const encode = (tag, value) => {
    let size = value.length;
    const length = [];
    do { length.unshift(size & 0xff); size >>= 8; } while (size);
    return Buffer.concat([Buffer.from([tag, ...(value.length < 128 ? [value.length] : [0x80 | length.length, ...length])]), value]);
  };
  const outer = field(cert.raw), body = field(cert.raw, outer.content);
  const algorithm = field(cert.raw, body.end), bits = field(cert.raw, algorithm.end);
  const sequence = field(bits.value, 1), r = field(bits.value, sequence.content), s = field(bits.value, r.end);
  const order = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
  // Both s and order-s verify, although the certificate's DER bytes and fingerprint change.
  let hex = (order - BigInt('0x' + s.value.toString('hex'))).toString(16);
  if (hex.length % 2) hex = '0' + hex;
  let alternateS = Buffer.from(hex, 'hex');
  if (alternateS[0] & 0x80) alternateS = Buffer.concat([Buffer.from([0]), alternateS]);
  const alternate = new X509Certificate(encode(0x30, Buffer.concat([
    body.raw, algorithm.raw,
    encode(0x03, Buffer.concat([Buffer.from([0]), encode(0x30, Buffer.concat([r.raw, encode(0x02, alternateS)]))])),
  ])));
  return alternate;
}

test('stable chip key IDs survive certificate ECDSA signature malleability', () => {
  const alternate = alternateCertificateSignature(device);
  assert.equal(device.verify(issuer.publicKey), true);
  assert.equal(alternate.verify(issuer.publicKey), true);
  const originalIdentity = verifier.identity(certificate);
  const alternateIdentity = verifier.identity(alternate.raw.toString('hex'));
  assert.notEqual(originalIdentity.fingerprint, alternateIdentity.fingerprint);
  assert.match(originalIdentity.keyId, /^[0-9a-f]{64}$/);
  assert.equal(originalIdentity.keyId, alternateIdentity.keyId);
  const text = 'airdrop claim bound to a recipient', proof = signText(text);
  verifier.signature(originalIdentity, text, proof);
  verifier.signature(alternateIdentity, text, proof);
});


function walletProof(text, code, wallet = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })) {
  const point = wallet.publicKey.export({ format: 'jwk' });
  const x = Buffer.from(point.x, 'base64url'), y = Buffer.from(point.y, 'base64url');
  const preimage = Buffer.concat([Buffer.from('wedgie prove\0'), createHash('sha256').update(text + '\n' + code, 'utf8').digest()]);
  const walletSignature = sign('sha256', preimage, { key: wallet.privateKey, dsaEncoding: 'ieee-p1363' });
  const factorySignature = sign('sha256', Buffer.concat([Buffer.from('wedgie safe key\0'), x, y]), { key, dsaEncoding: 'ieee-p1363' });
  return { text, code, cert: certificate, x: x.toString('hex'), y: y.toString('hex'),
    r: walletSignature.subarray(0, 32).toString('hex'), s: walletSignature.subarray(32).toString('hex'),
    fr: factorySignature.subarray(0, 32).toString('hex'), fs: factorySignature.subarray(32).toString('hex') };
}

test('wallet proofs bind a fresh challenge and wallet key to a certified chip identity', () => {
  const text = 'Starproof claim to the selected Safe', code = 'fresh-server-challenge';
  const proof = walletProof(text, code), identity = verifier.walletProof(proof, text, code);
  assert.equal(identity.keyId, verifier.identity(certificate).keyId);
  assert.equal(identity.fingerprint, verifier.identity(certificate).fingerprint);
  assert.deepEqual(identity.wallet, { x: '0x' + proof.x, y: '0x' + proof.y });
  const prefixed = Object.fromEntries(Object.entries(proof).map(([field, value]) =>
    [field, ['x', 'y', 'r', 's', 'fr', 'fs'].includes(field) ? '0x' + value.toUpperCase() : value]));
  assert.deepEqual(verifier.walletProof(prefixed, text, code).wallet, identity.wallet);
  const utf8 = walletProof(text, 'nonce-é');
  assert.equal(verifier.walletProof(utf8, utf8.text, utf8.code).keyId, identity.keyId);
  const unreadable = walletProof('Claim à the selected Safe 🚀', code);
  assert.throws(() => verifier.walletProof(unreadable, unreadable.text, code), /expected challenge/);
  const changedCert = alternateCertificateSignature(device);
  const alternate = verifier.walletProof({ ...proof, cert: changedCert.raw.toString('hex') }, text, code);
  assert.equal(alternate.keyId, identity.keyId);
  assert.notEqual(alternate.fingerprint, identity.fingerprint);
  assert.throws(() => trustM.walletProof(proof, text, code), /pinned Infineon/);
  assert.throws(() => verifier.walletProof(proof, text, code, Date.parse(device.validTo) + 1000), /expired/);
});

test('wallet proofs reject changed text, nonce, wallet key and either signature', () => {
  const text = 'Claim the airdrop', code = 'server-nonce', proof = walletProof(text, code);
  assert.throws(() => verifier.walletProof(proof, text + ' changed', code));
  assert.throws(() => verifier.walletProof(proof, text, code + ' changed'));
  assert.throws(() => verifier.walletProof({ ...proof, text: text + ' changed' }, text + ' changed', code));
  assert.throws(() => verifier.walletProof({ ...proof, code: code + ' changed' }, text, code + ' changed'));
  for (const field of ['x', 'y', 'r', 's', 'fr', 'fs']) {
    assert.throws(() => verifier.walletProof({ ...proof, [field]: '00'.repeat(32) }, text, code), field + ' substitution must fail');
    for (const value of [undefined, '', 'ff'.repeat(31), 'ff'.repeat(33), 'gg'.repeat(32)]) {
      assert.throws(() => verifier.walletProof({ ...proof, [field]: value }, text, code), field + ' must be exactly 32 bytes of hex');
    }
  }
  const attacker = walletProof(text, code);
  assert.throws(() => verifier.walletProof({ ...attacker, fr: proof.fr, fs: proof.fs }, text, code), /endorse this Safe key/,
    'a copied certificate and a valid attacker wallet signature need the matching factory endorsement');
  assert.throws(() => verifier.walletProof(null, text, code));
});
