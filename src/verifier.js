import { X509Certificate, createHash, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const readCA = (name) => new X509Certificate(readFileSync(new URL(`../certs/${name}.crt`, import.meta.url)));
const ROOTS = ['rootC', 'root2'].map(readCA);
const ISSUERS = ['ca101', 'ca300', 'ca306'].map(readCA);

export function certificateFromHex(hex) {
  if (typeof hex !== 'string' || hex.length < 400 || hex.length > 8192 || hex.length % 2 || !/^[0-9a-f]+$/i.test(hex)) {
    throw new Error('Malformed device certificate.');
  }
  const bytes = Buffer.from(hex, 'hex');
  // The Trust M certificate object may have a small C0/TLS wrapper before its DER sequence.
  for (let offset = 0; offset <= 16 && offset < bytes.length - 4; offset++) {
    if (bytes[offset] !== 0x30) continue;
    const lengthByte = bytes[offset + 1];
    const count = lengthByte & 0x80 ? lengthByte & 0x7f : 0;
    if (count > 3) continue;
    let length = count ? 0 : lengthByte;
    for (let i = 0; i < count; i++) length = length * 256 + bytes[offset + 2 + i];
    const end = offset + 2 + count + length;
    if (end > bytes.length) continue;
    try { return new X509Certificate(bytes.subarray(offset, end)); } catch { /* Try the next wrapper byte. */ }
  }
  throw new Error('Cannot decode the Trust M certificate.');
}

function validNow(cert, now) {
  return cert.validFromDate <= now && now <= cert.validToDate;
}

// Tests supply an ephemeral PKI here. The HTTP server always uses the bundled production CAs.
export function createTrustVerifier(roots = ROOTS, issuers = ISSUERS) {
  // shortcut: offline CA bundle has no revocation checks; add CRL handling before public enrollment.
  function identity(hex, now = Date.now()) {
    const cert = certificateFromHex(hex);
    if (cert.ca || cert.publicKey.asymmetricKeyType !== 'ec' || cert.publicKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
      throw new Error('A P-256 device certificate is required.');
    }
    if (!validNow(cert, now)) throw new Error('Device certificate is expired or not yet valid.');
    const issuer = issuers.find((candidate) => candidate.ca && validNow(candidate, now) && cert.checkIssued(candidate) && cert.verify(candidate.publicKey));
    const root = issuer && roots.find((candidate) => candidate.ca && validNow(candidate, now) && issuer.checkIssued(candidate) && issuer.verify(candidate.publicKey) && candidate.verify(candidate.publicKey));
    if (!root) throw new Error('Certificate does not chain to a pinned Infineon Trust M root.');
    return {
      fingerprint: createHash('sha256').update(cert.raw).digest('hex'),
      publicKey: cert.publicKey,
      issuer: issuer.subject,
    };
  }

  function signature(device, text, proof) {
    if (typeof text !== 'string' || !text.length || text.length > 1024 || !/^[\x20-\x7e\n]+$/.test(text)) {
      throw new Error('Action text must be at most 1024 bytes of printable ASCII and newlines.');
    }
    if (!proof || !['r', 's'].every((key) => typeof proof[key] === 'string' && /^[0-9a-f]{64}$/i.test(proof[key]))) {
      throw new Error('Malformed P-256 signature.');
    }
    const signed = verify('sha256', Buffer.from(text, 'ascii'), { key: device.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(proof.r + proof.s, 'hex'));
    if (!signed) throw new Error('The certified chip did not sign this exact action.');
  }
  return { identity, signature };
}

export const trustM = createTrustVerifier();
