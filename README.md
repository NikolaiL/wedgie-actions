# wedgie-actions

Reusable Web Serial transport, action encoding, and manufacturer-certified **OPTIGA Trust M** signature verification for Wedgie developers. Starproof is the [reference game](https://github.com/NikolaiL/starproof), not part of this package.

Requires Node.js 24+ on the server and desktop Chrome/Edge with Web Serial in the browser. No runtime npm dependencies and no build step.

## Install

```sh
npm install github:NikolaiL/wedgie-actions
```

This initial release is distributed from GitHub, not the npm registry. Pin a Git commit in applications for reproducible installs. The package exports `wedgie-actions/browser`, `wedgie-actions/server`, and `wedgie-actions/protocol`. Serve the browser module as an ES module through your app's bundler or static server; do not import the Node-only server module into a browser.

## Browser

```js
import { WedgieSigner } from 'wedgie-actions/browser';

const signer = new WedgieSigner('mygame'); // the app's module/namespace
await signer.connect();                 // call from a click; opens the serial picker
const cert = signer.cert;               // public certificate, NOT yet proof of possession
const proof = await signer.signAction(challenge); // { text } issued by your server
// Send proof.r and proof.s back to the server that issued the challenge.
// From a cancel button while signAction is pending:
// await signer.cancelAction(); // true only after the device acknowledges cancellation
await signer.disconnect();
```

`connect({ version, install })` optionally calls an app-owned `install(port)` callback once when the selected device lacks the expected app/version. The signer closes its transport before handing over the same authorized port, then reconnects and verifies the handshake. The callback must preserve the device’s physical installation approval; installation is never silently authorized by this library. A declined install is not retried.

The matching device app must implement the [v1 wire protocol](PROTOCOL.md). Namespaces use the same 2–20 lowercase letters/digits/underscores as Wedgie modules. `request(type, fields, timeoutMs)` exposes the underlying JSON transport. Only one device request can be active at a time, except a cancellation targeting the pending signature. Apps that advertise `cancel: true` in their identity reply support `cancelAction()`: it returns whether the device dismissed that prompt. Older apps need reinstalling for remote cancellation. Always invalidate the server challenge too; a signature already produced cannot be recalled. Refusals, transport errors and timeouts reject the promise. `disconnect` events tell your UI to stop requesting signatures. Reconnect after a timed-out request; a late response is never accepted as a newer request.

## Server

```js
import { trustM } from 'wedgie-actions/server';
import { encodeAction } from 'wedgie-actions/protocol';

const device = trustM.identity(cert); // validates the pinned CA chain and dates
const text = encodeAction('mygame', orderedFields); // construct from SERVER state
trustM.signature(device, text, proof); // throws on an invalid signature
// Check and consume the server's pending nonce, enforce your rules, then mutate state.
```

`identity(certHex, now?)` accepts DER hex or the Trust M's small certificate-object wrapper. It returns `fingerprint` (SHA-256 of DER), `publicKey` (Node KeyObject), and `issuer`. `signature(device, text, {r,s})` verifies SHA-256/P-256; each scalar is exactly 64 hex characters. `certificateFromHex` exposes certificate decoding. `createTrustVerifier(roots, issuers)` supports explicitly chosen trust stores, primarily test PKIs; never let a request supply those roots.

**Certificate validation is not authentication on its own.** Require a fresh signature from the factory private key certified by that certificate. The library does not issue challenges, consume nonces, authorize users, or enforce your game rules. Bind the protocol/app, origin, user/session, certified chip, complete action arguments, sequence/nonce and expiry; preserve and verify the exact server-issued text. Onchain actions also need chain ID and contract address in their domain.

## Device helper

`device/wedgie_actions.py` is vendorable MicroPython source, not a standalone app. Copy it into your app as `<mod>_actions.py` and include it in your app's manifest; Wedgie requires app-prefixed installed filenames. It provides:

- `decode_fields(text, app, names)`: strict ASCII envelope, namespace and field-order parsing. Your app must validate each field's meaning and allowed values.
- `certificate_der(blob)`: remove the chip's certificate-object wrapper.
- `confirm_action(chip, display, text, question, lines, cancelled=None)`: real-button `ui.ask`, then SHA-256/factory-key signing; returns `{r,s}` or `None` after decline/timeout. Derive the question and lines from the validated action, never from separate host labels.

For cooperative cancellation, supply a `cancelled()` callback that polls your app’s USB reader, validates the target request ID and acknowledges the cancel command. It is checked during `ui.ask` and immediately before signing. The helper wraps physical-only keys; host messages can abort but can never approve.

The helper does not generate, replace or lock keys. It uses `ui.ask`'s physical-only defaults. It does not make arbitrary raw-digest signing available over USB. See Starproof's device app for complete application-side validation and packaging.

## Test and inspect a package

```sh
npm ci
npm test                 # Node test runner, OpenSSL and Python 3 required
npm pack --dry-run       # inspect the publish allowlist; does not publish
```

Tests use a temporary software PKI to exercise verification and confirm that the production verifier rejects it. Browser tests use streams with a second app namespace. Cross-language tests verify the same bytes and ensure a declined prompt never calls the chip. Real-device integration was exercised in the original Starproof prototype; the extracted helper has not yet been reinstalled/tested on hardware.

## Trust, privacy and provenance

This verifies **certified-chip participation**, not human presence, firmware identity, proximity, or bot resistance. Factory certificates are stable, linkable identifiers. Read [THREAT_MODEL.md](THREAT_MODEL.md) and the [CA provenance](certs/README.md). No player certificates, receipts, private keys or API tokens belong in this repo.

Initially extracted from [Starproof](https://github.com/NikolaiL/starproof), built from scratch during ETHGlobal Mumbai on November 6, 2026 with Codex assistance. API usage follows the public [Wedgie guides](https://wedgie.dev/skill.md). The `lcd`, `ui`, `optiga` and USB runtime are supplied by Wedgie firmware, not bundled here. Public Infineon CAs retain their original provenance. MIT for this project's source.
