# Trust model

The verifier checks that a P-256 leaf certificate chains through a pinned Trust M intermediate to a pinned Infineon root, validates certificate dates, and verifies a signature from that certified factory key over the application's exact action text. Public CA provenance is recorded in `certs/README.md`.

It rejects software-generated/self-issued identities, copied certificates without their private key, malformed signatures, and signatures over changed text. The consuming app must issue and consume fresh challenges to reject replay, and must enforce authorization and state transitions.

## What it does not establish

- Approved firmware, a physical green-button press, a unique human or fair play. Modified code can operate a genuine chip automatically.
- Physical proximity. Challenges can be relayed to a real chip elsewhere.
- That a separately supplied application key lives on the chip. A factory signature endorsing an arbitrary public key is not remote firmware/key-generation attestation.
- Secure game state if the player controls the authoritative server. Use an independently controlled server or a contract with authenticated key enrollment for shared enforcement.

## Operational limits

- No CRL/OCSP checks, compromised-device revocation, automatic CA rotation, or chip-recovery policy. The initial bundle requires maintenance before production enrollment.
- A factory certificate is a stable cross-session identifier; receipts can be linkable. Treat this as a privacy decision.
- Applications must show the action's meaning and preserve domain separation. Do not expose an unrestricted factory-key signing oracle.
- The helper never creates or locks keys. It expects a factory-provisioned OPTIGA Trust M; the virtual Wedgie's software certificate is not accepted by the default verifier.
- The library is a prototype, not an audited hardware-wallet or anti-bot system. Native crypto/X509 parsing comes from Node.js; application state, clocks, trust-store distribution and update policy remain trust boundaries.

Tests may construct `createTrustVerifier` with an ephemeral test CA. Never accept a trust root supplied by a player and never substitute test roots in production.
