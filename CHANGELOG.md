# Changelog

## [0.3.0] - 2026-11-21

First public release, as ShakePortal (earlier versions were test builds
called Fingertip).

### Added

- Handshake sites in Chrome on Wi-Fi and mobile data, through a local proxy
  that the app's VPN sets for the whole phone. The VPN routes no traffic.
- DANE checking with no trusted resolver: each top-level name's on-chain
  record comes as a proof from Handshake peers (two public proof services as
  a fallback), checked against block headers the phone syncs and verifies
  itself; the site's own DNS answers are checked with DNSSEC from it.
- Stateless DANE: sites whose certificate carries its own proofs are
  verified from the certificate alone.
- A local CA, created on the phone, that can only sign Handshake names
  (never .com or any other ICANN name).
- The screen shows how each Handshake site was checked, the CA's
  fingerprint and whether it is installed.
