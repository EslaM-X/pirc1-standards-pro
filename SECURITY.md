# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| `main` | ✔ Supported |
| `v1.0.x` | ✔ Supported |

## Reporting a Vulnerability

Do **not** disclose security vulnerabilities publicly. Report privately through
a **GitHub Security Advisory** on this repository.

Include the affected file, a description, reproduction steps, and a suggested
fix if possible.

## Design notes

- **Signatures never guess.** PEP payloads are HMAC-SHA256 signed payloads from
  the dApp backend to the Pi SDK — the private material is never committed.
- **Sybil resistance is structural.** Utility weights and engagement proofs are
  verifiable by design; there is no "trust this claim" path.
- **Schema is governance-ready.** `pi-manifest.json` is the single source of
  truth for utility weights and verification methods; changes are reviewable.
- **This is a proposal, not a wallet.** The protocol standardizes how dApps
  report and verify utility; it does not hold or move user funds.
