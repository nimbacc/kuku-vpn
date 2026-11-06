# Security Policy

Kuku VPN follows the same hygiene rules that RIX-AETHER learned the hard way:

## Signing keys — the rule that must never break

- Signing material (`release.keystore`, `.jks`, `.p12`, `keystore.properties`) is
  **never committed** to this repository. `.gitignore` excludes it and the CI
  workflow **fails the build** if any signing file is ever tracked.
- CI restores the keystore at build time from the secrets:
  `KUKU_KEYSTORE_B64`, `KUKU_KEYSTORE_PASSWORD`, `KUKU_KEY_ALIAS`, `KUKU_KEY_PASSWORD`.
- Release APKs built on GitHub Actions receive a **build-provenance attestation**
  (`actions/attest-build-provenance`). Users verify an official build with:

  ```bash
  gh attestation verify Kuku-<version>.apk --repo <your-user>/kuku-vpn
  ```

  Note the same caveat as every GitHub attestation: the statement binds the file
  hash to a workflow run **of this repository** — a build from someone else's
  fork passes attestation on that fork, not here. That is exactly what makes
  this check useful.

- Verify checksums with `SHA256SUMS.txt` published next to each release.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting (Security → Report a vulnerability).
Please do not open public issues for exploitable problems.

## What Kuku VPN does NOT do

- No account system, no analytics SDK, no ads, no telemetry, no crash-reporting.
- Settings and profiles stay on-device (DataStore).
- Cleartext traffic is disabled in the manifest; app backup is disabled.

## Residual risk

A VPN necessarily forwards traffic to the selected upstream endpoint. To
understand that part of the network path, review the upstream sing-box project
and the server operators you connect to.
