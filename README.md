# Kuku VPN 🐔

Android VPN client built on the [sing-box](https://github.com/SagerNet/sing-box) core — with a RIX-style promise: **"Connected" is shown only after a real request has passed through the tunnel and returned.**

> Full documentation (Persian): [README.fa.md](README.fa.md)

## Features

- **Real-connection verification** — 4-stage bar (Core → Listener → Tunnel → Exit), each stage lit only with evidence
- **Automatic fallback** — ranked candidate chain (up to 3), last-known-good remembered
- **Per-app split tunneling** — all / include / exclude, Kuku itself always excluded
- **Kill switch** — dead tunnel keeps the VPN interface up so traffic blackholes instead of leaking
- **Live telemetry** — up/down counters, session time, exit IP, 60-second sparkline on a dedicated stream
- **Two modes** — full-device VPN (VpnService) or local SOCKS/HTTP proxy on `127.0.0.1:2080`
- **Imports** — subscription URLs (base64/text/sing-box JSON), share links, QR scan, share-to-app
- **Protocols** — VLESS (+Reality/Vision/ws/grpc/httpupgrade), VMess, Trojan, Shadowsocks, Hysteria2, TUIC v5, WireGuard, SSH
- **fa/en UI** — full RTL, light/dark/system themes
- **Privacy** — no account, no analytics, no ads, no telemetry; cleartext & backup disabled

## Building

The repo is designed to be built **entirely on GitHub Actions** — no local tooling needed:

1. Import/fork this repository to your GitHub account.
2. Run the `android` workflow (Actions tab → `android` → Run). Job 1 builds `libbox.aar` with gomobile from a pinned sing-box tag; job 2 assembles the APKs.
3. Grab the `kuku-apks` artifact, or push a `v*` tag for an automatic GitHub Release with `SHA256SUMS.txt` and build-provenance attestation.

Optional release signing uses four repository secrets (`KUKU_KEYSTORE_B64`, `KUKU_KEYSTORE_PASSWORD`, `KUKU_KEY_ALIAS`, `KUKU_KEY_PASSWORD`) — see README.fa.md for the exact commands. Signing material must never be committed; the CI refuses builds that track it.

For local builds: `scripts/build-libbox.sh` then `gradle :app:assembleDebug`.

If a libbox bump changes generated interfaces, see `docs/BUILD-TROUBLESHOOTING.md` (2-minute fix with `javap`).

## License

GPL-3.0-or-later (required by the GPL-licensed libbox core). See `LICENSE`, `NOTICE`, `TRADEMARK.md`.
