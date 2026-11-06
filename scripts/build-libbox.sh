#!/usr/bin/env bash
# Build libbox.aar locally (what the CI job "libbox" does on GitHub runners).
# Requirements: go 1.23+, gomobile, Android SDK + NDK, JAVA 17.
set -euo pipefail

SINGBOX_VERSION="${SINGBOX_VERSION:-v1.11.15}"
ABIS="${ABIS:-arm64-v8a,armeabi-v7a,x86_64}"

command -v go >/dev/null || { echo "go is missing"; exit 1; }
[ -n "${ANDROID_HOME:-}" ] || [ -n "${ANDROID_SDK_ROOT:-}" ] || { echo "ANDROID_HOME is missing"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

git clone --depth 1 --branch "$SINGBOX_VERSION" https://github.com/SagerNet/sing-box "$WORK/sing-box"
cd "$WORK/sing-box"

go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
gomobile init

gomobile bind \
  -o libbox.aar \
  -target=android \
  -androidapi 24 \
  -javapkg=io.nekohasekai.libbox \
  -abis "$ABIS" \
  -tags "with_quic,with_wireguard,with_gvisor,with_utls,with_clash_api" \
  ./experimental/libbox

OUT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
mkdir -p app/libs
cp libbox.aar "$(pwd)/app/libs/libbox.aar" 2>/dev/null || cp libbox.aar "$OLDPWD/app/libs/libbox.aar" || true
echo "done → app/libs/libbox.aar (copy it to your kuku-vpn checkout if the path differs)"
