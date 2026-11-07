#!/usr/bin/env bash
# Build the COMBINED core aar locally (what the CI job "core" does):
# sing-box libbox + the vendored WARP-over-MASQUE engine, bound together into
# ONE aar (one go.Seq runtime — two aars collide, see third_party/corebind/doc.go).
# Requirements: go 1.26+ (bind) and go 1.24 (to install gomobile), Android SDK + NDK, JAVA 17.
set -euo pipefail

SINGBOX_VERSION="${SINGBOX_VERSION:-v1.11.15}"
ABIS="${ABIS:-arm64-v8a,armeabi-v7a,x86_64}"

command -v go >/dev/null || { echo "go is missing"; exit 1; }
[ -n "${ANDROID_HOME:-}" ] || [ -n "${ANDROID_SDK_ROOT:-}" ] || { echo "ANDROID_HOME is missing"; exit 1; }
REPO="$(cd "$(dirname "$0")/.." && pwd)"

# gomobile v0.1.4 pulls x/tools v0.16.0 which does not compile under go >= 1.25;
# install the tools with 1.24 (or any go < 1.25) if the default go is newer.
if [ -z "${GOMOBILE_INSTALLED:-}" ]; then
  go install -v github.com/sagernet/gomobile/cmd/gomobile@v0.1.4
  go install -v github.com/sagernet/gomobile/cmd/gobind@v0.1.4
fi
export PATH="$PATH:$(go env GOPATH)/bin"

cd "$REPO/third_party/corebind"
go mod tidy
go get github.com/sagernet/gomobile@v0.1.4
go mod download github.com/sagernet/gomobile

gomobile bind \
  -o warpcore.aar \
  -target=android \
  -androidapi 24 \
  -abis "$ABIS" \
  -javapkg=io.nekohasekai \
  -libname=kuku \
  -trimpath \
  -buildvcs=false \
  -ldflags "-X github.com/sagernet/sing-box/constant.Version=${SINGBOX_VERSION} -s -w -buildid=" \
  -tags "with_gvisor,with_quic,with_wireguard,with_ech,with_utls,with_clash_api" \
  github.com/sagernet/sing-box/experimental/libbox github.com/Diniboy1123/usque/mobile

mkdir -p "$REPO/app/libs"
cp warpcore.aar "$REPO/app/libs/warpcore.aar"
echo "done → app/libs/warpcore.aar (combined libbox + warpcore)"
