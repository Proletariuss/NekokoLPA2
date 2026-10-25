#!/bin/bash
# Source-only build: never selects a signing identity or installs an app.
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"
MODE="${1:---framework-only}"
case "$MODE" in
  --framework-only|--app) ;;
  *) echo 'Usage: scripts/build_ios_vowifi.sh [--framework-only|--app]' >&2; exit 2 ;;
esac
command -v go >/dev/null
command -v gomobile >/dev/null
command -v gobind >/dev/null
command -v xcrun >/dev/null
bash scripts/build_ios_vowifi_codecs.sh
mkdir -p mobilecore/build local_packages/proletarius_vowifi/ios/Frameworks
(
  cd mobilecore
  gomobile bind -target=ios/arm64 -iosversion=15.6 -o build/Mobilecore.xcframework .
)
ditto mobilecore/build/Mobilecore.xcframework local_packages/proletarius_vowifi/ios/Frameworks/Mobilecore.xcframework
cp mobilecore/third_party/opencore-amr/prebuilt/ios-arm64/lib/libopencore-amrnb.a \
  local_packages/proletarius_vowifi/ios/Frameworks/libopencore-amrnb.a
if [[ "$MODE" == --app ]]; then
  command -v flutter >/dev/null
  command -v pod >/dev/null
  flutter pub get
  (cd ios && pod install)
  flutter build ios --release --no-codesign
fi
echo 'VoWiFi source build complete. No signing or device installation performed.'
