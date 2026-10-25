#!/bin/bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CODEC_SOURCE="$PROJECT_DIR/mobilecore/third_party/opencore-amr"
CODEC_BUILD="$PROJECT_DIR/mobilecore/build/opencore-ios-arm64"
CODEC_OUTPUT="$CODEC_SOURCE/prebuilt/ios-arm64"
IOS_SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
mkdir -p "$CODEC_BUILD" "$CODEC_OUTPUT"
cd "$CODEC_BUILD"
export CC="$(xcrun --sdk iphoneos --find clang)"
export CXX="$(xcrun --sdk iphoneos --find clang++)"
export AR="$(xcrun --sdk iphoneos --find ar)"
export RANLIB="$(xcrun --sdk iphoneos --find ranlib)"
export CFLAGS="-O2 -fPIC -target arm64-apple-ios15.6 -isysroot $IOS_SDK"
export CXXFLAGS="$CFLAGS -stdlib=libc++"
export LDFLAGS="-target arm64-apple-ios15.6 -isysroot $IOS_SDK"
"$CODEC_SOURCE/configure" --host=arm-apple-darwin --prefix="$CODEC_OUTPUT" \
  --disable-shared --enable-static --disable-examples --disable-dependency-tracking
# Only narrowband is used by the current IMS media negotiation.
make -C amrnb -j4
make -C amrnb install
echo "Built iOS codec: $CODEC_OUTPUT/lib/libopencore-amrnb.a"
