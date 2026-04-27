#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST_DIR="$ROOT/dist/apple"
FRAMEWORKS_DIR="$ROOT/dist/frameworks"

mkdir -p "$DIST_DIR" "$FRAMEWORKS_DIR"

for target in \
  aarch64-apple-darwin \
  aarch64-apple-ios \
  aarch64-apple-ios-sim \
  x86_64-apple-ios \
  aarch64-apple-ios-macabi \
  x86_64-apple-ios-macabi
do
  cargo rustc \
    --manifest-path "$ROOT/Cargo.toml" \
    --release \
    --features ffi \
    --target "$target" \
    --crate-type staticlib
done

for target in \
  aarch64-apple-ios-macabi \
  x86_64-apple-ios-macabi
do
  cargo rustc \
    --manifest-path "$ROOT/Cargo.toml" \
    --release \
    --features ffi \
    --target "$target" \
    --crate-type cdylib
done

lipo -create \
  "$ROOT/target/aarch64-apple-ios-sim/release/libaura_protected_protocol.a" \
  "$ROOT/target/x86_64-apple-ios/release/libaura_protected_protocol.a" \
  -output "$ROOT/target/libaura_protected_protocol_sim.a"

lipo -create \
  "$ROOT/target/aarch64-apple-ios-macabi/release/libaura_protected_protocol.a" \
  "$ROOT/target/x86_64-apple-ios-macabi/release/libaura_protected_protocol.a" \
  -output "$ROOT/target/libaura_protected_protocol_maccatalyst.a"

lipo -create \
  "$ROOT/target/aarch64-apple-ios-macabi/release/libaura_protected_protocol.dylib" \
  "$ROOT/target/x86_64-apple-ios-macabi/release/libaura_protected_protocol.dylib" \
  -output "$ROOT/target/libaura_protected_protocol_maccatalyst.dylib"

write_info_plist() {
  local plist="$1"

  /usr/libexec/PlistBuddy -c "Clear dict" "$plist" 2>/dev/null || true
  /usr/libexec/PlistBuddy -c "Add :CFBundleDevelopmentRegion string en" "$plist"
  /usr/libexec/PlistBuddy -c "Add :CFBundleExecutable string AuraProtectedProtocolC" "$plist"
  /usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string ai.auramessenger.AuraProtectedProtocolC" "$plist"
  /usr/libexec/PlistBuddy -c "Add :CFBundleInfoDictionaryVersion string 6.0" "$plist"
  /usr/libexec/PlistBuddy -c "Add :CFBundleName string AuraProtectedProtocolC" "$plist"
  /usr/libexec/PlistBuddy -c "Add :CFBundlePackageType string FMWK" "$plist"
  /usr/libexec/PlistBuddy -c "Add :CFBundleShortVersionString string 2.0.0" "$plist"
  /usr/libexec/PlistBuddy -c "Add :CFBundleVersion string 2.0.0" "$plist"
}

create_framework_bundle() {
  local dst="$1"
  local fw="$dst/AuraProtectedProtocolC.framework"

  rm -rf "$fw"
  mkdir -p "$fw/Headers" "$fw/Modules"
  cp "$ROOT"/include/*.h "$fw/Headers/"
  cp "$ROOT/include/module.modulemap" "$fw/Modules/"
  cp "$ROOT/include/module.modulemap" "$fw/Headers/"
  write_info_plist "$fw/Info.plist"
}

create_static_framework() {
  local lib="$1"
  local dst="$2"
  local fw="$dst/AuraProtectedProtocolC.framework"

  create_framework_bundle "$dst"
  cp "$lib" "$fw/AuraProtectedProtocolC"
}

create_dynamic_framework() {
  local lib="$1"
  local dst="$2"
  local fw="$dst/AuraProtectedProtocolC.framework"
  local version_dir="$fw/Versions/A"

  rm -rf "$fw"
  mkdir -p "$version_dir/Headers" "$version_dir/Modules" "$version_dir/Resources"
  cp "$lib" "$version_dir/AuraProtectedProtocolC"
  cp "$ROOT"/include/*.h "$version_dir/Headers/"
  cp "$ROOT/include/module.modulemap" "$version_dir/Modules/"
  cp "$ROOT/include/module.modulemap" "$version_dir/Headers/"
  write_info_plist "$version_dir/Resources/Info.plist"

  (
    cd "$fw"
    ln -s A Versions/Current
    ln -s Versions/Current/AuraProtectedProtocolC AuraProtectedProtocolC
    ln -s Versions/Current/Headers Headers
    ln -s Versions/Current/Modules Modules
    ln -s Versions/Current/Resources Resources
  )

  install_name_tool -id "@rpath/AuraProtectedProtocolC.framework/Versions/A/AuraProtectedProtocolC" "$version_dir/AuraProtectedProtocolC"
}

create_static_framework "$ROOT/target/aarch64-apple-darwin/release/libaura_protected_protocol.a" "$FRAMEWORKS_DIR/macos-arm64"
create_static_framework "$ROOT/target/aarch64-apple-ios/release/libaura_protected_protocol.a" "$FRAMEWORKS_DIR/ios-arm64"
create_static_framework "$ROOT/target/libaura_protected_protocol_sim.a" "$FRAMEWORKS_DIR/ios-sim"
create_dynamic_framework "$ROOT/target/libaura_protected_protocol_maccatalyst.dylib" "$FRAMEWORKS_DIR/ios-maccatalyst"

rm -rf "$DIST_DIR/AuraProtectedProtocol.xcframework" "$DIST_DIR/AuraProtectedProtocol.xcframework.zip" "$DIST_DIR/AuraProtectedProtocol.xcframework.zip.sha256"

xcodebuild -create-xcframework \
  -framework "$FRAMEWORKS_DIR/macos-arm64/AuraProtectedProtocolC.framework" \
  -framework "$FRAMEWORKS_DIR/ios-arm64/AuraProtectedProtocolC.framework" \
  -framework "$FRAMEWORKS_DIR/ios-sim/AuraProtectedProtocolC.framework" \
  -framework "$FRAMEWORKS_DIR/ios-maccatalyst/AuraProtectedProtocolC.framework" \
  -output "$DIST_DIR/AuraProtectedProtocol.xcframework"

(
  cd "$DIST_DIR"
  zip -r AuraProtectedProtocol.xcframework.zip AuraProtectedProtocol.xcframework >/dev/null
  shasum -a 256 AuraProtectedProtocol.xcframework.zip > AuraProtectedProtocol.xcframework.zip.sha256
)

echo "Built: $DIST_DIR/AuraProtectedProtocol.xcframework.zip"
echo "SHA-256: $(cut -d' ' -f1 "$DIST_DIR/AuraProtectedProtocol.xcframework.zip.sha256")"
