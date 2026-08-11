#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
DIST_DIR="${AURA_APPLE_DIST_DIR:-$ROOT/dist/apple}"
if [[ "$DIST_DIR" != /* ]]; then
  DIST_DIR="$ROOT/$DIST_DIR"
fi

if [[ -n "${RUSTFLAGS:-}" || -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]]; then
  echo "Refusing ambient Rust compiler flags for an Apple release artifact." >&2
  exit 2
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aura-protocol-apple-release.XXXXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT HUP INT TERM
WORK_DIR="$(cd "$WORK_DIR" && pwd -P)"
FRAMEWORKS_DIR="$WORK_DIR/frameworks"
export CARGO_TARGET_DIR="$WORK_DIR/cargo-target"

RUST_HOST="$(rustc -vV | sed -n 's/^host: //p')"
RUST_COMMIT_HASH="$(rustc -vV | sed -n 's/^commit-hash: //p')"
RUST_SYSROOT="$(cd "$(rustc --print sysroot)" && pwd -P)"
RUST_SOURCE_ROOT="$RUST_SYSROOT/lib/rustlib/src/rust"
[[ "$RUST_COMMIT_HASH" =~ ^[0-9a-f]{40}$ ]] || {
  echo "Unable to determine the exact Rust compiler commit." >&2
  exit 2
}
AURA_CARGO_HOME_PATH="${CARGO_HOME:-${HOME:?HOME is required when CARGO_HOME is unset}/.cargo}"
[[ -d "$AURA_CARGO_HOME_PATH" ]] || {
  echo "Cargo home is unavailable: $AURA_CARGO_HOME_PATH" >&2
  exit 2
}
AURA_CARGO_HOME_PATH="$(cd "$AURA_CARGO_HOME_PATH" && pwd -P)"

remap_flags=(
  "--remap-path-prefix=$ROOT=/aura/protocol/source"
  "--remap-path-prefix=$WORK_DIR=/aura/protocol/build"
  "--remap-path-prefix=$AURA_CARGO_HOME_PATH=/aura/cargo"
  "--remap-path-prefix=$RUST_SOURCE_ROOT=/rustc/$RUST_COMMIT_HASH"
  "--remap-path-prefix=$RUST_SYSROOT=/aura/rust"
)
printf -v CARGO_ENCODED_RUSTFLAGS '%s\x1f' "${remap_flags[@]}"
CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS%$'\x1f'}"
export CARGO_ENCODED_RUSTFLAGS

LLVM_STRIP="${AURA_LLVM_STRIP:-$RUST_SYSROOT/lib/rustlib/$RUST_HOST/bin/llvm-strip}"
[[ -x "$LLVM_STRIP" ]] || {
  echo "Rust llvm-strip is required; install llvm-tools-preview." >&2
  exit 2
}

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
    --locked \
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
    --locked \
    --features ffi \
    --target "$target" \
    --crate-type cdylib \
    -- \
    -C link-arg=-Wl,-no_uuid
done

MACOS_LIB="$WORK_DIR/libaura_protected_protocol_macos.a"
DEVICE_LIB="$WORK_DIR/libaura_protected_protocol_ios.a"
SIM_LIB="$WORK_DIR/libaura_protected_protocol_sim.a"
MACABI_STATIC_LIB="$WORK_DIR/libaura_protected_protocol_maccatalyst.a"
MACABI_DYNAMIC_LIB="$WORK_DIR/libaura_protected_protocol_maccatalyst.dylib"

cp "$CARGO_TARGET_DIR/aarch64-apple-darwin/release/libaura_protected_protocol.a" "$MACOS_LIB"
cp "$CARGO_TARGET_DIR/aarch64-apple-ios/release/libaura_protected_protocol.a" "$DEVICE_LIB"

lipo -create \
  "$CARGO_TARGET_DIR/aarch64-apple-ios-sim/release/libaura_protected_protocol.a" \
  "$CARGO_TARGET_DIR/x86_64-apple-ios/release/libaura_protected_protocol.a" \
  -output "$SIM_LIB"

lipo -create \
  "$CARGO_TARGET_DIR/aarch64-apple-ios-macabi/release/libaura_protected_protocol.a" \
  "$CARGO_TARGET_DIR/x86_64-apple-ios-macabi/release/libaura_protected_protocol.a" \
  -output "$MACABI_STATIC_LIB"

lipo -create \
  "$CARGO_TARGET_DIR/aarch64-apple-ios-macabi/release/libaura_protected_protocol.dylib" \
  "$CARGO_TARGET_DIR/x86_64-apple-ios-macabi/release/libaura_protected_protocol.dylib" \
  -output "$MACABI_DYNAMIC_LIB"

for binary in "$MACOS_LIB" "$DEVICE_LIB" "$SIM_LIB" "$MACABI_STATIC_LIB" "$MACABI_DYNAMIC_LIB"; do
  "$LLVM_STRIP" -S "$binary"
  strings "$binary" >"$WORK_DIR/$(basename "$binary").strings"
  for forbidden_path in \
    "$ROOT" \
    "$WORK_DIR" \
    "$AURA_CARGO_HOME_PATH" \
    "$RUST_SYSROOT"
  do
    if grep -F "$forbidden_path" "$WORK_DIR/$(basename "$binary").strings" >/dev/null; then
      echo "Release binary contains a local build path: $forbidden_path" >&2
      exit 1
    fi
  done
done

write_info_plist() {
  local plist="$1"

  /usr/libexec/PlistBuddy -c "Clear dict" "$plist" 2>/dev/null || true
  /usr/libexec/PlistBuddy -c "Add :CFBundleDevelopmentRegion string en" "$plist"
  /usr/libexec/PlistBuddy -c "Add :CFBundleExecutable string AuraProtectedProtocolC" "$plist"
  /usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string ai.auramessenger.AuraProtectedProtocolC" "$plist"
  /usr/libexec/PlistBuddy -c "Add :CFBundleInfoDictionaryVersion string 6.0" "$plist"
  /usr/libexec/PlistBuddy -c "Add :CFBundleName string AuraProtectedProtocolC" "$plist"
  /usr/libexec/PlistBuddy -c "Add :CFBundlePackageType string FMWK" "$plist"
  /usr/libexec/PlistBuddy -c "Add :CFBundleShortVersionString string 3.0.0" "$plist"
  /usr/libexec/PlistBuddy -c "Add :CFBundleVersion string 3.0.0" "$plist"
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

create_static_framework "$MACOS_LIB" "$FRAMEWORKS_DIR/macos-arm64"
create_static_framework "$DEVICE_LIB" "$FRAMEWORKS_DIR/ios-arm64"
create_static_framework "$SIM_LIB" "$FRAMEWORKS_DIR/ios-sim"
create_dynamic_framework "$MACABI_DYNAMIC_LIB" "$FRAMEWORKS_DIR/ios-maccatalyst"

rm -rf "$DIST_DIR/AuraProtectedProtocol.xcframework" "$DIST_DIR/AuraProtectedProtocol.xcframework.zip" "$DIST_DIR/AuraProtectedProtocol.xcframework.zip.sha256"

xcodebuild -create-xcframework \
  -framework "$FRAMEWORKS_DIR/macos-arm64/AuraProtectedProtocolC.framework" \
  -framework "$FRAMEWORKS_DIR/ios-arm64/AuraProtectedProtocolC.framework" \
  -framework "$FRAMEWORKS_DIR/ios-sim/AuraProtectedProtocolC.framework" \
  -framework "$FRAMEWORKS_DIR/ios-maccatalyst/AuraProtectedProtocolC.framework" \
  -output "$DIST_DIR/AuraProtectedProtocol.xcframework"

# xcodebuild does not guarantee AvailableLibraries ordering. Canonicalize the
# plist so provenance hashes compare release content rather than host ordering.
python3 - "$DIST_DIR/AuraProtectedProtocol.xcframework/Info.plist" <<'PY'
import os
import plistlib
import sys
import tempfile

path = sys.argv[1]
with open(path, "rb") as source:
    document = plistlib.load(source)
document["AvailableLibraries"] = sorted(
    document["AvailableLibraries"],
    key=lambda library: library["LibraryIdentifier"],
)
directory = os.path.dirname(path)
descriptor, temporary = tempfile.mkstemp(prefix="Info.", suffix=".plist", dir=directory)
try:
    with os.fdopen(descriptor, "wb") as destination:
        plistlib.dump(document, destination, fmt=plistlib.FMT_XML, sort_keys=True)
    os.replace(temporary, path)
except BaseException:
    os.unlink(temporary)
    raise
PY

(
  cd "$DIST_DIR"
  zip -r AuraProtectedProtocol.xcframework.zip AuraProtectedProtocol.xcframework >/dev/null
  shasum -a 256 AuraProtectedProtocol.xcframework.zip > AuraProtectedProtocol.xcframework.zip.sha256
)

echo "Built: $DIST_DIR/AuraProtectedProtocol.xcframework.zip"
echo "SHA-256: $(cut -d' ' -f1 "$DIST_DIR/AuraProtectedProtocol.xcframework.zip.sha256")"
