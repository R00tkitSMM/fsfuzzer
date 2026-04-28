#!/usr/bin/env bash
#
# Rebuild libprotobuf-mutator against the system protobuf + absl, so the
# `absl::lts_*` ABI tag in the .a file matches the one the system libprotobuf
# and libabsl_* were compiled with.
#
# This fixes link errors of the form:
#   undefined reference to 'absl::lts_20230802::log_internal::LogMessageFatal::...'
#   undefined reference to 'google::protobuf::MessageLite::ParsePartialFromString(absl::lts_20230802::string_view)'
# which mean the libprotobuf-mutator.a was built against a different absl
# release than what's installed on this system.

set -euo pipefail

PMUT_PREFIX="${PMUT_PREFIX:-/usr/local}"
BUILD_DIR="${BUILD_DIR:-/tmp/libprotobuf-mutator-build}"
SUDO="${SUDO:-sudo}"

command -v cmake  >/dev/null || { echo "install cmake first"; exit 1; }
command -v git    >/dev/null || { echo "install git first";   exit 1; }
command -v protoc >/dev/null || { echo "install protobuf-compiler / libprotobuf-dev first"; exit 1; }

echo "[+] Wiping any old install at $PMUT_PREFIX"
$SUDO rm -f \
  "$PMUT_PREFIX/lib/libprotobuf-mutator.a" \
  "$PMUT_PREFIX/lib/libprotobuf-mutator-libfuzzer.a" \
  "$PMUT_PREFIX/lib/pkgconfig/libprotobuf-mutator"*.pc
$SUDO rm -rf "$PMUT_PREFIX/include/libprotobuf-mutator"

echo "[+] Cloning libprotobuf-mutator into $BUILD_DIR"
rm -rf "$BUILD_DIR"
git clone --depth 1 https://github.com/google/libprotobuf-mutator.git "$BUILD_DIR"

mkdir -p "$BUILD_DIR/build"
cd       "$BUILD_DIR/build"

echo "[+] Configuring (against the SYSTEM protobuf, not a downloaded one)"
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PMUT_PREFIX" \
  -DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=OFF \
  -DLIB_PROTO_MUTATOR_TESTING=OFF \
  -DLIB_PROTO_MUTATOR_FUZZER_LIBRARIES=

echo "[+] Building"
make -j"$(nproc)"

echo "[+] Installing into $PMUT_PREFIX (sudo will prompt)"
$SUDO make install
$SUDO ldconfig || true

echo
echo "[+] Done. Now rerun ./build.sh in the fuzzer directory."
