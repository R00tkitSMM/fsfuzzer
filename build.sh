#!/usr/bin/env bash
set -euo pipefail

# Linux build script.
#
# Required packages (Debian/Ubuntu names, adjust for your distro):
#   clang lld
#   protobuf-compiler libprotobuf-dev
#   libprotobuf-mutator-dev          # or build from source, see PMUT_PREFIX
#   libabsl-dev                      # protobuf 22+ depends on Abseil
#   pkg-config
#
# Override any of these via env vars if your toolchain lives elsewhere:
#   CC, CXX, PROTOC, PKG_CONFIG_BIN, PMUT_PREFIX
#   DEBUG=1                          # debug build

CC="${CC:-clang}"
CXX="${CXX:-clang++}"
PROTOC="${PROTOC:-protoc}"
PKG_CONFIG_BIN="${PKG_CONFIG_BIN:-pkg-config}"

echo "clang:   $CC"
echo "clang++: $CXX"

if [[ "${DEBUG:-0}" == "1" ]]; then
  OPT_FLAGS="-O0 -g -DDEBUG"
  echo "Build mode: DEBUG"
else
  OPT_FLAGS="-O2 -g"
  echo "Build mode: RELEASE"
fi

# protobuf (cflags/libs) via pkg-config.
PROTO_CFLAGS=$("$PKG_CONFIG_BIN" --cflags protobuf)
PROTO_LIBS=$("$PKG_CONFIG_BIN" --libs protobuf)

# libprotobuf-mutator: prefer pkg-config, fall back to common install prefixes.
if "$PKG_CONFIG_BIN" --exists libprotobuf-mutator-libfuzzer 2>/dev/null; then
  PMUT_CFLAGS=$("$PKG_CONFIG_BIN" --cflags libprotobuf-mutator-libfuzzer)
  PMUT_LIBS=$("$PKG_CONFIG_BIN" --libs libprotobuf-mutator-libfuzzer)
else
  # Manual fallback. Override PMUT_PREFIX to point at a custom install.
  PMUT_PREFIX="${PMUT_PREFIX:-/usr/local}"
  if [[ -d "$PMUT_PREFIX/include/libprotobuf-mutator" ]]; then
    PMUT_CFLAGS="-I$PMUT_PREFIX/include/libprotobuf-mutator"
  elif [[ -d "/usr/include/libprotobuf-mutator" ]]; then
    PMUT_CFLAGS="-I/usr/include/libprotobuf-mutator"
  else
    PMUT_CFLAGS=""
  fi
  PMUT_LIBS="-L$PMUT_PREFIX/lib -lprotobuf-mutator-libfuzzer -lprotobuf-mutator"
fi

# Modern protobuf (>= 22) depends on Abseil. Pick up absl libs from
# pkg-config when each module is packaged separately, otherwise fall back to
# a hard-coded list of -l flags. The unused ones are silently dropped by
# `-Wl,--as-needed`.
ABSL_PC_MODULES=(
  absl_log_internal_check_op
  absl_log_internal_message
  absl_log_internal_format
  absl_log_internal_log_sink_set
  absl_log_internal_globals
  absl_log_internal_conditions
  absl_log_internal_proto
  absl_log_internal_nullguard
  absl_log_globals
  absl_log_severity
  absl_log_sink
  absl_log_initialize
  absl_log_entry
  absl_strings
  absl_strings_internal
  absl_str_format_internal
  absl_synchronization
  absl_graphcycles_internal
  absl_base
  absl_raw_logging_internal
  absl_spinlock_wait
  absl_throw_delegate
  absl_status
  absl_statusor
  absl_int128
  absl_cord
  absl_cord_internal
  absl_cordz_info
  absl_cordz_handle
  absl_cordz_functions
  absl_civil_time
  absl_time_zone
  absl_time
  absl_hash
  absl_city
  absl_low_level_hash
)

ABSL_LIBS=""
for pkg in "${ABSL_PC_MODULES[@]}"; do
  if "$PKG_CONFIG_BIN" --exists "$pkg" 2>/dev/null; then
    ABSL_LIBS="$ABSL_LIBS $("$PKG_CONFIG_BIN" --libs "$pkg")"
  fi
done

# Fallback: if no absl pkg-config files were found, just emit -l flags for
# every module above. The linker drops the ones that don't exist.
if [[ -z "$ABSL_LIBS" ]]; then
  for pkg in "${ABSL_PC_MODULES[@]}"; do
    ABSL_LIBS="$ABSL_LIBS -l${pkg}"
  done
fi

# ld.gold (Ubuntu's default in some versions) doesn't support
# --copy-dt-needed-entries and chokes on libprotobuf.so's transitive libz
# dependency. Force ld.bfd or ld.lld; both follow DT_NEEDED chains and
# resolve archive members properly.
LINKER="${LINKER:-bfd}"  # set LINKER=lld if you have lld installed
LDFLAGS_COMMON="-fuse-ld=${LINKER} -Wl,--as-needed,--copy-dt-needed-entries"

echo "PMUT_CFLAGS: $PMUT_CFLAGS"
echo "PMUT_LIBS:   $PMUT_LIBS"
echo "ABSL_LIBS:   $ABSL_LIBS"

"$PROTOC" --cpp_out=. --python_out=. fuzz_filesys.proto

# --start-group / --end-group lets the linker walk the archives multiple
# times so libprotobuf-mutator.a, libprotobuf, and absl can all resolve
# each other's back-references. -lz handles libprotobuf's transitive zlib
# dependency.
LINK_GROUP="-Wl,--start-group $PMUT_LIBS $PROTO_LIBS $ABSL_LIBS -lz -Wl,--end-group"

# fuzz_filesys: in-process libFuzzer build.
$CXX -std=c++17 $OPT_FLAGS -fsanitize=fuzzer \
  -I. \
  $PROTO_CFLAGS $PMUT_CFLAGS \
  fuzz_filesys.cc fuzz_filesys.pb.cc \
  $LDFLAGS_COMMON \
  $LINK_GROUP \
  -lpthread \
  -o fuzz_filesys

# fork_base: forking variant that uses kcov for kernel coverage.
# Requires running on Linux as a user that can open /sys/kernel/debug/kcov
# (typically root, or a process with CAP_SYS_ADMIN + debugfs mounted).
$CXX -std=c++17 $OPT_FLAGS -fsanitize=fuzzer \
  -I. \
  $PROTO_CFLAGS $PMUT_CFLAGS \
  fork_base.cc fuzz_filesys.pb.cc \
  $LDFLAGS_COMMON \
  $LINK_GROUP \
  -lpthread \
  -o fork_base
