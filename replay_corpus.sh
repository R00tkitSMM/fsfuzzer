#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: replay_corpus.sh <binary> <corpus_dir> [timeout_secs]

Replays each file in a corpus directory one-by-one against the given binary,
records per-input status, and stores stdout/stderr logs for triage.

Examples:
  ./replay_corpus.sh ./fuzz_filesys ./corpus_binary
  ./replay_corpus.sh ./fork_base ./corpus_binary 5

Environment:
  FSFUZZ_ENABLE_ASYNC_UNSAFE=1   Enable async/event syscalls if the harness
                                 was built with the safety gate.
EOF
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
  usage
  exit 2
fi

BIN="$1"
CORPUS_DIR="$2"
TIMEOUT_SECS="${3:-10}"

if [[ ! -x "$BIN" ]]; then
  echo "binary is not executable: $BIN" >&2
  exit 2
fi

if [[ ! -d "$CORPUS_DIR" ]]; then
  echo "corpus dir not found: $CORPUS_DIR" >&2
  exit 2
fi

if ! [[ "$TIMEOUT_SECS" =~ ^[0-9]+$ ]] || [[ "$TIMEOUT_SECS" -le 0 ]]; then
  echo "timeout must be a positive integer: $TIMEOUT_SECS" >&2
  exit 2
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="replay-logs-$STAMP"
mkdir -p "$OUT_DIR"

SUMMARY="$OUT_DIR/summary.tsv"
touch "$SUMMARY"

run_with_timeout() {
  local timeout_secs="$1"
  shift
  python3 - "$timeout_secs" "$@" <<'PY'
import os
import signal
import subprocess
import sys

timeout = int(sys.argv[1])
argv = sys.argv[2:]

proc = subprocess.Popen(argv)
try:
    rc = proc.wait(timeout=timeout)
    sys.exit(rc)
except subprocess.TimeoutExpired:
    try:
        proc.terminate()
        rc = proc.wait(timeout=1)
    except subprocess.TimeoutExpired:
        proc.kill()
        rc = proc.wait()
    sys.exit(124)
PY
}

total=0
ok=0
failed=0
timed_out=0

while IFS= read -r -d '' input; do
  total=$((total + 1))
  name="$(basename "$input")"
  safe_name="${name//[^A-Za-z0-9._-]/_}"
  log="$OUT_DIR/$safe_name.log"

  echo "[$total] running $input"
  set +e
  run_with_timeout "$TIMEOUT_SECS" "$BIN" "$input" >"$log" 2>&1
  rc=$?
  set -e

  status="ok"
  if [[ "$rc" -eq 124 ]]; then
    status="timeout"
    timed_out=$((timed_out + 1))
  elif [[ "$rc" -ne 0 ]]; then
    status="fail"
    failed=$((failed + 1))
  else
    ok=$((ok + 1))
  fi

  printf "%s\t%s\t%s\n" "$status" "$rc" "$input" >>"$SUMMARY"
done < <(find "$CORPUS_DIR" -type f -print0 | sort -z)

echo
echo "Summary"
echo "  logs:     $OUT_DIR"
echo "  total:    $total"
echo "  ok:       $ok"
echo "  failed:   $failed"
echo "  timeout:  $timed_out"
echo
echo "Failed inputs:"
grep -P '^fail\t' "$SUMMARY" || true
echo
echo "Timed out inputs:"
grep -P '^timeout\t' "$SUMMARY" || true
