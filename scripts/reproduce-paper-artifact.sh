#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-quick}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${AURA_ARTIFACT_OUT:-"$ROOT/artifact-output/$STAMP-$MODE"}"

mkdir -p "$OUT"

finish() {
  local status=$?
  set +e

  {
    echo "artifact_mode=$MODE"
    echo "timestamp_utc=$STAMP"
    echo "repo_root=$ROOT"
    echo "exit_status=$status"
    echo
    echo "Files:"
    (
      cd "$OUT" || exit 0
      find . -type f ! -name MANIFEST.txt ! -name SHA256SUMS -print |
        LC_ALL=C sort |
        while IFS= read -r file; do
          bytes="$(wc -c < "$file" | tr -d ' ')"
          printf "%s\t%s bytes\n" "${file#./}" "$bytes"
        done
    )
  } > "$OUT/MANIFEST.txt"

  (
    cd "$OUT" || exit 0
    find . -type f ! -name SHA256SUMS -print |
      LC_ALL=C sort |
      while IFS= read -r file; do
        sha256sum "$file"
      done
  ) > "$OUT/SHA256SUMS"

  echo "artifact_logs=$OUT"
  echo "artifact_manifest=$OUT/MANIFEST.txt"
  echo "artifact_checksums=$OUT/SHA256SUMS"
  exit "$status"
}

trap finish EXIT

run() {
  local name="$1"
  shift
  echo "==> $name"
  "$@" 2>&1 | tee "$OUT/$name.log"
}

run_shell() {
  local name="$1"
  shift
  echo "==> $name"
  bash -lc "$*" 2>&1 | tee "$OUT/$name.log"
}

versions() {
  {
    echo "artifact_mode=$MODE"
    echo "timestamp_utc=$STAMP"
    echo "repo_root=$ROOT"
    git -C "$ROOT" rev-parse HEAD 2>/dev/null | sed 's/^/git_head=/'
    git -C "$ROOT" status --short 2>/dev/null | sed 's/^/git_status=/' || true
    rustc --version 2>/dev/null | sed 's/^/rustc=/'
    cargo --version 2>/dev/null | sed 's/^/cargo=/'
    protoc --version 2>/dev/null | sed 's/^/protoc=/' || echo "protoc=missing"
    pdflatex --version 2>/dev/null | head -n 1 | sed 's/^/pdflatex=/' || echo "pdflatex=missing"
    tamarin-prover --version 2>/dev/null | head -n 1 | sed 's/^/tamarin=/' || echo "tamarin=missing"
    proverif -version 2>/dev/null | head -n 1 | sed 's/^/proverif=/' || echo "proverif=missing"
  } | tee "$OUT/versions.txt"
}

paper_build() {
  run_shell paper_english \
    "cd '$ROOT/docs' && pdflatex -interaction=nonstopmode -halt-on-error aura-paper.tex >/tmp/aura-paper-repro-1.log && pdflatex -interaction=nonstopmode -halt-on-error aura-paper.tex >/tmp/aura-paper-repro-2.log && pdflatex -interaction=nonstopmode -halt-on-error aura-paper.tex"
  run_shell paper_ukrainian \
    "cd '$ROOT/docs' && pdflatex -interaction=nonstopmode -halt-on-error aura-paper-ua.tex >/tmp/aura-paper-ua-repro-1.log && pdflatex -interaction=nonstopmode -halt-on-error aura-paper-ua.tex >/tmp/aura-paper-ua-repro-2.log && pdflatex -interaction=nonstopmode -halt-on-error aura-paper-ua.tex"
  rm -f "$ROOT"/docs/aura-paper.{aux,log,out,toc} "$ROOT"/docs/aura-paper-ua.{aux,log,out,toc}
}

case "$MODE" in
  quick)
    versions
    run paper_vectors_test cargo test --release --features test-vectors --test paper_vectors
    run paper_vectors_dump cargo run --release --features test-vectors --example paper_vectors
    run attack_poc_tests cargo test --release --test attack_poc
    ;;
  test)
    versions
    run all_tests cargo test --release
    run all_tests_ffi cargo test --release --features ffi
    ;;
  formal)
    versions
    run formal_handshake make -C "$ROOT/formal" handshake
    run formal_ratchet make -C "$ROOT/formal" ratchet
    run formal_proverif make -C "$ROOT/formal" proverif
    ;;
  paper)
    versions
    paper_build
    ;;
  bench)
    versions
    run benchmarks cargo bench
    ;;
  full)
    versions
    run paper_vectors_test cargo test --release --features test-vectors --test paper_vectors
    run paper_vectors_dump cargo run --release --features test-vectors --example paper_vectors
    run all_tests cargo test --release
    run all_tests_ffi cargo test --release --features ffi
    run formal_handshake make -C "$ROOT/formal" handshake
    run formal_ratchet make -C "$ROOT/formal" ratchet
    run formal_proverif make -C "$ROOT/formal" proverif
    paper_build
    run benchmarks cargo bench
    ;;
  *)
    cat >&2 <<EOF
usage: $0 [quick|test|formal|paper|bench|full]

quick  - fixed paper vectors + attack PoC tests
test   - full Rust tests, with and without ffi
formal - Tamarin handshake/ratchet + ProVerif
paper  - rebuild English and Ukrainian PDFs
bench  - Criterion benchmark suite
full   - test + formal + paper + bench

Logs are written to: $OUT
EOF
    exit 2
    ;;
esac
