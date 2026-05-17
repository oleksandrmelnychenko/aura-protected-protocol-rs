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
trap 'exit 130' INT
trap 'exit 143' TERM

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
    uname -a 2>/dev/null | sed 's/^/uname=/'
    if [ -r /etc/os-release ]; then
      . /etc/os-release
      echo "os=${PRETTY_NAME:-unknown}"
    fi
    lscpu 2>/dev/null | awk -F: '/^(Architecture|CPU\(s\)|Model name|Vendor ID)/ { gsub(/^[ \t]+/, "", $2); print "cpu_" $1 "=" $2 }' || true
    rustc --version 2>/dev/null | sed 's/^/rustc=/'
    rustc -vV 2>/dev/null | sed 's/^/rustc_vv=/' || true
    cargo --version 2>/dev/null | sed 's/^/cargo=/'
    sha256sum "$ROOT/Cargo.lock" 2>/dev/null | awk '{ print "cargo_lock_sha256="$1 }' || true
    env | LC_ALL=C sort | grep -E '^(CARGO|RUSTFLAGS|RUSTUP_TOOLCHAIN)=' | sed 's/^/env_/' || true
    echo "artifact_build_profiles=release tests/examples; bench mode uses Cargo bench profile"
    protoc --version 2>/dev/null | sed 's/^/protoc=/' || echo "protoc=missing"
    curl --version 2>/dev/null | head -n 1 | sed 's/^/curl=/' || echo "curl=missing"
    pdflatex --version 2>/dev/null | head -n 1 | sed 's/^/pdflatex=/' || echo "pdflatex=missing"
    if command -v tamarin-prover >/dev/null 2>&1; then
      tamarin-prover --version 2>/dev/null | head -n 1 | sed 's/^/tamarin=/'
    else
      echo "tamarin=missing"
    fi
    if command -v proverif >/dev/null 2>&1; then
      proverif -help 2>&1 | head -n 1 | sed 's/^/proverif=/'
    else
      echo "proverif=missing"
    fi
  } | tee "$OUT/versions.txt"
}

capture_criterion() {
  if [ -d "$ROOT/target/criterion" ]; then
    tar -C "$ROOT/target" -czf "$OUT/criterion.tar.gz" criterion
  fi
}

paper_build() {
  run_shell paper_english \
    "rm -rf '$OUT/aura-paper-build' && mkdir -p '$OUT/aura-paper-build' && cd '$ROOT/docs' && pdflatex -interaction=nonstopmode -halt-on-error -output-directory='$OUT/aura-paper-build' aura-paper.tex >'$OUT/paper_english_pass1.log' && pdflatex -interaction=nonstopmode -halt-on-error -output-directory='$OUT/aura-paper-build' aura-paper.tex >'$OUT/paper_english_pass2.log' && pdflatex -interaction=nonstopmode -halt-on-error -output-directory='$OUT/aura-paper-build' aura-paper.tex && cp '$OUT/aura-paper-build/aura-paper.pdf' '$OUT/aura-paper.pdf'"
  run_shell paper_ukrainian \
    "rm -rf '$OUT/aura-paper-ua-build' && mkdir -p '$OUT/aura-paper-ua-build' && cd '$ROOT/docs' && pdflatex -interaction=nonstopmode -halt-on-error -output-directory='$OUT/aura-paper-ua-build' aura-paper-ua.tex >'$OUT/paper_ukrainian_pass1.log' && pdflatex -interaction=nonstopmode -halt-on-error -output-directory='$OUT/aura-paper-ua-build' aura-paper-ua.tex >'$OUT/paper_ukrainian_pass2.log' && pdflatex -interaction=nonstopmode -halt-on-error -output-directory='$OUT/aura-paper-ua-build' aura-paper-ua.tex && cp '$OUT/aura-paper-ua-build/aura-paper-ua.pdf' '$OUT/aura-paper-ua.pdf'"
  run_shell security_proof \
    "rm -rf '$OUT/security-proof-build' && mkdir -p '$OUT/security-proof-build' && pdflatex -interaction=nonstopmode -halt-on-error -output-directory='$OUT/security-proof-build' '$ROOT/docs/security-proof.tex' >'$OUT/security_proof_pass1.log' && pdflatex -interaction=nonstopmode -halt-on-error -output-directory='$OUT/security-proof-build' '$ROOT/docs/security-proof.tex' >'$OUT/security_proof_pass2.log' && pdflatex -interaction=nonstopmode -halt-on-error -output-directory='$OUT/security-proof-build' '$ROOT/docs/security-proof.tex' && cp '$OUT/security-proof-build/security-proof.pdf' '$OUT/security-proof.pdf'"
}

reference_audit() {
  run reference_audit "$ROOT/scripts/audit-paper-references.sh"
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
  references)
    versions
    reference_audit
    ;;
  bench)
    versions
    run benchmarks cargo bench
    capture_criterion
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
    reference_audit
    run benchmarks cargo bench
    capture_criterion
    ;;
  *)
    cat >&2 <<EOF
usage: $0 [quick|test|formal|paper|references|bench|full]

quick  - fixed paper vectors + attack PoC tests
test   - full Rust tests, with and without ffi
formal - Tamarin handshake/ratchet + ProVerif
paper  - rebuild English, Ukrainian, and companion proof PDFs
references - verify paper bibliography/citation consistency and URL reachability
bench  - Criterion benchmark suite
full   - test + formal + paper + references + bench

Logs are written to: $OUT
EOF
    exit 2
    ;;
esac
