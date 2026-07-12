#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

FILES=(
  "$ROOT/docs/aura-paper.tex"
  "$ROOT/docs/aura-paper-ua.tex"
)

extract_bibitems() {
  perl -ne 'while(/\\bibitem(?:\[[^\]]*\])?\{([^}]+)\}/g){ print "$1\n" }' "$1" |
    LC_ALL=C sort -u
}

extract_cites() {
  perl -ne 'while(/\\cite[a-zA-Z*]*(?:\[[^\]]*\]){0,2}\{([^}]*)\}/g){ for $k (split /,/, $1){ $k =~ s/^\s+|\s+$//g; print "$k\n" if length $k } }' "$1" |
    LC_ALL=C sort -u
}

extract_urls() {
  perl -ne 'while(/\\url\{([^}]+)\}/g){ print "$1\n" }' "${FILES[@]}" |
    LC_ALL=C sort -u
}

echo "==> bibliography consistency"

for file in "${FILES[@]}"; do
  name="${file#$ROOT/}"
  safe_name="${name//\//_}"
  bib="$TMPDIR/$safe_name.bib"
  cite="$TMPDIR/$safe_name.cite"
  missing="$TMPDIR/$safe_name.missing"
  uncited="$TMPDIR/$safe_name.uncited"

  extract_bibitems "$file" > "$bib"
  extract_cites "$file" > "$cite"
  comm -23 "$cite" "$bib" > "$missing"
  comm -13 "$cite" "$bib" > "$uncited"

  bib_count="$(wc -l < "$bib" | tr -d ' ')"
  cite_count="$(wc -l < "$cite" | tr -d ' ')"
  missing_count="$(wc -l < "$missing" | tr -d ' ')"
  uncited_count="$(wc -l < "$uncited" | tr -d ' ')"

  printf '%s bibitems=%s cited_unique=%s missing=%s uncited=%s\n' \
    "$name" "$bib_count" "$cite_count" "$missing_count" "$uncited_count"

  if [[ "$missing_count" != "0" ]]; then
    echo "missing bibliography entries in $name:"
    sed 's/^/  /' "$missing"
  fi
  if [[ "$uncited_count" != "0" ]]; then
    echo "uncited bibliography entries in $name:"
    sed 's/^/  /' "$uncited"
  fi

  [[ "$missing_count" == "0" ]]
  [[ "$uncited_count" == "0" ]]
done

echo "==> external URL reachability"

urls="$TMPDIR/urls"
extract_urls > "$urls"
url_count="$(wc -l < "$urls" | tr -d ' ')"
echo "unique_urls=$url_count"

hard_failures=0
warnings=0
while IFS= read -r url; do
  if [[ ! "$url" =~ ^https?://[^[:space:]]+$ ]]; then
    printf 'INVALID %s\n' "$url"
    hard_failures=$((hard_failures + 1))
    continue
  fi

  code="$(
    curl -L \
      -A 'Mozilla/5.0 reference-audit' \
      --connect-timeout 10 \
      --max-time 30 \
      --retry 2 \
      --retry-delay 1 \
      -o /dev/null \
      -s \
      -w '%{http_code}' \
      "$url" || true
  )"
  code="${code:-000}"
  printf '%s %s\n' "$code" "$url"
  case "$code" in
    2??|3??)
      ;;
    000|401|403|408|420|425|429|451|5??)
      # DNS/TLS/timeouts, access controls, rate limiting, bot blocking, and
      # upstream outages are not evidence that a citation is dead. Keep them
      # visible in the artifact without making PR CI depend on third parties.
      warnings=$((warnings + 1))
      ;;
    *)
      # Other final 4xx responses (notably 404/410) are deterministic evidence
      # of a malformed or removed reference and remain release-blocking.
      hard_failures=$((hard_failures + 1))
      ;;
  esac
done < "$urls"

if (( hard_failures > 0 )); then
  echo "reference audit failed: $hard_failures URL(s) returned a hard HTTP failure" >&2
  exit 1
fi

echo "reference audit passed: $warnings transient/access-controlled URL warning(s)"
