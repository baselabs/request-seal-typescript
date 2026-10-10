#!/bin/sh
# A runner failure counts only when it executed the planted assertion.
set -eu
output=$(mktemp "${TMPDIR:-/tmp}/request-seal-red-proof-XXXXXX")
trap 'rm -f "$output"' EXIT HUP INT TERM
if "$@" >"$output" 2>&1; then
  cat "$output"
  echo 'Planted failure was accepted' >&2
  exit 1
fi
cat "$output"
# A different assertion can also produce a failing count; require the planted marker independently.
grep -F 'Intentional red proof' "$output" >/dev/null || exit 1
# Node TAP/spec, Deno and Bun each report a positive failing-test count.
grep -E '(^# fail [1-9][0-9]*|[[:space:]]fail [1-9][0-9]*|[1-9][0-9]* (fail|failed)([[:space:]]|$))' "$output" >/dev/null || exit 1
