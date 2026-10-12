#!/bin/sh
# Run isolated DNS kernel tests; leave Go's cache configuration to the caller.
set -eu
cd "$(dirname "$0")/.."
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 2; }
unset GOFLAGS
if go test -tags root -count=1 -v ./internal/dns ./cmd/snitchd -run 'DNSProg' "$@"; then
  echo "PASS"
else
  echo "FAIL"
  exit 1
fi
