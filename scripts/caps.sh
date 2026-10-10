#!/bin/sh
# caps: the code-shape gates from .kiro/steering/tech.md, run by CI and by hand.
#   functions <= 40 body lines and files <= 300 lines (tools/caps), cyclomatic <= 10 (gocyclo).
# Scope: packages in CAPS_PKGS (default: internal/ without the generated bindings, plus tools/).
# cmd/ joins the scope in task 6.3 of the rule-loading spec.
set -eu
cd "$(dirname "$0")/.."
if [ -z "${CAPS_PKGS:-}" ]; then
  all=$(go list ./internal/... ./tools/...)   # a go list error fails the gate (set -e)
  pkgs=$(echo "$all" | grep -v '/internal/bpf$' || true)
else
  pkgs=$CAPS_PKGS
fi
if [ -z "$pkgs" ]; then
  echo "caps: no packages in scope yet"
  exit 0
fi
# shellcheck disable=SC2086  # $pkgs / $dirs are lists of import paths / directories
dirs=$(go list -f '{{.Dir}}' $pkgs)
# shellcheck disable=SC2086
go run ./tools/caps -func 40 -file 300 $dirs
# shellcheck disable=SC2086
go run github.com/fzipp/gocyclo/cmd/gocyclo@v0.6.0 -over 10 $dirs
echo "caps: ok ($(echo "$pkgs" | wc -l) packages)"
