#!/bin/sh
# fuzz: run every Go fuzz target of the module for a bounded time, one after another (Go
# fuzzes one target per invocation). The ordinary `go test` already runs each target's
# seeds; this script does the bounded mutation runs (c-hardening Req 8.2, 8.6). A target that
# fails leaves its input under <package>/testdata/fuzz/<Target>/: commit that file as a seed
# once the defect is fixed (Req 8.5). Nothing here needs root.
#
# usage: scripts/fuzz.sh [-t duration] [-m duration] [substring]
#   -t duration   per target, Go duration syntax (default 30s)
#   -m duration   cap on minimizing a new input (default 5s: with Go's 60s default the DNS
#                 record target spends whole runs minimizing 976-byte inputs)
#   substring     only targets whose name contains it (default: all)
# exit 0 every target ran without a failure, 1 a target failed or none was found, 2 usage
set -eu
cd "$(dirname "$0")/.."

usage() { sed -n '8,13p' "$0" | sed 's/^# \{0,1\}//'; }

time=30s minimize=5s
while getopts t:m:h opt; do
  case $opt in
    t) time=$OPTARG ;;
    m) minimize=$OPTARG ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
want=${1:-}

ran=0 failed=""
for pkg in $(go list ./...); do
  for target in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true); do
    case $target in *"$want"*) ;; *) continue ;; esac
    ran=$((ran + 1))
    echo "== $target ($pkg, $time)"
    if go test -run '^$' -fuzz "^$target\$" -fuzztime "$time" -fuzzminimizetime "$minimize" "$pkg"; then
      echo "PASS $target"
    else
      echo "FAIL $target: the failing input is in $(go list -f '{{.Dir}}' "$pkg")/testdata/fuzz/$target/"
      failed="$failed $target"
    fi
  done
done

[ "$ran" -gt 0 ] || { echo "fuzz: no target matches '$want'"; exit 1; }
if [ -n "$failed" ]; then
  echo "fuzz: $ran targets, failed:$failed"
  exit 1
fi
echo "fuzz: $ran targets, no failure in $time each"
