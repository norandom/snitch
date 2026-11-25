#!/bin/sh
# bindings-regen: regenerate the committed bpf2go bindings (internal/bpf/) with the pinned
# toolchain, then compare them with the tree (--check) or write them into it (--write).
#
# The committed objects are what releases ship; nothing a CI compiler produces is ever
# committed or released (c-hardening Req 7.6, 7.7). --check only observes. --write is the
# maintainer's step after a C change. This script is the one place that names the toolchain
# the committed bytes are tied to: the pinned packages and the expected compiler line below.
# The Dagger bindings check runs it with --install --check in the pinned image (.dagger/pins.go
# names the same image digest as IMAGE below; keep the two equal).
#
# usage: scripts/bindings-regen.sh [--check|--write] [--docker] [--install]
#   --check    (default) regenerate a copy and compare every file of internal/bpf/
#   --write    regenerate and copy the result into internal/bpf/
#   --docker   run inside the pinned image through docker (host use, no sudo needed)
#   --install  apt-install the pinned packages first (inside a debian container)
#   --emit DIR regenerate into DIR only (the inner half of --docker)
# exit 0 identical / written, 1 stale or generation failed (names the files), 2 usage,
#      3 the compiler differs from the pin, 4 the environment is unavailable
set -eu

IMAGE=debian@sha256:f3671d5a279b1ae356c7318ce6cdb84c600c2063d708ee97d3cce607bebfb85a
# clang/llvm are the identity of the bytes; libbpf-dev's helper declarations decide what
# compiles at all (1.6.3 rejects snitch.bpf.c's const bpf_d_path argument). Go's version does
# not reach the output, so golang-go is not pinned.
PACKAGES="clang=1:21.1.8-74 clang-21=1:21.1.8-13 llvm=1:21.1.8-74 llvm-21=1:21.1.8-13 libbpf-dev=1:1.7.0-1 golang-go ca-certificates"
CLANG_EXPECTED="Debian clang version 21.1.8 (13)"
# --install reads apt from this dated snapshot.debian.org state (the one IMAGE was built
# from, its debian.sources names it), so the pinned versions stay installable after forky
# moves on. BINDINGS_SNAPSHOT overrides it; BINDINGS_SNAPSHOT= (empty) uses IMAGE's live
# sources. Plain http: the base image has no CA bundle, apt checks the archive signature.
SNAPSHOT=${BINDINGS_SNAPSHOT-20261123T000000Z}

usage() { sed -n '12,19p' "$0" | sed 's/^# \{0,1\}//'; }

mode=check docker=no install=no emit=""
while [ $# -gt 0 ]; do
  case $1 in
    --check) mode="check" ;;
    --write) mode="write" ;;
    --docker) docker=yes ;;
    --install) install=yes ;;
    --emit) [ $# -ge 2 ] || { usage >&2; exit 2; }; mode=emit; emit=$2; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done
repo=$(cd "$(dirname "$0")/.." && pwd)

# compare <committed dir> <regenerated dir>: every file on either side must match.
compare() {
  stale=""
  for f in "$1"/* "$2"/*; do
    n=${f##*/}
    case " $stale " in *" $n "*) continue ;; esac
    cmp -s "$1/$n" "$2/$n" || stale="$stale $n"
  done
  if [ -n "$stale" ]; then
    echo "bindings are stale:$stale"
    echo "regenerate with: scripts/bindings-regen.sh --docker --write"
    return 1
  fi
  echo "bindings: identical to the regeneration with $CLANG_EXPECTED"
}

# regenerate <src tree> <out dir>: go generate on a copy, the bindings land in <out dir>.
regenerate() {
  w=$(mktemp -d)
  (cd "$1" && tar -cf - --exclude=./.git .) | tar -xf - -C "$w"
  if ! (cd "$w" && GOFLAGS=-buildvcs=false GOTOOLCHAIN=auto go generate ./internal/bpf/); then
    echo "bindings: generation failed with $CLANG_EXPECTED (see the compiler output above)"
    return 1
  fi
  cp "$w"/internal/bpf/* "$2"/
  rm -rf "$w"
}

if [ "$docker" = yes ]; then
  command -v docker >/dev/null 2>&1 || { echo "bindings: environment unavailable: no docker"; exit 4; }
  out=$(mktemp -d)
  rc=0
  docker run --rm -v "$repo":/src:ro -v "$out":/out -e HOME=/tmp -e OWNER="$(id -u):$(id -g)" \
    -e BINDINGS_SNAPSHOT="$SNAPSHOT" \
    "$IMAGE" sh -c 'sh /src/scripts/bindings-regen.sh --install --emit /out; rc=$?; chown -R "$OWNER" /out; exit $rc' \
    || rc=$?
  if [ "$rc" -eq 0 ]; then
    if [ "$mode" = write ]; then
      cp "$out"/* "$repo"/internal/bpf/
      echo "bindings: written to internal/bpf/ (review the diff, then commit)"
    else
      compare "$repo"/internal/bpf "$out" || rc=1
    fi
  fi
  rm -rf "$out"
  exit "$rc"
fi

if [ "$install" = yes ]; then
  if [ -n "$SNAPSHOT" ]; then
    printf '%s\n' "Types: deb" "URIs: http://snapshot.debian.org/archive/debian/$SNAPSHOT/" \
      "Suites: forky" "Components: main" "Check-Valid-Until: no" \
      "Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp" \
      >/etc/apt/sources.list.d/debian.sources
  fi
  # $PACKAGES is a word list on purpose
  # shellcheck disable=SC2086
  if ! { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
      --no-install-recommends $PACKAGES >/dev/null; }; then
    echo "bindings: environment unavailable: the pinned packages do not install ($PACKAGES; snapshot ${SNAPSHOT:-none})"
    exit 4
  fi
fi
for tool in clang llvm-strip go; do
  command -v "$tool" >/dev/null 2>&1 || { echo "bindings: environment unavailable: no $tool"; exit 4; }
done
have=$(clang --version | head -n 1)
[ "$have" = "$CLANG_EXPECTED" ] || {
  echo "bindings: the compiler is '$have', the committed bindings are tied to '$CLANG_EXPECTED'"
  exit 3
}

out=$(mktemp -d)
regenerate "$repo" "$out" || exit 1
case $mode in
  emit) cp "$out"/* "$emit"/ ;;
  check) compare "$repo"/internal/bpf "$out" || { rm -rf "$out"; exit 1; } ;;
  write) cp "$out"/* "$repo"/internal/bpf/; echo "bindings: written to internal/bpf/" ;;
esac
rm -rf "$out"
