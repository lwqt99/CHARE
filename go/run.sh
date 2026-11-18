#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
profile="${1:-sanity}"
if (($#)); then shift; fi
case "$profile" in
  sanity|paper) ;;
  *) printf 'Usage: %s [sanity|paper] [-params public.params] [-out results]\n' "$0" >&2; exit 2 ;;
esac
command -v go >/dev/null || { echo 'Go 1.23+ is required.' >&2; exit 1; }
export CGO_ENABLED=1
mkdir -p build
# GMP and PBC must already be installed. This script never changes the system.
if ! go test ./... -count=1 2>&1 | tee build/functional-tests.log; then
  echo 'Functional gate failed. Return build/functional-tests.log; no batch was started.' >&2
  exit 1
fi
if ! go build -o build/chare-runner . 2>&1 | tee build/build.log; then
  echo 'Build failed. Return build/build.log.' >&2
  exit 1
fi
exec ./build/chare-runner -config "config/${profile}.json" "$@"
