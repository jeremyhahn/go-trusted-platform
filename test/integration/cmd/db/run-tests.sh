#!/bin/bash
# Integration tests for the db dump command
# Run from the repository root with: ./test/integration/cmd/db/run-tests.sh

set -e

# The tags come from the Makefile, never a hand-written list.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
BUILD_TAGS="${BUILD_TAGS:-integration $(make -s -C "$REPO_ROOT" print-build-tags)}"

echo "Running db dump integration tests..."
go test -tags "$BUILD_TAGS" -v -race -timeout 5m ./test/integration/cmd/db/...
