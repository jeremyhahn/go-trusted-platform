#!/bin/bash
# Integration tests for the db dump command
# Run from the repository root with: ./test/integration/cmd/db/run-tests.sh

set -e

export INTEGRATION_TEST=1

echo "Running db dump integration tests..."
go test -tags integration -v -race -timeout 5m ./test/integration/cmd/db/...
