// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration

package kms

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// kmsSecretsMissingReason names where the MISSING cells are recorded.
const kmsSecretsMissingReason = "docs/kms/api.md §4 records it MISSING (docs/13 G7)"

// kmsSecretsMissing lists, per secrets operation, the transports that have no
// surface for it (docs/kms/api.md §4). The cell is asserted as a typed refusal.
var kmsSecretsMissing = map[string][]string{
	"SecretsRotate":   {quicTransport, "MCP"},
	"SecretsVersions": {"gRPC", "Unix", quicTransport, "MCP"},
	"SecretsVersion":  {"gRPC", "Unix", quicTransport, "MCP"},
	"SecretsRollback": {"gRPC", "Unix", quicTransport, "MCP"},
	"SecretsStatus":   {quicTransport, "MCP"},
}

// kmsSecretsGapMethods maps each secrets operation to the quicbaas.Secrets
// method the embedded SDK transport leaves unrouted (go-quicbaas #1540).
var kmsSecretsGapMethods = map[string]string{
	"SecretsRotate":   "Rotate",
	"SecretsVersions": "ListVersions",
	"SecretsVersion":  "GetVersion",
	"SecretsRollback": "Rollback",
	"SecretsStatus":   "UpdateStatus",
}

// kmsSecretsMissingOn reports whether transport has no surface for op.
func kmsSecretsMissingOn(transport, op string) bool {
	return slices.Contains(kmsSecretsMissing[op], transport)
}

// kmsSecretsRefused reports whether err is the declared outcome of op on cmd's
// transport, so the caller stops: the typed refusal on a MISSING cell, or the
// go-quicbaas #1540 gap on a transport that serves op. It fails t when a
// MISSING cell answers with anything but a typed refusal.
func kmsSecretsRefused(t *testing.T, cmd KMSCommands, op string, err error) bool {
	t.Helper()
	if kmsSecretsMissingOn(cmd.Name(), op) {
		assert.Truef(t, surface.IsNotImplemented(err),
			"%s %s has no surface (%s): got %v, want a typed refusal", cmd.Name(), op, kmsSecretsMissingReason, err)
		t.Logf("MISSING: %s %s: %s", cmd.Name(), op, kmsSecretsMissingReason)
		return true
	}
	method, gapped := kmsSecretsGapMethods[op]
	if !gapped {
		return false
	}
	// Declared gap: go-quicbaas #1540 — flips to the success path on the pin bump that carries the fix.
	return helpers.GapEmbeddedSecrets.UnservedOverWire(t, method, err)
}

// kmsSecretsDeclaredMissing probes op with call on a MISSING cell and asserts
// the typed refusal before the caller spends any setup on it. It reports
// whether op is MISSING on cmd's transport.
func kmsSecretsDeclaredMissing(t *testing.T, cmd KMSCommands, op string, call func() error) bool {
	t.Helper()
	if !kmsSecretsMissingOn(cmd.Name(), op) {
		return false
	}
	return kmsSecretsRefused(t, cmd, op, call())
}
