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

// Owner ruling 1234 approves this table for four operations; the Tenant
// approved a fifth, quicbaas.Secrets/UpdateStatus, on 2026-11-26. No others;
// a row that starts passing fails the gate; delete this file and its call
// sites with the go-quicbaas tag that routes them.

package helpers

import (
	"strings"
	"testing"
)

// The five go-quicbaas methods the embedded transport does not route at the
// pinned tag (owner ruling 1234 and the Tenant's 2026-11-26 fifth row).
const (
	MethodIAMUserAssignRole   = "quicbaas.IAM.User/AssignRole"
	MethodIAMUserRevokeRole   = "quicbaas.IAM.User/RevokeRole"
	MethodIAMGroupAddMember   = "quicbaas.IAM.Group/AddMember"
	MethodSecretsRotate       = "quicbaas.Secrets/Rotate"
	MethodSecretsUpdateStatus = "quicbaas.Secrets/UpdateStatus"
)

// KnownGapsRemovedBy names the change that deletes the table.
const KnownGapsRemovedBy = "the first go-quicbaas tag after v0.12.0-alpha that routes these methods in the embedded transport"

// KnownGapRow says why a method is a known gap and what removes the row.
type KnownGapRow struct {
	Reason    string
	RemovedBy string
}

// KnownGaps is the ruling-1234 table: exactly these five rows, no others.
var KnownGaps = map[string]KnownGapRow{
	MethodIAMUserAssignRole: {
		Reason:    "the embedded transport has no quicbaas.IAM.User route at the pinned go-quicbaas tag",
		RemovedBy: KnownGapsRemovedBy,
	},
	MethodIAMUserRevokeRole: {
		Reason:    "the embedded transport has no quicbaas.IAM.User route at the pinned go-quicbaas tag",
		RemovedBy: KnownGapsRemovedBy,
	},
	MethodIAMGroupAddMember: {
		Reason:    "the embedded transport has no quicbaas.IAM.Group route at the pinned go-quicbaas tag",
		RemovedBy: KnownGapsRemovedBy,
	},
	MethodSecretsRotate: {
		Reason:    "the embedded transport does not route secret rotation at the pinned go-quicbaas tag (" + SecretsSDKGapIssue + ")",
		RemovedBy: KnownGapsRemovedBy,
	},
	MethodSecretsUpdateStatus: {
		Reason:    "the embedded transport does not route secret status updates at the pinned go-quicbaas tag (" + SecretsUpdateStatusGapIssue + ")",
		RemovedBy: KnownGapsRemovedBy,
	},
}

// SecretsUpdateStatusGapIssue is the go-quicbaas issue for the missing
// embedded quicbaas.Secrets/UpdateStatus route.
const SecretsUpdateStatusGapIssue = "go-quicbaas #1544"

// knownGapAdapters are the adapters that reach the embedded transport.
var knownGapAdapters = map[string]bool{"Unix": true, "CLI": true, "gRPC-UDS": true}

// KnownGap reports whether err is the embedded transport's unknown-method
// error for a ruling-1234 method on an embedded adapter, in which case the
// caller skips the rest of its check. A listed call that succeeds fails the
// test so its row is deleted; any other error returns false so the caller's
// own assertion fails.
func KnownGap(t testing.TB, adapter, method string, err error) bool {
	t.Helper()
	if _, ok := KnownGaps[method]; !ok {
		t.Errorf("%s is not in helpers.KnownGaps: ruling 1234 and the Tenant approve only five rows", method)
		return false
	}
	if !knownGapAdapters[adapter] {
		return false
	}
	if err == nil {
		t.Errorf("known gap %s now passes on %s: delete its row from helpers.KnownGaps (ruling 1234) and the KnownGap call that guards it", method, adapter)
		return false
	}
	if strings.Contains(err.Error(), "unknown method: "+method) {
		t.Logf("known gap %s on %s (%s): %v", method, adapter, KnownGaps[method].Reason, err)
		return true
	}
	return false
}
