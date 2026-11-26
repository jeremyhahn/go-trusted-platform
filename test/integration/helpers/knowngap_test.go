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

package helpers

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Errorf records a formatted failure the way Error does, so KnownGap's
// strict-on-pass report can be asserted without failing the outer test.
func (r *recordingTB) Errorf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

var knownGapMethods = []string{
	MethodIAMUserAssignRole,
	MethodIAMUserRevokeRole,
	MethodIAMGroupAddMember,
	MethodSecretsRotate,
	MethodSecretsUpdateStatus,
}

func TestKnownGap_UnknownMethodOnEmbeddedSkips(t *testing.T) {
	unixErr := errors.New("rpc error: code = Internal desc = UNIMPLEMENTED: embedded: unknown method: quicbaas.IAM.User/AssignRole")
	cliErr := fmt.Errorf("CLI command failed: exit status 1\nstderr: Error: %v", unixErr)
	cases := []struct {
		adapter string
		err     error
	}{
		{"Unix", unixErr},
		{"CLI", cliErr},
		{"gRPC-UDS", unixErr},
	}
	for _, tc := range cases {
		rec := &recordingTB{TB: t}
		if !KnownGap(rec, tc.adapter, MethodIAMUserAssignRole, tc.err) {
			t.Errorf("%s: KnownGap = false, want true for %v", tc.adapter, tc.err)
		}
		if len(rec.failures) != 0 {
			t.Errorf("%s: recorded failures %q, want none", tc.adapter, rec.failures)
		}
	}
}

func TestKnownGap_SecretsRotateUnimplementedSkips(t *testing.T) {
	err := errors.New("rpc error: code = Unimplemented desc = secret rotation failed: UNIMPLEMENTED: embedded: unknown method: quicbaas.Secrets/Rotate")
	rec := &recordingTB{TB: t}
	if !KnownGap(rec, "Unix", MethodSecretsRotate, err) {
		t.Fatalf("KnownGap = false, want true for %v", err)
	}
	if len(rec.failures) != 0 {
		t.Fatalf("recorded failures %q, want none", rec.failures)
	}
}

func TestKnownGap_PassingRowFails(t *testing.T) {
	for _, method := range knownGapMethods {
		rec := &recordingTB{TB: t}
		if KnownGap(rec, "Unix", method, nil) {
			t.Errorf("%s: KnownGap(nil) = true, want false", method)
		}
		if len(rec.failures) != 1 {
			t.Fatalf("%s: recorded %d failures %q, want 1", method, len(rec.failures), rec.failures)
		}
		msg := rec.failures[0]
		for _, want := range []string{method, "now passes", "delete its row from helpers.KnownGaps (ruling 1234)"} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s: failure %q does not contain %q", method, msg, want)
			}
		}
	}
}

func TestKnownGap_OtherErrorIsNotMasked(t *testing.T) {
	for _, err := range []error{
		errors.New("auth: tenant not found in certificate"),
		errors.New("rpc error: code = Internal desc = UNIMPLEMENTED: embedded: unknown method: quicbaas.IAM.PEP/Check"),
	} {
		rec := &recordingTB{TB: t}
		if KnownGap(rec, "Unix", MethodIAMUserAssignRole, err) {
			t.Errorf("KnownGap = true for %v, want false", err)
		}
		if len(rec.failures) != 0 {
			t.Errorf("recorded failures %q for %v, want none", rec.failures, err)
		}
	}
}

func TestKnownGap_NonEmbeddedAdapterIsNotMasked(t *testing.T) {
	err := errors.New("rpc error: code = Internal desc = UNIMPLEMENTED: embedded: unknown method: quicbaas.IAM.User/AssignRole")
	for _, adapter := range []string{"REST", "gRPC", "QUIC", "MCP"} {
		rec := &recordingTB{TB: t}
		if KnownGap(rec, adapter, MethodIAMUserAssignRole, err) {
			t.Errorf("%s: KnownGap = true, want false", adapter)
		}
		if KnownGap(rec, adapter, MethodIAMUserAssignRole, nil) {
			t.Errorf("%s: KnownGap(nil) = true, want false", adapter)
		}
		if len(rec.failures) != 0 {
			t.Errorf("%s: recorded failures %q, want none", adapter, rec.failures)
		}
	}
}

func TestKnownGap_UnlistedMethodFails(t *testing.T) {
	rec := &recordingTB{TB: t}
	err := errors.New("unknown method: quicbaas.IAM.PEP/Check")
	if KnownGap(rec, "Unix", "quicbaas.IAM.PEP/Check", err) {
		t.Fatal("KnownGap = true for an unlisted method, want false")
	}
	if len(rec.failures) != 1 || !strings.Contains(rec.failures[0], "not in helpers.KnownGaps") {
		t.Fatalf("recorded failures %q, want one containing %q", rec.failures, "not in helpers.KnownGaps")
	}
}

func TestKnownGaps_ExactlyTheFiveRulingRows(t *testing.T) {
	if len(KnownGaps) != 5 {
		t.Fatalf("len(KnownGaps) = %d, want 5 (ruling 1234 and the Tenant's fifth row)", len(KnownGaps))
	}
	for _, method := range knownGapMethods {
		row, ok := KnownGaps[method]
		if !ok {
			t.Errorf("KnownGaps lacks %s", method)
			continue
		}
		if row.Reason == "" || row.RemovedBy == "" {
			t.Errorf("KnownGaps[%s] = %+v, want non-empty Reason and RemovedBy", method, row)
		}
	}
}
