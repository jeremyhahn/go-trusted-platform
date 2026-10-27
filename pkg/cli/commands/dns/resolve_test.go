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

package dns

import (
	"errors"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestResolve_ReturnsRecords(t *testing.T) {
	fake := newFakeDNSClient()
	fake.resolved = []*platformv1.Record{{
		Type:   platformv1.RecordType_RECORD_TYPE_A,
		Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www.example.test.", Value: "192.0.2.10", Ttl: 300}},
	}}
	out := withFakeClient(t, fake)
	if err := execute(t, "resolve", "www.example.test.", "--type", "a"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	req := fake.requests["Resolve"].(*platformv1.ResolveRequest)
	if req.GetFqdn() != "www.example.test." || req.GetType() != platformv1.RecordType_RECORD_TYPE_A {
		t.Errorf("request = %v", req)
	}
	table := requireTable(t, out)
	if len(table.Rows) != 1 || table.Rows[0][2] != "192.0.2.10" {
		t.Errorf("rows = %v", table.Rows)
	}
}

func TestResolve_WithoutTypeAsksForEveryType(t *testing.T) {
	fake := newFakeDNSClient()
	withFakeClient(t, fake)
	if err := execute(t, "resolve", "www.example.test."); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := fake.requests["Resolve"].(*platformv1.ResolveRequest).GetType(); got != platformv1.RecordType_RECORD_TYPE_UNSPECIFIED {
		t.Errorf("type = %v, want unspecified", got)
	}
}

func TestResolve_Errors(t *testing.T) {
	fake := newFakeDNSClient()
	withFakeClient(t, fake)
	var typeErr *ErrUnknownRecordType
	if err := execute(t, "resolve", "www.example.test.", "--type", "BOGUS"); !errors.As(err, &typeErr) {
		t.Fatalf("err = %v, want *ErrUnknownRecordType", err)
	}
	fake.err = errRPC
	requireRPCError(t, execute(t, "resolve", "www.example.test."))
}

func TestRegister_SendsNameAndAddress(t *testing.T) {
	fake := newFakeDNSClient()
	out := withFakeClient(t, fake)
	if err := execute(t, "register", "node1.example.test.", "192.0.2.21"); err != nil {
		t.Fatalf("register: %v", err)
	}
	req := fake.requests["Register"].(*platformv1.RegisterRequest)
	if req.GetFqdn() != "node1.example.test." || req.GetIp() != "192.0.2.21" {
		t.Errorf("request = %v", req)
	}
	if got := tableValue(t, requireTable(t, out), "name"); got != "example.test." {
		t.Errorf("zone = %q", got)
	}
}

func TestRegister_Errors(t *testing.T) {
	fake := newFakeDNSClient()
	withFakeClient(t, fake)
	if err := execute(t, "register", "node1.example.test."); err == nil {
		t.Fatal("register without an address succeeded")
	}
	fake.err = errRPC
	requireRPCError(t, execute(t, "register", "node1.example.test.", "192.0.2.21"))
}
