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
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestZoneCreate_SendsSOAAndNameServers(t *testing.T) {
	fake := newFakeDNSClient()
	out := withFakeClient(t, fake)
	err := execute(t, "zone", "create", "example.test.", "--ttl", "600", "--description", "lab", "--internal",
		"--soa-mname", "ns1.example.test.", "--soa-rname", "admin.example.test.", "--soa-serial", "9",
		"--ns", "ns1.example.test.", "--ns", "ns2.example.test.")
	if err != nil {
		t.Fatalf("zone create: %v", err)
	}
	req := fake.requests["CreateZone"].(*platformv1.CreateZoneRequest)
	if req.GetName() != "example.test." || req.GetTtl() != 600 || req.GetDescription() != "lab" || !req.GetInternal() {
		t.Errorf("request = %v", req)
	}
	soa := req.GetSoa()
	if soa.GetName() != "example.test." || soa.GetMname() != "ns1.example.test." || soa.GetRname() != "admin.example.test." ||
		soa.GetSerial() != 9 || soa.GetRefresh() != 86400 || soa.GetRetry() != 7200 || soa.GetExpire() != 86400 ||
		soa.GetMinimumTtl() != 3600 || soa.GetTtl() != 600 {
		t.Errorf("soa = %v", soa)
	}
	if len(req.GetNsRecords()) != 2 || req.GetNsRecords()[1].GetValue() != "ns2.example.test." ||
		req.GetNsRecords()[0].GetName() != "example.test." {
		t.Errorf("ns records = %v", req.GetNsRecords())
	}
	if got := tableValue(t, requireTable(t, out), "name"); got != "example.test." {
		t.Errorf("name row = %q", got)
	}
}

func TestZoneCreate_NameOnlySendsNoSOA(t *testing.T) {
	fake := newFakeDNSClient()
	withFakeClient(t, fake)
	if err := execute(t, "zone", "create", "example.test."); err != nil {
		t.Fatalf("zone create: %v", err)
	}
	req := fake.requests["CreateZone"].(*platformv1.CreateZoneRequest)
	if req.GetSoa() != nil || len(req.GetNsRecords()) != 0 || req.GetTtl() != defaultZoneTTL {
		t.Errorf("request = %v", req)
	}
}

func TestZoneCreate_RPCError(t *testing.T) {
	fake := newFakeDNSClient()
	fake.err = errRPC
	withFakeClient(t, fake)
	requireRPCError(t, execute(t, "zone", "create", "example.test."))
}

func TestZoneGet_ShowsZone(t *testing.T) {
	fake := newFakeDNSClient()
	fake.zone.Records = &platformv1.RecordSet{
		Soa:      &platformv1.SOARecord{Mname: "ns1.example.test.", Rname: "admin.example.test.", Serial: 3},
		ARecords: []*platformv1.ARecord{{Name: "www", Value: "192.0.2.10"}},
	}
	out := withFakeClient(t, fake)
	if err := execute(t, "zone", "get", "example.test."); err != nil {
		t.Fatalf("zone get: %v", err)
	}
	if fake.requests["GetZone"].(*platformv1.GetZoneRequest).GetName() != "example.test." {
		t.Errorf("request = %v", fake.requests["GetZone"])
	}
	table := requireTable(t, out)
	if got := tableValue(t, table, "records"); got != "2" {
		t.Errorf("records = %q, want 2 (SOA and A)", got)
	}
	if got := tableValue(t, table, "soa"); got != "ns1.example.test. admin.example.test. 3 0 0 0 0" {
		t.Errorf("soa = %q", got)
	}
	if got := tableValue(t, table, "id"); got != "7" {
		t.Errorf("id = %q", got)
	}
}

func TestZoneGet_RPCError(t *testing.T) {
	fake := newFakeDNSClient()
	fake.err = errRPC
	withFakeClient(t, fake)
	requireRPCError(t, execute(t, "zone", "get", "example.test."))
}

func TestZoneUpdate_SendsTTLAndDescription(t *testing.T) {
	fake := newFakeDNSClient()
	withFakeClient(t, fake)
	if err := execute(t, "zone", "update", "example.test.", "--ttl", "7200", "--description", "lab zone"); err != nil {
		t.Fatalf("zone update: %v", err)
	}
	req := fake.requests["UpdateZone"].(*platformv1.UpdateZoneRequest)
	if req.GetName() != "example.test." || req.GetTtl() != 7200 || req.GetDescription() != "lab zone" {
		t.Errorf("request = %v", req)
	}
}

func TestZoneUpdate_RPCError(t *testing.T) {
	fake := newFakeDNSClient()
	fake.err = errRPC
	withFakeClient(t, fake)
	requireRPCError(t, execute(t, "zone", "update", "example.test.", "--ttl", "60"))
}

func TestZoneDelete_ReportsDeleted(t *testing.T) {
	fake := newFakeDNSClient()
	out := withFakeClient(t, fake)
	if err := execute(t, "zone", "delete", "example.test."); err != nil {
		t.Fatalf("zone delete: %v", err)
	}
	if fake.requests["DeleteZone"].(*platformv1.DeleteZoneRequest).GetName() != "example.test." {
		t.Errorf("request = %v", fake.requests["DeleteZone"])
	}
	if got := tableValue(t, requireTable(t, out), "deleted"); got != "true" {
		t.Errorf("deleted = %q", got)
	}
}

func TestZoneDelete_RPCError(t *testing.T) {
	fake := newFakeDNSClient()
	fake.err = errRPC
	withFakeClient(t, fake)
	requireRPCError(t, execute(t, "zone", "delete", "example.test."))
}

func TestZoneList_FiltersAndPages(t *testing.T) {
	fake := newFakeDNSClient()
	fake.zones = []*platformv1.Zone{
		{Name: "a.test.", Id: 1, Ttl: 60, Internal: true},
		{Name: "b.test.", Id: 2, Ttl: 120},
	}
	out := withFakeClient(t, fake)
	if err := execute(t, "zone", "list", "--internal-only", "--page", "2", "--page-size", "50"); err != nil {
		t.Fatalf("zone list: %v", err)
	}
	req := fake.requests["ListZones"].(*platformv1.ListZonesRequest)
	if !req.GetInternalOnly() || req.GetPublicOnly() || req.GetPagination().GetPage() != 2 || req.GetPagination().GetPageSize() != 50 {
		t.Errorf("request = %v", req)
	}
	table := requireTable(t, out)
	if len(table.Rows) != 2 || table.Rows[0][0] != "a.test." || table.Rows[0][3] != "true" || table.Rows[1][2] != "120" {
		t.Errorf("rows = %v", table.Rows)
	}
}

func TestZoneList_NoPaginationByDefault(t *testing.T) {
	fake := newFakeDNSClient()
	withFakeClient(t, fake)
	if err := execute(t, "zone", "list"); err != nil {
		t.Fatalf("zone list: %v", err)
	}
	if fake.requests["ListZones"].(*platformv1.ListZonesRequest).GetPagination() != nil {
		t.Error("pagination sent without --page or --page-size")
	}
}

func TestZoneList_InternalAndPublicExclusive(t *testing.T) {
	fake := newFakeDNSClient()
	withFakeClient(t, fake)
	if err := execute(t, "zone", "list", "--internal-only", "--public-only"); err == nil {
		t.Fatal("--internal-only with --public-only succeeded")
	}
	if _, called := fake.requests["ListZones"]; called {
		t.Error("ListZones was called")
	}
}

func TestZoneList_RPCError(t *testing.T) {
	fake := newFakeDNSClient()
	fake.err = errRPC
	withFakeClient(t, fake)
	requireRPCError(t, execute(t, "zone", "list"))
}

func TestZoneTable_NilZoneIsEmpty(t *testing.T) {
	table := zoneTable(nil)
	if len(table.Rows) != 0 {
		t.Fatalf("rows = %v", table.Rows)
	}
}

func TestCountRecords(t *testing.T) {
	if got := countRecords(nil); got != 0 {
		t.Errorf("countRecords(nil) = %d", got)
	}
	set := &platformv1.RecordSet{
		TlsaRecords:   []*platformv1.TLSARecord{{}},
		DnskeyRecords: []*platformv1.DNSKEYRecord{{}, {}},
		RrsigRecords:  []*platformv1.RRSIGRecord{{}},
	}
	if got := countRecords(set); got != 4 {
		t.Errorf("countRecords = %d, want 4", got)
	}
}

func TestZoneCreateRequest_SOAFromRNameAlone(t *testing.T) {
	req := zoneCreateRequest("example.test.", zoneCreateFlags{TTL: 60, SOARName: "admin.example.test."})
	if req.GetSoa() == nil || req.GetSoa().GetRname() != "admin.example.test." {
		t.Fatalf("soa = %v", req.GetSoa())
	}
	empty := zoneCreateRequest("example.test.", zoneCreateFlags{})
	if empty.GetSoa() != nil {
		t.Fatalf("soa sent without --soa-mname or --soa-rname: %v", empty.GetSoa())
	}
}
