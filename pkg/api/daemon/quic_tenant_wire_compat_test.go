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

//go:build codec_msgpack

package daemon

import (
	"testing"

	"google.golang.org/protobuf/proto"

	quic "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The tests in this file guard the QUIC wire contract for the Tenant surface
// between the platform SDK client and the daemon. The canonical contract is
// the platform.v1 protobuf messages themselves: the SDK QUIC transport adapter
// hands the generated pb request struct straight to the payload codec, which
// keys on exact Go field names. Before the pb-wire fix the daemon decoded flat
// local structs whose Go field names did not match the pb Go field names,
// silently dropping every diverging request field:
//
//   - GetTenantRequest.TenantId       (flat TenantID   -> dropped)
//   - CreateTenantRequest's nested ComputeQuota/NetworkQuota/StorageQuota
//     (flat *QuotaDTO with MaxVMs vs pb MaxVms -> dropped)
//
// Each message is round-tripped through the payload codec (encode SDK-side
// shape -> decode daemon-side shape) and compared with proto.Equal so a codec
// or field-shape regression on either side fails here first. These are the
// SDK-mapped tenant operations (grpcMethodToOpcodeMap) plus the
// daemon-native operations that also travel as pb once the handlers delegate
// to the shared *TenantGRPCServer.

func roundTripTenantWire(t *testing.T, src, dst proto.Message) {
	t.Helper()
	payload, err := quic.EncodePayload(src)
	if err != nil {
		t.Fatalf("encode %T: %v", src, err)
	}
	if err := quic.DecodePayload(payload, dst); err != nil {
		t.Fatalf("decode %T into %T: %v", src, dst, err)
	}
	if !proto.Equal(src, dst) {
		t.Fatalf("round trip mismatch:\n src: %+v\n dst: %+v", src, dst)
	}
}

func TestQUICTenantWireCompatCRUD(t *testing.T) {
	roundTripTenantWire(t,
		&platformv1.ListTenantsRequest{Limit: 25, Offset: 50},
		&platformv1.ListTenantsRequest{})
	roundTripTenantWire(t,
		&platformv1.GetTenantRequest{TenantId: "tenant-a"},
		&platformv1.GetTenantRequest{})
	roundTripTenantWire(t,
		&platformv1.GetTenantByNameRequest{Name: "acme"},
		&platformv1.GetTenantByNameRequest{})
	roundTripTenantWire(t,
		&platformv1.DeleteTenantRequest{TenantId: "tenant-a"},
		&platformv1.DeleteTenantRequest{})

	// Create carries the fields the flat decode dropped: the nested quota
	// messages (flat used *ComputeQuotaDTO whose Go fields MaxVMs/MaxVCPUs
	// differ from the pb MaxVms/MaxVcpus).
	roundTripTenantWire(t,
		&platformv1.CreateTenantRequest{
			Name:        "acme",
			DisplayName: "Acme Corp",
			Labels:      map[string]string{"tier": "gold"},
			Annotations: map[string]string{"owner": "ops"},
			ComputeQuota: &platformv1.ComputeQuota{
				MaxVms: 10, MaxContainers: 50, MaxVcpus: 40, MaxMemoryMb: 65536,
			},
			NetworkQuota: &platformv1.NetworkQuota{
				MaxBridges: 4, MaxPorts: 64, MaxBandwidthMbps: 10000,
			},
			StorageQuota: &platformv1.StorageQuota{
				MaxVolumesGb: 1024, MaxSnapshots: 32,
			},
		},
		&platformv1.CreateTenantRequest{})

	roundTripTenantWire(t,
		&platformv1.UpdateTenantRequest{
			TenantId:    "tenant-a",
			DisplayName: "Acme Corp Renamed",
			Labels:      map[string]string{"tier": "platinum"},
			Annotations: map[string]string{"owner": "sre"},
		},
		&platformv1.UpdateTenantRequest{})
}

func TestQUICTenantWireCompatLifecycle(t *testing.T) {
	roundTripTenantWire(t,
		&platformv1.SuspendTenantRequest{TenantId: "tenant-a"},
		&platformv1.SuspendTenantRequest{})
	roundTripTenantWire(t,
		&platformv1.ResumeTenantRequest{TenantId: "tenant-a"},
		&platformv1.ResumeTenantRequest{})
}

func TestQUICTenantWireCompatQuotas(t *testing.T) {
	roundTripTenantWire(t,
		&platformv1.GetQuotasRequest{TenantId: "tenant-a"},
		&platformv1.GetQuotasRequest{})
	roundTripTenantWire(t,
		&platformv1.UpdateQuotasRequest{
			TenantId: "tenant-a",
			Compute:  &platformv1.ComputeQuota{MaxVms: 20, MaxVcpus: 80},
			Network:  &platformv1.NetworkQuota{MaxBridges: 8},
			Storage:  &platformv1.StorageQuota{MaxVolumesGb: 2048},
		},
		&platformv1.UpdateQuotasRequest{})
	roundTripTenantWire(t,
		&platformv1.GetUsageRequest{TenantId: "tenant-a"},
		&platformv1.GetUsageRequest{})
	roundTripTenantWire(t,
		&platformv1.CheckQuotaRequest{TenantId: "tenant-a", Resource: "vms", Amount: 5},
		&platformv1.CheckQuotaRequest{})
}

func TestQUICTenantWireCompatSyncAndDEK(t *testing.T) {
	roundTripTenantWire(t,
		&platformv1.SyncTenantsRequest{},
		&platformv1.SyncTenantsRequest{})
	roundTripTenantWire(t,
		&platformv1.RotateTenantDEKRequest{TenantId: "tenant-a", Background: true},
		&platformv1.RotateTenantDEKRequest{})
	roundTripTenantWire(t,
		&platformv1.GetTenantDEKStatusRequest{TenantId: "tenant-a"},
		&platformv1.GetTenantDEKStatusRequest{})
}

// TestQUICTenantWireCompatResponses round-trips the pb responses the SDK QUIC
// transport decodes into the generated response structs.
func TestQUICTenantWireCompatResponses(t *testing.T) {
	roundTripTenantWire(t,
		&platformv1.CreateTenantResponse{
			Status: &platformv1.Status{Success: true, Message: "tenant created successfully"},
			Tenant: &platformv1.Tenant{
				Id: "tenant-a", Name: "acme", DisplayName: "Acme Corp",
				DekPath: "tenant/tenant-a",
			},
		},
		&platformv1.CreateTenantResponse{})
	roundTripTenantWire(t,
		&platformv1.GetTenantResponse{
			Tenant: &platformv1.Tenant{Id: "tenant-a", Name: "acme"},
		},
		&platformv1.GetTenantResponse{})
	roundTripTenantWire(t,
		&platformv1.ListTenantsResponse{
			Tenants: []*platformv1.Tenant{{Id: "tenant-a", Name: "acme"}},
			Total:   1,
		},
		&platformv1.ListTenantsResponse{})
}
