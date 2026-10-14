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

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	ipamBackends "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// envZoneService is a zone service numbered in environment 4.
func envZoneService(t *testing.T) gateway.ZoneService {
	t.Helper()
	svc, err := gateway.NewZoneService(nil, &netplan.Environment{ID: 4})
	require.NoError(t, err)
	return svc
}

func labProto() *platformv1.NetworkZoneConfig {
	return &platformv1.NetworkZoneConfig{
		Name:        "lab",
		Offset:      9,
		PortClasses: []string{"hypervisor"},
		Isolate:     true,
		Services:    []string{"ssh"},
		AllowTo:     []*platformv1.NetworkZonePath{{Zone: "control-plane", Services: []string{"dns"}}},
		PrivilegedAccess: &platformv1.NetworkZonePrivilegedAccess{
			Reason: "lab resolver", ApprovedBy: "owner",
		},
	}
}

// TestSDNServiceZones_GRPC drives create, list, update and delete through
// the gRPC handlers against a real zone service.
func TestSDNServiceZones_GRPC(t *testing.T) {
	s := &SDNService{}
	s.WithZoneService(envZoneService(t))
	ctx := context.Background()

	created, err := s.CreateNetworkZone(ctx, &platformv1.CreateNetworkZoneRequest{Config: labProto()})
	require.NoError(t, err)
	z := created.GetZone()
	assert.True(t, z.GetRestartRequired())
	assert.Equal(t, uint32(9), z.GetConfig().GetOffset())
	assert.Equal(t, []string{"hypervisor"}, z.GetConfig().GetPortClasses())
	assert.Equal(t, []string{"ssh"}, z.GetConfig().GetServices())
	assert.Equal(t, "owner", z.GetConfig().GetPrivilegedAccess().GetApprovedBy())
	assert.Equal(t, uint32(409), z.GetNumbering().GetVlan())
	assert.Equal(t, "10.4.9.0/24", z.GetNumbering().GetSubnet4())
	assert.Equal(t, "10.4.9.1", z.GetNumbering().GetGateway())

	list, err := s.ListNetworkZones(ctx, &platformv1.ListNetworkZonesRequest{LifecycleRole: "quarantine"})
	require.NoError(t, err)
	require.Len(t, list.GetZones(), 1)
	assert.Equal(t, "quarantine", list.GetZones()[0].GetConfig().GetName())

	updated, err := s.UpdateNetworkZone(ctx, &platformv1.UpdateNetworkZoneRequest{
		Name:   "storage",
		Config: &platformv1.NetworkZoneConfig{Isolate: true, Services: []string{"nvme-tcp"}},
	})
	require.NoError(t, err)
	assert.Equal(t, uint32(7), updated.GetZone().GetConfig().GetOffset(), "a built-in keeps its offset")
	assert.True(t, updated.GetZone().GetRestartRequired())

	deleted, err := s.DeleteNetworkZone(ctx, &platformv1.DeleteNetworkZoneRequest{Name: "lab"})
	require.NoError(t, err)
	assert.True(t, deleted.GetRestartRequired())
}

// TestSDNServiceZones_GRPCErrors maps every failure to its gRPC code.
func TestSDNServiceZones_GRPCErrors(t *testing.T) {
	ctx := context.Background()
	code := status.Code

	none := &SDNService{}
	_, err := none.ListNetworkZones(ctx, &platformv1.ListNetworkZonesRequest{})
	assert.Equal(t, codes.FailedPrecondition, code(err))
	_, err = none.CreateNetworkZone(ctx, &platformv1.CreateNetworkZoneRequest{})
	assert.Equal(t, codes.FailedPrecondition, code(err))
	_, err = none.UpdateNetworkZone(ctx, &platformv1.UpdateNetworkZoneRequest{})
	assert.Equal(t, codes.FailedPrecondition, code(err))
	_, err = none.DeleteNetworkZone(ctx, &platformv1.DeleteNetworkZoneRequest{})
	assert.Equal(t, codes.FailedPrecondition, code(err))

	s := &SDNService{}
	s.WithZoneService(envZoneService(t))
	_, err = s.CreateNetworkZone(ctx, &platformv1.CreateNetworkZoneRequest{})
	assert.Equal(t, codes.InvalidArgument, code(err), "config required")
	_, err = s.CreateNetworkZone(ctx, &platformv1.CreateNetworkZoneRequest{Config: &platformv1.NetworkZoneConfig{Name: "fabric"}})
	assert.Equal(t, codes.AlreadyExists, code(err))
	unaudited := labProto()
	unaudited.PrivilegedAccess = nil
	_, err = s.CreateNetworkZone(ctx, &platformv1.CreateNetworkZoneRequest{Config: unaudited})
	assert.Equal(t, codes.InvalidArgument, code(err))
	_, err = s.UpdateNetworkZone(ctx, &platformv1.UpdateNetworkZoneRequest{})
	assert.Equal(t, codes.InvalidArgument, code(err), "name required")
	_, err = s.UpdateNetworkZone(ctx, &platformv1.UpdateNetworkZoneRequest{Name: "nowhere"})
	assert.Equal(t, codes.NotFound, code(err))
	_, err = s.DeleteNetworkZone(ctx, &platformv1.DeleteNetworkZoneRequest{})
	assert.Equal(t, codes.InvalidArgument, code(err))
	_, err = s.DeleteNetworkZone(ctx, &platformv1.DeleteNetworkZoneRequest{Name: "fabric"})
	assert.Equal(t, codes.InvalidArgument, code(err), "a required built-in cannot be removed")

	assert.Equal(t, codes.Internal, code(sdnMapZoneError(errors.New("boom"))))
}

// TestZoneProtoConversion_RoundTrip converts a config to proto and back.
func TestZoneProtoConversion_RoundTrip(t *testing.T) {
	cfg := sdnProtoToZoneConfig(labProto())
	assert.Equal(t, zone.Offset(9), cfg.Offset)
	assert.Equal(t, []zone.PortClass{zone.PortClassHypervisor}, cfg.PortClasses)
	require.NotNil(t, cfg.PrivilegedAccess)

	back := sdnZoneRecordToProto(&gateway.ZoneRecord{Config: cfg})
	assert.Equal(t, labProto().GetAllowTo()[0].GetZone(), back.GetConfig().GetAllowTo()[0].GetZone())
	assert.Nil(t, back.GetNumbering(), "no numbering without an environment")

	bare := sdnProtoToZoneConfig(&platformv1.NetworkZoneConfig{Name: "x"})
	assert.Nil(t, bare.PrivilegedAccess)
	assert.Nil(t, bare.AllowTo)
}

// TestMCPZoneProviders covers both MCP service providers' zone operations
// and the VLAN lookup.
func TestMCPZoneProviders(t *testing.T) {
	ctx := context.Background()
	type provider interface {
		GatewayNetworkZoneList(context.Context, string) ([]interface{}, error)
		GatewayNetworkZoneCreate(context.Context, *mcp.NetworkZoneCreateRequest) (interface{}, error)
		GatewayNetworkZoneUpdate(context.Context, string, *mcp.NetworkZoneUpdateRequest) (interface{}, error)
		GatewayNetworkZoneDelete(context.Context, string) (bool, error)
		GatewayNetworkZoneVLAN(context.Context, string) (uint16, error)
	}
	mk := map[string]func(gateway.ZoneService) provider{
		"mcp": func(zs gateway.ZoneService) provider {
			return NewMCPServiceProvider(&MCPServiceProviderConfig{ZoneService: zs})
		},
	}
	for name, newProvider := range mk {
		t.Run(name, func(t *testing.T) {
			p := newProvider(envZoneService(t))

			out, err := p.GatewayNetworkZoneCreate(ctx, &mcp.NetworkZoneCreateRequest{
				Name: "lab", Offset: 9, PortClasses: []string{"gateway"}, Isolate: true,
			})
			require.NoError(t, err)
			view, ok := out.(gateway.ZoneView)
			require.True(t, ok, "%T", out)
			assert.True(t, view.RestartRequired)
			assert.Equal(t, uint16(409), view.Numbering.VLAN)

			out, err = p.GatewayNetworkZoneUpdate(ctx, "storage", &mcp.NetworkZoneUpdateRequest{Isolate: true})
			require.NoError(t, err)
			assert.Equal(t, uint8(7), out.(gateway.ZoneView).Offset)

			zones, err := p.GatewayNetworkZoneList(ctx, "")
			require.NoError(t, err)
			assert.Len(t, zones, 10)

			vlan, err := p.GatewayNetworkZoneVLAN(ctx, "provisioning")
			require.NoError(t, err)
			assert.Equal(t, uint16(405), vlan)
			_, err = p.GatewayNetworkZoneVLAN(ctx, "nowhere")
			var nf gateway.ErrZoneNotFound
			assert.True(t, errors.As(err, &nf))

			restart, err := p.GatewayNetworkZoneDelete(ctx, "lab")
			require.NoError(t, err)
			assert.True(t, restart)

			_, err = p.GatewayNetworkZoneCreate(ctx, &mcp.NetworkZoneCreateRequest{Name: "fabric"})
			var exists gateway.ErrZoneAlreadyExists
			assert.True(t, errors.As(err, &exists))
			_, err = p.GatewayNetworkZoneUpdate(ctx, "nowhere", &mcp.NetworkZoneUpdateRequest{})
			assert.True(t, errors.As(err, &nf))
		})
		t.Run(name+"/no zone service", func(t *testing.T) {
			p := newProvider(nil)
			var unavailable ErrServiceNotAvailable
			_, err := p.GatewayNetworkZoneList(ctx, "")
			assert.True(t, errors.As(err, &unavailable))
			_, err = p.GatewayNetworkZoneCreate(ctx, &mcp.NetworkZoneCreateRequest{Name: "lab"})
			assert.True(t, errors.As(err, &unavailable))
			_, err = p.GatewayNetworkZoneUpdate(ctx, "lab", &mcp.NetworkZoneUpdateRequest{})
			assert.True(t, errors.As(err, &unavailable))
			_, err = p.GatewayNetworkZoneDelete(ctx, "lab")
			assert.True(t, errors.As(err, &unavailable))
			_, err = p.GatewayNetworkZoneVLAN(ctx, "lab")
			assert.True(t, errors.As(err, &unavailable))
		})
	}
}

// TestZoneVLAN_NoEnvironment refuses a VLAN lookup the service cannot
// number.
func TestZoneVLAN_NoEnvironment(t *testing.T) {
	svc, err := gateway.NewZoneService(nil, nil)
	require.NoError(t, err)
	_, err = zoneVLAN(context.Background(), svc, "provisioning")
	var unavailable ErrServiceNotAvailable
	assert.True(t, errors.As(err, &unavailable), "got %v", err)
}

// TestQUICZoneAdapters_CRUD drives both QUIC adapters through a real zone
// service and checks the error statuses.
func TestQUICZoneAdapters_CRUD(t *testing.T) {
	ctx := context.Background()
	adapters := map[string]quic.GatewayServiceInterface{
		"zone": newZoneGatewayAdapter(envZoneService(t)),
		"full": newFullGatewayQUICAdapter(ipamBackends.NewMemoryBackend(), envZoneService(t), nil, nil, nil),
	}
	for name, a := range adapters {
		t.Run(name, func(t *testing.T) {
			created, err := a.CreateNetworkZone(ctx, &quic.CreateNetworkZoneOptions{
				Name: "lab", Offset: 9, PortClasses: []string{"hypervisor"},
				AllowTo:          []quic.NetworkZonePathInfo{{Zone: "control-plane", Services: []string{"dns"}}},
				PrivilegedAccess: &quic.NetworkZonePrivilegedAccessInfo{Reason: "r", ApprovedBy: "owner"},
				IsolateFrom:      []string{"storage"},
				Isolate:          true,
			})
			require.NoError(t, err)
			assert.True(t, created.RestartRequired)
			assert.Equal(t, uint16(409), created.Numbering.VLAN)
			assert.Equal(t, []string{"storage"}, created.IsolateFrom)
			assert.Equal(t, "owner", created.PrivilegedAccess.ApprovedBy)

			updated, err := a.UpdateNetworkZone(ctx, "storage", &quic.UpdateNetworkZoneOptions{Isolate: true, Services: []string{"nvme-tcp"}})
			require.NoError(t, err)
			assert.Equal(t, uint8(7), updated.Offset)
			cleared, err := a.UpdateNetworkZone(ctx, "backup", nil)
			require.NoError(t, err, "nil options clear a built-in's policy; its identity stays")
			assert.Equal(t, uint8(8), cleared.Offset)

			zones, err := a.ListNetworkZones(ctx, "")
			require.NoError(t, err)
			assert.Len(t, zones, 10)

			restart, err := a.DeleteNetworkZone(ctx, "lab")
			require.NoError(t, err)
			assert.True(t, restart)

			_, err = a.CreateNetworkZone(ctx, &quic.CreateNetworkZoneOptions{Name: "fabric"})
			assert.ErrorIs(t, err, quic.ErrGatewayZoneAlreadyExists)
			_, err = a.UpdateNetworkZone(ctx, "nowhere", &quic.UpdateNetworkZoneOptions{})
			assert.ErrorIs(t, err, quic.ErrGatewayZoneNotFound)
			_, err = a.DeleteNetworkZone(ctx, "fabric")
			assert.ErrorIs(t, err, quic.ErrGatewayZoneInvalid)
		})
	}

	none := newFullGatewayQUICAdapter(ipamBackends.NewMemoryBackend(), nil, nil, nil, nil)
	_, err := none.ListNetworkZones(ctx, "")
	assert.ErrorIs(t, err, errGatewayFeatureNotConfigured)
	_, err = none.CreateNetworkZone(ctx, &quic.CreateNetworkZoneOptions{Name: "lab"})
	assert.ErrorIs(t, err, errGatewayFeatureNotConfigured)
	_, err = none.UpdateNetworkZone(ctx, "lab", nil)
	assert.ErrorIs(t, err, errGatewayFeatureNotConfigured)
	_, err = none.DeleteNetworkZone(ctx, "lab")
	assert.ErrorIs(t, err, errGatewayFeatureNotConfigured)
	assert.Equal(t, zone.ZoneConfig{}, quicCreateOptsToZoneConfig(nil))
	assert.Equal(t, errors.New("boom"), mapZoneToQUICError(errors.New("boom")))
	assert.Nil(t, zonesFromStrings(nil))
	assert.Nil(t, privilegedAccessFromQUIC(nil))
	assert.Nil(t, privilegedAccessToQUIC(nil))
}
