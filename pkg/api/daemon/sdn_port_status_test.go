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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// newPortStatusTestService serves two ports on br0 whose interfaces carry
// the given admin states; a port missing from adminStates has no interface
// of its own name.
func newPortStatusTestService(adminStates map[string]string) *SDNService {
	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnListPorts(func(ctx context.Context, bridgeName string) ([]*ovs.Port, error) {
		return []*ovs.Port{{UUID: "uuid-p-up", Name: "p-up"}, {UUID: "uuid-p-down", Name: "p-down"}, {UUID: "uuid-bond0", Name: "bond0"}}, nil
	})
	mockOVS.OnGetInterface(func(ctx context.Context, name string) (*ovs.Interface, error) {
		adminState, ok := adminStates[name]
		if !ok {
			return nil, ovs.ErrPortNotFound
		}
		return &ovs.Interface{Name: name, AdminState: adminState}, nil
	})
	svc := createMCPTestSDNService(mockOVS)
	svc.bridges["br0"] = &bridgeResource{id: "br0-uuid", name: "br0"}
	svc.ports["p-down"] = &portResource{id: "uuid-p-down", name: "p-down", bridgeID: "br0-uuid"}
	return svc
}

// A port set down reads down afterwards: Get and List report the interface's
// admin_state, not a fixed up.
func TestSDNService_PortsReportTheirAdminState(t *testing.T) {
	svc := newPortStatusTestService(map[string]string{"p-up": "up", "p-down": "down"})
	ctx := context.Background()

	got, err := svc.GetPort(ctx, &platformv1.GetPortRequest{BridgeId: "br0-uuid", PortId: "uuid-p-down"})
	require.NoError(t, err)
	assert.Equal(t, platformv1.PortStatus_PORT_STATUS_DOWN, got.GetPort().GetStatus())

	list, err := svc.ListPorts(ctx, &platformv1.ListPortsRequest{BridgeId: "br0-uuid"})
	require.NoError(t, err)
	statuses := make(map[string]platformv1.PortStatus)
	for _, p := range list.GetPorts() {
		statuses[p.GetConfig().GetName()] = p.GetStatus()
	}
	assert.Equal(t, map[string]platformv1.PortStatus{
		"p-up":   platformv1.PortStatus_PORT_STATUS_UP,
		"p-down": platformv1.PortStatus_PORT_STATUS_DOWN,
		"bond0":  platformv1.PortStatus_PORT_STATUS_UNSPECIFIED,
	}, statuses)
}

// An OVSDB failure reading the state is an internal error, never a guessed
// status.
func TestSDNService_PortStateReadFailureIsInternal(t *testing.T) {
	mockOVS := NewConfigurableMockOVSClient()
	mockOVS.OnGetInterface(func(ctx context.Context, name string) (*ovs.Interface, error) {
		return nil, ovs.ErrNotConnected
	})
	svc := createMCPTestSDNService(mockOVS)
	svc.ports["p0"] = &portResource{id: "uuid-p0", name: "p0", bridgeID: "br0-uuid"}

	_, err := svc.GetPort(context.Background(), &platformv1.GetPortRequest{BridgeId: "br0-uuid", PortId: "uuid-p0"})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestPortAdminStatus(t *testing.T) {
	assert.Equal(t, platformv1.PortStatus_PORT_STATUS_UP, portAdminStatus["up"])
	assert.Equal(t, platformv1.PortStatus_PORT_STATUS_DOWN, portAdminStatus["down"])
	assert.Equal(t, platformv1.PortStatus_PORT_STATUS_UNSPECIFIED, portAdminStatus[""], "a state OVS has not recorded")
}
