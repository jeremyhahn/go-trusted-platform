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
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vxlan"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockOverlayController implements OverlayControllerInterface for testing.
type mockOverlayController struct {
	running      bool
	state        *overlay.State
	config       *overlay.Config
	vteps        []overlay.VTEPInfo
	vnis         map[uint32]*overlay.VNIInfo
	uptime       time.Duration
	listVTEPsErr error
	addVNIErr    error
	removeVNIErr error
	forgetMACErr error
}

func newMockOverlayController() *mockOverlayController {
	return &mockOverlayController{
		running: true,
		vnis:    make(map[uint32]*overlay.VNIInfo),
		config: &overlay.Config{
			NodeID: "test-node-1",
			VTEPIP: netip.MustParseAddr("10.0.0.1"),
		},
		vteps: []overlay.VTEPInfo{
			{
				NodeID:   "test-node-1",
				IP:       netip.MustParseAddr("10.0.0.1"),
				Healthy:  true,
				LastSeen: time.Now(),
			},
		},
		state: &overlay.State{
			NodeID:          "test-node-1",
			VTEPIP:          netip.MustParseAddr("10.0.0.1"),
			ControllerState: overlay.ControllerStateRunning,
			VTEPs:           []overlay.VTEPInfo{},
			VNIs:            []overlay.VNIInfo{},
			Tunnels:         []overlay.TunnelInfo{},
			RemoteMACs:      []overlay.RemoteMACEntry{},
		},
		uptime: 30 * time.Second,
	}
}

func (m *mockOverlayController) IsRunning() bool {
	return m.running
}

func (m *mockOverlayController) GetState() *overlay.State {
	return m.state
}

func (m *mockOverlayController) GetConfig() *overlay.Config {
	return m.config
}

func (m *mockOverlayController) Uptime() time.Duration {
	return m.uptime
}

func (m *mockOverlayController) ListVTEPs(ctx context.Context) ([]overlay.VTEPInfo, error) {
	if m.listVTEPsErr != nil {
		return nil, m.listVTEPsErr
	}
	return m.vteps, nil
}

func (m *mockOverlayController) GetVTEP(ctx context.Context, ip netip.Addr) (*overlay.VTEPInfo, error) {
	for i := range m.vteps {
		if m.vteps[i].IP == ip {
			return &m.vteps[i], nil
		}
	}
	return nil, errors.New("VTEP not found")
}

func (m *mockOverlayController) AddVNI(ctx context.Context, config *overlay.VNIConfig) error {
	if m.addVNIErr != nil {
		return m.addVNIErr
	}
	m.vnis[config.VNI] = &overlay.VNIInfo{
		VNI:       config.VNI,
		VLAN:      config.VLAN,
		CreatedAt: time.Now(),
	}
	return nil
}

func (m *mockOverlayController) RemoveVNI(ctx context.Context, vni uint32) error {
	if m.removeVNIErr != nil {
		return m.removeVNIErr
	}
	if _, exists := m.vnis[vni]; !exists {
		return errors.New("VNI not found")
	}
	delete(m.vnis, vni)
	return nil
}

func (m *mockOverlayController) ListVNIs(ctx context.Context) ([]overlay.VNIInfo, error) {
	result := make([]overlay.VNIInfo, 0, len(m.vnis))
	for _, vni := range m.vnis {
		result = append(result, *vni)
	}
	return result, nil
}

func (m *mockOverlayController) GetVNI(ctx context.Context, vni uint32) (*overlay.VNIInfo, error) {
	if v, exists := m.vnis[vni]; exists {
		return v, nil
	}
	return nil, errors.New("VNI not found")
}

func (m *mockOverlayController) GetRemoteMACs(ctx context.Context, vni uint32) ([]overlay.RemoteMACEntry, error) {
	return m.state.RemoteMACs, nil
}

func (m *mockOverlayController) ForgetMAC(ctx context.Context, mac net.HardwareAddr, vni uint32) error {
	if m.forgetMACErr != nil {
		return m.forgetMACErr
	}
	return nil
}

func TestNewOverlayService(t *testing.T) {
	t.Run("creates service without controller", func(t *testing.T) {
		svc := NewOverlayService()
		assert.NotNil(t, svc)
		assert.Nil(t, svc.Controller())
	})

	t.Run("creates service with controller option", func(t *testing.T) {
		mock := newMockOverlayController()
		svc := NewOverlayService(WithOverlayController(mock))
		assert.NotNil(t, svc)
		assert.Equal(t, mock, svc.Controller())
	})
}

func TestOverlayService_SetController(t *testing.T) {
	svc := NewOverlayService()
	assert.Nil(t, svc.Controller())

	mock := newMockOverlayController()
	svc.SetController(mock)
	assert.Equal(t, mock, svc.Controller())
}

func TestOverlayService_ListVTEPs(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func() *mockOverlayController
		expectError   bool
		errorContains string
		expectedCount int
	}{
		{
			name: "success",
			setupMock: func() *mockOverlayController {
				mock := newMockOverlayController()
				mock.vteps = []overlay.VTEPInfo{
					{NodeID: "node-1", IP: netip.MustParseAddr("10.0.0.1"), Healthy: true},
					{NodeID: "node-2", IP: netip.MustParseAddr("10.0.0.2"), Healthy: true},
				}
				return mock
			},
			expectError:   false,
			expectedCount: 2,
		},
		{
			name: "controller not configured",
			setupMock: func() *mockOverlayController {
				return nil
			},
			expectError:   true,
			errorContains: "overlay controller not configured",
		},
		{
			name: "controller not running",
			setupMock: func() *mockOverlayController {
				mock := newMockOverlayController()
				mock.running = false
				return mock
			},
			expectError:   true,
			errorContains: "overlay controller is not running",
		},
		{
			name: "list VTEPs error",
			setupMock: func() *mockOverlayController {
				mock := newMockOverlayController()
				mock.listVTEPsErr = errors.New("internal error")
				return mock
			},
			expectError:   true,
			errorContains: "failed to list VTEPs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewOverlayService()
			if mock != nil {
				svc.SetController(mock)
			}

			ctx := context.Background()
			resp, err := svc.ListVTEPs(ctx, &platformv1.ListVTEPsRequest{})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Len(t, resp.Vteps, tt.expectedCount)
			}
		})
	}
}

func TestOverlayService_GetVTEP(t *testing.T) {
	tests := []struct {
		name          string
		nodeID        string
		setupMock     func() *mockOverlayController
		expectError   bool
		errorContains string
	}{
		{
			name:   "success",
			nodeID: "node-1",
			setupMock: func() *mockOverlayController {
				mock := newMockOverlayController()
				mock.vteps = []overlay.VTEPInfo{
					{NodeID: "node-1", IP: netip.MustParseAddr("10.0.0.1"), Healthy: true},
				}
				return mock
			},
			expectError: false,
		},
		{
			name:   "empty node_id",
			nodeID: "",
			setupMock: func() *mockOverlayController {
				return newMockOverlayController()
			},
			expectError:   true,
			errorContains: "node_id is required",
		},
		{
			name:   "not found",
			nodeID: "nonexistent",
			setupMock: func() *mockOverlayController {
				mock := newMockOverlayController()
				mock.vteps = []overlay.VTEPInfo{
					{NodeID: "node-1", IP: netip.MustParseAddr("10.0.0.1"), Healthy: true},
				}
				return mock
			},
			expectError:   true,
			errorContains: "VTEP not found",
		},
		{
			name:   "controller not configured",
			nodeID: "node-1",
			setupMock: func() *mockOverlayController {
				return nil
			},
			expectError:   true,
			errorContains: "overlay controller not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewOverlayService()
			if mock != nil {
				svc.SetController(mock)
			}

			ctx := context.Background()
			resp, err := svc.GetVTEP(ctx, &platformv1.GetVTEPRequest{NodeId: tt.nodeID})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotNil(t, resp.Vtep)
				assert.Equal(t, tt.nodeID, resp.Vtep.NodeId)
			}
		})
	}
}

func TestOverlayService_CreateVNI(t *testing.T) {
	tests := []struct {
		name          string
		config        *platformv1.VNIConfig
		setupMock     func() *mockOverlayController
		expectError   bool
		errorContains string
	}{
		{
			name: "success",
			config: &platformv1.VNIConfig{
				Vni:  1000,
				Vlan: 100,
			},
			setupMock: func() *mockOverlayController {
				return newMockOverlayController()
			},
			expectError: false,
		},
		{
			name:   "nil config",
			config: nil,
			setupMock: func() *mockOverlayController {
				return newMockOverlayController()
			},
			expectError:   true,
			errorContains: "config is required",
		},
		{
			name: "zero VNI",
			config: &platformv1.VNIConfig{
				Vni: 0,
			},
			setupMock: func() *mockOverlayController {
				return newMockOverlayController()
			},
			expectError:   true,
			errorContains: "vni is required",
		},
		{
			name: "VNI exceeds max",
			config: &platformv1.VNIConfig{
				Vni: overlay.MaxVNI + 1,
			},
			setupMock: func() *mockOverlayController {
				return newMockOverlayController()
			},
			expectError:   true,
			errorContains: "vni must not exceed",
		},
		{
			name: "controller error",
			config: &platformv1.VNIConfig{
				Vni: 1000,
			},
			setupMock: func() *mockOverlayController {
				mock := newMockOverlayController()
				mock.addVNIErr = errors.New("internal error")
				return mock
			},
			expectError:   true,
			errorContains: "failed to create VNI",
		},
		{
			name: "controller not configured",
			config: &platformv1.VNIConfig{
				Vni: 1000,
			},
			setupMock: func() *mockOverlayController {
				return nil
			},
			expectError:   true,
			errorContains: "overlay controller not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewOverlayService()
			if mock != nil {
				svc.SetController(mock)
			}

			ctx := context.Background()
			req := &platformv1.CreateVNIRequest{Config: tt.config}
			resp, err := svc.CreateVNI(ctx, req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.True(t, resp.Status.Success)
				assert.NotNil(t, resp.Vni)
			}
		})
	}
}

func TestOverlayService_DeleteVNI(t *testing.T) {
	tests := []struct {
		name          string
		vni           uint32
		setupMock     func() *mockOverlayController
		expectError   bool
		errorContains string
	}{
		{
			name: "success",
			vni:  1000,
			setupMock: func() *mockOverlayController {
				mock := newMockOverlayController()
				mock.vnis[1000] = &overlay.VNIInfo{VNI: 1000}
				return mock
			},
			expectError: false,
		},
		{
			name: "zero VNI",
			vni:  0,
			setupMock: func() *mockOverlayController {
				return newMockOverlayController()
			},
			expectError:   true,
			errorContains: "vni is required",
		},
		{
			name: "controller error",
			vni:  1000,
			setupMock: func() *mockOverlayController {
				mock := newMockOverlayController()
				mock.removeVNIErr = errors.New("internal error")
				return mock
			},
			expectError:   true,
			errorContains: "failed to delete VNI",
		},
		{
			name: "controller not configured",
			vni:  1000,
			setupMock: func() *mockOverlayController {
				return nil
			},
			expectError:   true,
			errorContains: "overlay controller not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewOverlayService()
			if mock != nil {
				svc.SetController(mock)
			}

			ctx := context.Background()
			resp, err := svc.DeleteVNI(ctx, &platformv1.DeleteVNIRequest{Vni: tt.vni})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.True(t, resp.Status.Success)
			}
		})
	}
}

func TestOverlayService_ListVNIs(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func() *mockOverlayController
		expectError   bool
		errorContains string
		expectedCount int
	}{
		{
			name: "success with VNIs",
			setupMock: func() *mockOverlayController {
				mock := newMockOverlayController()
				mock.vnis[1000] = &overlay.VNIInfo{VNI: 1000}
				mock.vnis[2000] = &overlay.VNIInfo{VNI: 2000}
				return mock
			},
			expectError:   false,
			expectedCount: 2,
		},
		{
			name: "success empty",
			setupMock: func() *mockOverlayController {
				return newMockOverlayController()
			},
			expectError:   false,
			expectedCount: 0,
		},
		{
			name: "controller not configured",
			setupMock: func() *mockOverlayController {
				return nil
			},
			expectError:   true,
			errorContains: "overlay controller not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewOverlayService()
			if mock != nil {
				svc.SetController(mock)
			}

			ctx := context.Background()
			resp, err := svc.ListVNIs(ctx, &platformv1.ListVNIsRequest{})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Len(t, resp.Vnis, tt.expectedCount)
			}
		})
	}
}

func TestOverlayService_ListTunnels(t *testing.T) {
	tests := []struct {
		name          string
		vni           uint32
		setupMock     func() *mockOverlayController
		expectError   bool
		expectedCount int
	}{
		{
			name: "success all tunnels",
			vni:  0,
			setupMock: func() *mockOverlayController {
				mock := newMockOverlayController()
				mock.state.Tunnels = []overlay.TunnelInfo{
					{VNI: 1000, LocalVTEP: netip.MustParseAddr("10.0.0.1"), RemoteVTEP: netip.MustParseAddr("10.0.0.2"), State: vxlan.TunnelStatusUp},
					{VNI: 2000, LocalVTEP: netip.MustParseAddr("10.0.0.1"), RemoteVTEP: netip.MustParseAddr("10.0.0.3"), State: vxlan.TunnelStatusUp},
				}
				return mock
			},
			expectError:   false,
			expectedCount: 2,
		},
		{
			name: "success filtered by VNI",
			vni:  1000,
			setupMock: func() *mockOverlayController {
				mock := newMockOverlayController()
				mock.state.Tunnels = []overlay.TunnelInfo{
					{VNI: 1000, LocalVTEP: netip.MustParseAddr("10.0.0.1"), RemoteVTEP: netip.MustParseAddr("10.0.0.2"), State: vxlan.TunnelStatusUp},
					{VNI: 2000, LocalVTEP: netip.MustParseAddr("10.0.0.1"), RemoteVTEP: netip.MustParseAddr("10.0.0.3"), State: vxlan.TunnelStatusUp},
				}
				return mock
			},
			expectError:   false,
			expectedCount: 1,
		},
		{
			name: "controller not configured",
			vni:  0,
			setupMock: func() *mockOverlayController {
				return nil
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewOverlayService()
			if mock != nil {
				svc.SetController(mock)
			}

			ctx := context.Background()
			resp, err := svc.ListTunnels(ctx, &platformv1.ListTunnelsRequest{Vni: tt.vni})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Len(t, resp.Tunnels, tt.expectedCount)
			}
		})
	}
}

func TestOverlayService_GetTunnelStats(t *testing.T) {
	tests := []struct {
		name          string
		remoteVTEP    string
		vni           uint32
		setupMock     func() *mockOverlayController
		expectError   bool
		errorContains string
	}{
		{
			name:       "success",
			remoteVTEP: "10.0.0.2",
			vni:        0,
			setupMock: func() *mockOverlayController {
				mock := newMockOverlayController()
				mock.state.Tunnels = []overlay.TunnelInfo{
					{VNI: 1000, LocalVTEP: netip.MustParseAddr("10.0.0.1"), RemoteVTEP: netip.MustParseAddr("10.0.0.2"), State: vxlan.TunnelStatusUp, BytesTx: 1000, BytesRx: 2000},
				}
				return mock
			},
			expectError: false,
		},
		{
			name:       "empty remote_vtep",
			remoteVTEP: "",
			setupMock: func() *mockOverlayController {
				return newMockOverlayController()
			},
			expectError:   true,
			errorContains: "remote_vtep is required",
		},
		{
			name:       "invalid remote_vtep",
			remoteVTEP: "invalid",
			setupMock: func() *mockOverlayController {
				return newMockOverlayController()
			},
			expectError:   true,
			errorContains: "invalid remote_vtep",
		},
		{
			name:       "not found",
			remoteVTEP: "10.0.0.99",
			setupMock: func() *mockOverlayController {
				mock := newMockOverlayController()
				mock.state.Tunnels = []overlay.TunnelInfo{}
				return mock
			},
			expectError:   true,
			errorContains: "tunnel not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewOverlayService()
			if mock != nil {
				svc.SetController(mock)
			}

			ctx := context.Background()
			resp, err := svc.GetTunnelStats(ctx, &platformv1.GetTunnelStatsRequest{
				RemoteVtep: tt.remoteVTEP,
				Vni:        tt.vni,
			})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotNil(t, resp.Tunnel)
			}
		})
	}
}

func TestOverlayService_ListRemoteMACs(t *testing.T) {
	mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	mac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")

	tests := []struct {
		name          string
		vni           uint32
		setupMock     func() *mockOverlayController
		expectError   bool
		expectedCount int
	}{
		{
			name: "success all MACs",
			vni:  0,
			setupMock: func() *mockOverlayController {
				mock := newMockOverlayController()
				mock.state.RemoteMACs = []overlay.RemoteMACEntry{
					{MAC: mac1, VNI: 1000, RemoteVTEP: netip.MustParseAddr("10.0.0.2")},
					{MAC: mac2, VNI: 2000, RemoteVTEP: netip.MustParseAddr("10.0.0.3")},
				}
				return mock
			},
			expectError:   false,
			expectedCount: 2,
		},
		{
			name: "success filtered by VNI",
			vni:  1000,
			setupMock: func() *mockOverlayController {
				mock := newMockOverlayController()
				mock.state.RemoteMACs = []overlay.RemoteMACEntry{
					{MAC: mac1, VNI: 1000, RemoteVTEP: netip.MustParseAddr("10.0.0.2")},
					{MAC: mac2, VNI: 2000, RemoteVTEP: netip.MustParseAddr("10.0.0.3")},
				}
				return mock
			},
			expectError:   false,
			expectedCount: 1,
		},
		{
			name: "controller not configured",
			vni:  0,
			setupMock: func() *mockOverlayController {
				return nil
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewOverlayService()
			if mock != nil {
				svc.SetController(mock)
			}

			ctx := context.Background()
			resp, err := svc.ListRemoteMACs(ctx, &platformv1.ListRemoteMACsRequest{Vni: tt.vni})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Len(t, resp.Macs, tt.expectedCount)
			}
		})
	}
}

func TestOverlayService_ForgetMAC(t *testing.T) {
	tests := []struct {
		name          string
		mac           string
		vni           uint32
		setupMock     func() *mockOverlayController
		expectError   bool
		errorContains string
	}{
		{
			name: "success",
			mac:  "aa:bb:cc:dd:ee:ff",
			vni:  1000,
			setupMock: func() *mockOverlayController {
				return newMockOverlayController()
			},
			expectError: false,
		},
		{
			name: "empty MAC",
			mac:  "",
			vni:  1000,
			setupMock: func() *mockOverlayController {
				return newMockOverlayController()
			},
			expectError:   true,
			errorContains: "mac is required",
		},
		{
			name: "zero VNI",
			mac:  "aa:bb:cc:dd:ee:ff",
			vni:  0,
			setupMock: func() *mockOverlayController {
				return newMockOverlayController()
			},
			expectError:   true,
			errorContains: "vni is required",
		},
		{
			name: "invalid MAC",
			mac:  "invalid",
			vni:  1000,
			setupMock: func() *mockOverlayController {
				return newMockOverlayController()
			},
			expectError:   true,
			errorContains: "invalid MAC address",
		},
		{
			name: "controller error",
			mac:  "aa:bb:cc:dd:ee:ff",
			vni:  1000,
			setupMock: func() *mockOverlayController {
				mock := newMockOverlayController()
				mock.forgetMACErr = errors.New("internal error")
				return mock
			},
			expectError:   true,
			errorContains: "failed to forget MAC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewOverlayService()
			if mock != nil {
				svc.SetController(mock)
			}

			ctx := context.Background()
			resp, err := svc.ForgetMAC(ctx, &platformv1.ForgetMACRequest{
				Mac: tt.mac,
				Vni: tt.vni,
			})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.True(t, resp.Status.Success)
			}
		})
	}
}

func TestOverlayService_GetOverlayStatus(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func() *mockOverlayController
		expectError   bool
		expectHealthy bool
	}{
		{
			name: "success healthy",
			setupMock: func() *mockOverlayController {
				mock := newMockOverlayController()
				mock.state.VTEPs = make([]overlay.VTEPInfo, 2)
				mock.state.VNIs = make([]overlay.VNIInfo, 3)
				mock.state.Tunnels = make([]overlay.TunnelInfo, 5)
				mock.state.RemoteMACs = make([]overlay.RemoteMACEntry, 10)
				return mock
			},
			expectError:   false,
			expectHealthy: true,
		},
		{
			name: "controller not running",
			setupMock: func() *mockOverlayController {
				mock := newMockOverlayController()
				mock.running = false
				return mock
			},
			expectError:   false,
			expectHealthy: false,
		},
		{
			name: "controller not configured",
			setupMock: func() *mockOverlayController {
				return nil
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setupMock()
			svc := NewOverlayService()
			if mock != nil {
				svc.SetController(mock)
			}

			ctx := context.Background()
			resp, err := svc.GetOverlayStatus(ctx, &platformv1.GetOverlayStatusRequest{})

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, tt.expectHealthy, resp.Status.Healthy)
			}
		})
	}
}

func TestFormatVNIID(t *testing.T) {
	tests := []struct {
		vni      uint32
		expected string
	}{
		{0, "vni-0"},
		{1, "vni-1"},
		{1000, "vni-1000"},
		{16777215, "vni-16777215"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatVNIID(tt.vni)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVtepInfoToProto(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := vtepInfoToProto(nil)
		assert.Nil(t, result)
	})

	t.Run("valid input", func(t *testing.T) {
		now := time.Now()
		info := &overlay.VTEPInfo{
			NodeID:   "test-node",
			IP:       netip.MustParseAddr("10.0.0.1"),
			Healthy:  true,
			LastSeen: now,
		}
		result := vtepInfoToProto(info)
		require.NotNil(t, result)
		assert.Equal(t, "test-node", result.NodeId)
		assert.Equal(t, "10.0.0.1", result.Ip)
		assert.True(t, result.Healthy)
	})
}

func TestVniInfoToProto(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := vniInfoToProto(nil)
		assert.Nil(t, result)
	})

	t.Run("valid input", func(t *testing.T) {
		now := time.Now()
		info := &overlay.VNIInfo{
			VNI:       1000,
			VLAN:      100,
			MACCount:  5,
			CreatedAt: now,
		}
		result := vniInfoToProto(info)
		require.NotNil(t, result)
		assert.Equal(t, "vni-1000", result.Id)
		assert.Equal(t, uint32(1000), result.Config.Vni)
		assert.Equal(t, uint32(100), result.Config.Vlan)
		assert.Equal(t, uint32(5), result.MacCount)
	})
}

func TestTunnelInfoToProto(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := tunnelInfoToProto(nil)
		assert.Nil(t, result)
	})

	t.Run("valid input", func(t *testing.T) {
		info := &overlay.TunnelInfo{
			LocalVTEP:  netip.MustParseAddr("10.0.0.1"),
			RemoteVTEP: netip.MustParseAddr("10.0.0.2"),
			VNI:        1000,
			State:      vxlan.TunnelStatusUp,
			BytesTx:    1000,
			BytesRx:    2000,
		}
		result := tunnelInfoToProto(info)
		require.NotNil(t, result)
		assert.Equal(t, "10.0.0.1", result.LocalVtep)
		assert.Equal(t, "10.0.0.2", result.RemoteVtep)
		assert.Equal(t, uint32(1000), result.Vni)
		assert.Equal(t, uint64(1000), result.BytesTx)
		assert.Equal(t, uint64(2000), result.BytesRx)
	})
}

func TestRemoteMACEntryToProto(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := remoteMACEntryToProto(nil)
		assert.Nil(t, result)
	})

	t.Run("valid input", func(t *testing.T) {
		mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
		now := time.Now()
		entry := &overlay.RemoteMACEntry{
			MAC:        mac,
			VNI:        1000,
			RemoteVTEP: netip.MustParseAddr("10.0.0.2"),
			LearnedAt:  now,
		}
		result := remoteMACEntryToProto(entry)
		require.NotNil(t, result)
		assert.Equal(t, "aa:bb:cc:dd:ee:ff", result.Mac)
		assert.Equal(t, uint32(1000), result.Vni)
		assert.Equal(t, "10.0.0.2", result.RemoteVtep)
	})
}
