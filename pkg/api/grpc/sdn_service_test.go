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

package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// mockSDNService implements SDNService for testing.
type mockSDNService struct {
	createBridgeResp *ovs.Bridge
	createBridgeErr  error
	getBridgeResp    *ovs.Bridge
	getBridgeErr     error
	deleteBridgeErr  error
	listBridgesResp  []*ovs.Bridge
	listBridgesErr   error
	addPortResp      *ovs.Port
	addPortErr       error
	removePortErr    error
	getPortResp      *ovs.Port
	getPortErr       error
	listPortsResp    []*ovs.Port
	listPortsErr     error
	addFlowErr       error
	deleteFlowErr    error
	listFlowsResp    []*ovs.Flow
	listFlowsErr     error
	setPortVLANErr   error
	getInterfaceResp *ovs.Interface
	getInterfaceErr  error
	setPortStateErr  error
	getFlowStatsResp []*ovs.Flow
	getFlowStatsErr  error
}

func newMockSDNService() *mockSDNService {
	return &mockSDNService{
		createBridgeResp: &ovs.Bridge{
			UUID:         "br-uuid-123",
			Name:         "br-test",
			DatapathType: "system",
			FailMode:     "secure",
			Ports:        []string{"port1", "port2"},
			STP:          false,
			ExternalIDs:  map[string]string{"env": "test"},
			OtherConfig:  map[string]string{},
			Status:       map[string]string{},
		},
		getBridgeResp: &ovs.Bridge{
			UUID:         "br-uuid-123",
			Name:         "br-test",
			DatapathType: "system",
			Ports:        []string{"port1"},
		},
		listBridgesResp: []*ovs.Bridge{
			{UUID: "br-uuid-1", Name: "br1", Ports: []string{}},
			{UUID: "br-uuid-2", Name: "br2", Ports: []string{"p1"}},
		},
		addPortResp: &ovs.Port{
			UUID:        "port-uuid-123",
			Name:        "eth0",
			Interfaces:  []string{"eth0"},
			Tag:         100,
			VLANMode:    "access",
			ExternalIDs: map[string]string{},
			OtherConfig: map[string]string{},
		},
		getPortResp: &ovs.Port{
			UUID:       "port-uuid-123",
			Name:       "eth0",
			Tag:        100,
			Trunks:     []int64{10, 20, 30},
			VLANMode:   "access",
			MAC:        "aa:bb:cc:dd:ee:ff",
			Interfaces: []string{"eth0"},
		},
		listPortsResp: []*ovs.Port{
			{UUID: "port-1", Name: "eth0", Tag: 100},
			{UUID: "port-2", Name: "eth1", Tag: 200},
		},
		listFlowsResp: []*ovs.Flow{
			{
				Table:       0,
				Priority:    100,
				Match:       "in_port=1",
				Actions:     "output:2",
				Cookie:      "0x1234",
				Duration:    100,
				PacketCount: 1000,
				ByteCount:   100000,
			},
		},
		getInterfaceResp: &ovs.Interface{
			UUID:   "iface-uuid-123",
			Name:   "eth0",
			Type:   "system",
			OFPort: 1,
			Statistics: map[string]int64{
				"rx_packets": 1000,
				"tx_packets": 500,
				"rx_bytes":   100000,
				"tx_bytes":   50000,
				"rx_errors":  5,
				"tx_errors":  2,
				"rx_dropped": 10,
				"tx_dropped": 3,
			},
		},
		getFlowStatsResp: []*ovs.Flow{
			{
				Table:       0,
				Priority:    100,
				Match:       "in_port=1",
				Actions:     "output:2",
				Duration:    3600,
				PacketCount: 10000,
				ByteCount:   1000000,
			},
		},
	}
}

// generateTestCert creates a self-signed certificate for testing.
func generateTestCert(t *testing.T, cn string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM
}

func (m *mockSDNService) CreateBridge(ctx context.Context, name string) (*ovs.Bridge, error) {
	if m.createBridgeErr != nil {
		return nil, m.createBridgeErr
	}
	result := *m.createBridgeResp
	result.Name = name
	return &result, nil
}

func (m *mockSDNService) GetBridge(ctx context.Context, name string) (*ovs.Bridge, error) {
	if m.getBridgeErr != nil {
		return nil, m.getBridgeErr
	}
	return m.getBridgeResp, nil
}

func (m *mockSDNService) DeleteBridge(ctx context.Context, name string) error {
	return m.deleteBridgeErr
}

func (m *mockSDNService) ListBridges(ctx context.Context) ([]*ovs.Bridge, error) {
	if m.listBridgesErr != nil {
		return nil, m.listBridgesErr
	}
	return m.listBridgesResp, nil
}

func (m *mockSDNService) AddPort(ctx context.Context, bridgeName, portName string) (*ovs.Port, error) {
	if m.addPortErr != nil {
		return nil, m.addPortErr
	}
	result := *m.addPortResp
	result.Name = portName
	return &result, nil
}

func (m *mockSDNService) RemovePort(ctx context.Context, bridgeName, portName string) error {
	return m.removePortErr
}

func (m *mockSDNService) GetPort(ctx context.Context, portName string) (*ovs.Port, error) {
	if m.getPortErr != nil {
		return nil, m.getPortErr
	}
	return m.getPortResp, nil
}

func (m *mockSDNService) ListPorts(ctx context.Context, bridgeName string) ([]*ovs.Port, error) {
	if m.listPortsErr != nil {
		return nil, m.listPortsErr
	}
	return m.listPortsResp, nil
}

func (m *mockSDNService) AddFlow(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
	return m.addFlowErr
}

func (m *mockSDNService) DeleteFlow(ctx context.Context, bridgeName, match string) error {
	return m.deleteFlowErr
}

func (m *mockSDNService) ListFlows(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
	if m.listFlowsErr != nil {
		return nil, m.listFlowsErr
	}
	return m.listFlowsResp, nil
}

func (m *mockSDNService) SetPortVLAN(ctx context.Context, portName string, vlan int64) error {
	return m.setPortVLANErr
}

func (m *mockSDNService) GetInterface(ctx context.Context, ifaceName string) (*ovs.Interface, error) {
	if m.getInterfaceErr != nil {
		return nil, m.getInterfaceErr
	}
	return m.getInterfaceResp, nil
}

func (m *mockSDNService) SetPortState(ctx context.Context, portName string, state ovs.PortState) error {
	return m.setPortStateErr
}

func (m *mockSDNService) GetFlowStats(ctx context.Context, bridgeName, match string) ([]*ovs.Flow, error) {
	if m.getFlowStatsErr != nil {
		return nil, m.getFlowStatsErr
	}
	return m.getFlowStatsResp, nil
}

// Ensure mockSDNService implements SDNService at compile time.
var _ SDNService = (*mockSDNService)(nil)

func newTestSDNService() (*SDNGRPCService, *mockSDNService) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	mock := newMockSDNService()
	service := NewSDNGRPCService(logger, mock)
	return service, mock
}

// Test CreateBridge

func TestSDNGRPCService_CreateBridge_Success(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.CreateBridgeRequest{
		Config: &platformv1.BridgeConfig{
			Name:       "br-test",
			Type:       platformv1.BridgeType_BRIDGE_TYPE_OVS,
			StpEnabled: false,
		},
	}

	resp, err := service.CreateBridge(ctx, req)
	if err != nil {
		t.Fatalf("CreateBridge failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetBridge() == nil {
		t.Error("Expected bridge in response")
	}

	if resp.GetBridge().GetConfig().GetName() != "br-test" {
		t.Errorf("Expected bridge name 'br-test', got '%s'", resp.GetBridge().GetConfig().GetName())
	}
}

func TestSDNGRPCService_CreateBridge_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewSDNGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.CreateBridgeRequest{
		Config: &platformv1.BridgeConfig{Name: "br-test"},
	}

	_, err := service.CreateBridge(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestSDNGRPCService_CreateBridge_MissingConfig(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.CreateBridgeRequest{}

	_, err := service.CreateBridge(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing config")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_CreateBridge_MissingName(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.CreateBridgeRequest{
		Config: &platformv1.BridgeConfig{},
	}

	_, err := service.CreateBridge(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing bridge name")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_CreateBridge_ServiceError(t *testing.T) {
	service, mock := newTestSDNService()
	mock.createBridgeErr = errors.New("create failed")
	ctx := context.Background()

	req := &platformv1.CreateBridgeRequest{
		Config: &platformv1.BridgeConfig{Name: "br-test"},
	}

	_, err := service.CreateBridge(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal error, got %v", st.Code())
	}
}

// Test DeleteBridge

func TestSDNGRPCService_DeleteBridge_Success(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	// First create a bridge
	createReq := &platformv1.CreateBridgeRequest{
		Config: &platformv1.BridgeConfig{Name: "br-delete"},
	}
	createResp, _ := service.CreateBridge(ctx, createReq)

	req := &platformv1.DeleteBridgeRequest{
		Id: createResp.GetBridge().GetId(),
	}

	resp, err := service.DeleteBridge(ctx, req)
	if err != nil {
		t.Fatalf("DeleteBridge failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestSDNGRPCService_DeleteBridge_MissingID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.DeleteBridgeRequest{}

	_, err := service.DeleteBridge(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing bridge ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_DeleteBridge_ServiceError(t *testing.T) {
	service, mock := newTestSDNService()
	mock.deleteBridgeErr = errors.New("delete failed")
	ctx := context.Background()

	req := &platformv1.DeleteBridgeRequest{Id: "br-test"}

	_, err := service.DeleteBridge(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test GetBridge

func TestSDNGRPCService_GetBridge_Success(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.GetBridgeRequest{Id: "br-test"}

	resp, err := service.GetBridge(ctx, req)
	if err != nil {
		t.Fatalf("GetBridge failed: %v", err)
	}

	if resp.GetBridge() == nil {
		t.Error("Expected bridge in response")
	}
}

func TestSDNGRPCService_GetBridge_MissingID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.GetBridgeRequest{}

	_, err := service.GetBridge(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing bridge ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_GetBridge_NotFound(t *testing.T) {
	service, mock := newTestSDNService()
	mock.getBridgeErr = ErrSDNBridgeNotFound{BridgeName: "nonexistent"}
	ctx := context.Background()

	req := &platformv1.GetBridgeRequest{Id: "nonexistent"}

	_, err := service.GetBridge(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nonexistent bridge")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got %v", st.Code())
	}
}

// Test ListBridges

func TestSDNGRPCService_ListBridges_Success(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.ListBridgesRequest{}

	resp, err := service.ListBridges(ctx, req)
	if err != nil {
		t.Fatalf("ListBridges failed: %v", err)
	}

	if len(resp.GetBridges()) != 2 {
		t.Errorf("Expected 2 bridges, got %d", len(resp.GetBridges()))
	}
}

func TestSDNGRPCService_ListBridges_WithPagination(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.ListBridgesRequest{
		Pagination: &platformv1.PaginationRequest{
			Page:     0,
			PageSize: 1,
		},
	}

	resp, err := service.ListBridges(ctx, req)
	if err != nil {
		t.Fatalf("ListBridges failed: %v", err)
	}

	if len(resp.GetBridges()) != 1 {
		t.Errorf("Expected 1 bridge with pagination, got %d", len(resp.GetBridges()))
	}

	if resp.GetPagination().GetTotalItems() != 2 {
		t.Errorf("Expected 2 total items, got %d", resp.GetPagination().GetTotalItems())
	}
}

func TestSDNGRPCService_ListBridges_ServiceError(t *testing.T) {
	service, mock := newTestSDNService()
	mock.listBridgesErr = errors.New("list failed")
	ctx := context.Background()

	req := &platformv1.ListBridgesRequest{}

	_, err := service.ListBridges(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test AddPort

func TestSDNGRPCService_AddPort_Success(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.AddPortRequest{
		BridgeId: "br-test",
		Config: &platformv1.PortConfig{
			Name: "eth0",
			Type: platformv1.PortType_PORT_TYPE_PHYSICAL,
			Vlan: 100,
		},
	}

	resp, err := service.AddPort(ctx, req)
	if err != nil {
		t.Fatalf("AddPort failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetPort() == nil {
		t.Error("Expected port in response")
	}
}

func TestSDNGRPCService_AddPort_MissingBridgeID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.AddPortRequest{
		Config: &platformv1.PortConfig{Name: "eth0"},
	}

	_, err := service.AddPort(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing bridge ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_AddPort_MissingConfig(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.AddPortRequest{
		BridgeId: "br-test",
	}

	_, err := service.AddPort(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing port config")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_AddPort_MissingName(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.AddPortRequest{
		BridgeId: "br-test",
		Config:   &platformv1.PortConfig{},
	}

	_, err := service.AddPort(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing port name")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_AddPort_ServiceError(t *testing.T) {
	service, mock := newTestSDNService()
	mock.addPortErr = errors.New("add port failed")
	ctx := context.Background()

	req := &platformv1.AddPortRequest{
		BridgeId: "br-test",
		Config:   &platformv1.PortConfig{Name: "eth0"},
	}

	_, err := service.AddPort(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test DeletePort

func TestSDNGRPCService_DeletePort_Success(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.DeletePortRequest{
		BridgeId: "br-test",
		PortId:   "eth0",
	}

	resp, err := service.DeletePort(ctx, req)
	if err != nil {
		t.Fatalf("DeletePort failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestSDNGRPCService_DeletePort_MissingBridgeID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.DeletePortRequest{
		PortId: "eth0",
	}

	_, err := service.DeletePort(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing bridge ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_DeletePort_MissingPortID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.DeletePortRequest{
		BridgeId: "br-test",
	}

	_, err := service.DeletePort(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing port ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test GetPort

func TestSDNGRPCService_GetPort_Success(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.GetPortRequest{
		BridgeId: "br-test",
		PortId:   "eth0",
	}

	resp, err := service.GetPort(ctx, req)
	if err != nil {
		t.Fatalf("GetPort failed: %v", err)
	}

	if resp.GetPort() == nil {
		t.Error("Expected port in response")
	}
}

func TestSDNGRPCService_GetPort_MissingPortID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.GetPortRequest{
		BridgeId: "br-test",
	}

	_, err := service.GetPort(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing port ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test ListPorts

func TestSDNGRPCService_ListPorts_Success(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.ListPortsRequest{
		BridgeId: "br-test",
	}

	resp, err := service.ListPorts(ctx, req)
	if err != nil {
		t.Fatalf("ListPorts failed: %v", err)
	}

	if len(resp.GetPorts()) != 2 {
		t.Errorf("Expected 2 ports, got %d", len(resp.GetPorts()))
	}
}

func TestSDNGRPCService_ListPorts_MissingBridgeID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.ListPortsRequest{}

	_, err := service.ListPorts(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing bridge ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test AddFlow

func TestSDNGRPCService_AddFlow_Success(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.AddFlowRequest{
		Config: &platformv1.FlowConfig{
			BridgeId: "br-test",
			Table:    platformv1.FlowTable_FLOW_TABLE_0,
			Priority: 100,
			Match: &platformv1.FlowMatch{
				InPort: "1",
			},
			Actions: []*platformv1.FlowAction{
				{Type: platformv1.FlowActionType_FLOW_ACTION_OUTPUT, Port: "2"},
			},
		},
	}

	resp, err := service.AddFlow(ctx, req)
	if err != nil {
		t.Fatalf("AddFlow failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetFlow() == nil {
		t.Error("Expected flow in response")
	}
}

func TestSDNGRPCService_AddFlow_MissingConfig(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.AddFlowRequest{}

	_, err := service.AddFlow(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing flow config")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_AddFlow_MissingBridgeID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.AddFlowRequest{
		Config: &platformv1.FlowConfig{
			Priority: 100,
		},
	}

	_, err := service.AddFlow(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing bridge ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test DeleteFlow

func TestSDNGRPCService_DeleteFlow_Success(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.DeleteFlowRequest{
		BridgeId: "br-test",
		FlowId:   "flow-123",
	}

	resp, err := service.DeleteFlow(ctx, req)
	if err != nil {
		t.Fatalf("DeleteFlow failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestSDNGRPCService_DeleteFlow_MissingBridgeID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.DeleteFlowRequest{
		FlowId: "flow-123",
	}

	_, err := service.DeleteFlow(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing bridge ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_DeleteFlow_MissingFlowID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.DeleteFlowRequest{
		BridgeId: "br-test",
	}

	_, err := service.DeleteFlow(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing flow ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test ListFlows

func TestSDNGRPCService_ListFlows_Success(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.ListFlowsRequest{
		BridgeId: "br-test",
	}

	resp, err := service.ListFlows(ctx, req)
	if err != nil {
		t.Fatalf("ListFlows failed: %v", err)
	}

	if len(resp.GetFlows()) == 0 {
		t.Error("Expected flows in response")
	}
}

func TestSDNGRPCService_ListFlows_MissingBridgeID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.ListFlowsRequest{}

	_, err := service.ListFlows(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing bridge ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test FlushFlows

func TestSDNGRPCService_FlushFlows_Success(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.FlushFlowsRequest{
		BridgeId: "br-test",
	}

	resp, err := service.FlushFlows(ctx, req)
	if err != nil {
		t.Fatalf("FlushFlows failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestSDNGRPCService_FlushFlows_MissingBridgeID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.FlushFlowsRequest{}

	_, err := service.FlushFlows(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing bridge ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test CreateVLAN

func TestSDNGRPCService_CreateVLAN_Success(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.CreateVLANRequest{
		Config: &platformv1.VLANConfig{
			VlanId:   100,
			Name:     "vlan100",
			BridgeId: "br-test",
			Ports:    []string{"eth0", "eth1"},
		},
	}

	resp, err := service.CreateVLAN(ctx, req)
	if err != nil {
		t.Fatalf("CreateVLAN failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetVlan() == nil {
		t.Error("Expected VLAN in response")
	}
}

func TestSDNGRPCService_CreateVLAN_MissingConfig(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.CreateVLANRequest{}

	_, err := service.CreateVLAN(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing VLAN config")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_CreateVLAN_InvalidVLANID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.CreateVLANRequest{
		Config: &platformv1.VLANConfig{
			VlanId:   0,
			BridgeId: "br-test",
		},
	}

	_, err := service.CreateVLAN(ctx, req)
	if err == nil {
		t.Fatal("Expected error for invalid VLAN ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_CreateVLAN_VLANIDTooHigh(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.CreateVLANRequest{
		Config: &platformv1.VLANConfig{
			VlanId:   4095,
			BridgeId: "br-test",
		},
	}

	_, err := service.CreateVLAN(ctx, req)
	if err == nil {
		t.Fatal("Expected error for VLAN ID too high")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_CreateVLAN_MissingBridgeID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.CreateVLANRequest{
		Config: &platformv1.VLANConfig{
			VlanId: 100,
		},
	}

	_, err := service.CreateVLAN(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing bridge ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test DeleteVLAN

func TestSDNGRPCService_DeleteVLAN_Success(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	// First create a VLAN
	createReq := &platformv1.CreateVLANRequest{
		Config: &platformv1.VLANConfig{
			VlanId:   100,
			BridgeId: "br-test",
		},
	}
	_, _ = service.CreateVLAN(ctx, createReq)

	req := &platformv1.DeleteVLANRequest{
		BridgeId: "br-test",
		VlanId:   100,
	}

	resp, err := service.DeleteVLAN(ctx, req)
	if err != nil {
		t.Fatalf("DeleteVLAN failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestSDNGRPCService_DeleteVLAN_MissingBridgeID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.DeleteVLANRequest{
		VlanId: 100,
	}

	_, err := service.DeleteVLAN(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing bridge ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_DeleteVLAN_InvalidVLANID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.DeleteVLANRequest{
		BridgeId: "br-test",
		VlanId:   0,
	}

	_, err := service.DeleteVLAN(ctx, req)
	if err == nil {
		t.Fatal("Expected error for invalid VLAN ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test ListVLANs

func TestSDNGRPCService_ListVLANs_Success(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	// Create VLANs first
	for _, vlan := range []uint32{100, 200} {
		createReq := &platformv1.CreateVLANRequest{
			Config: &platformv1.VLANConfig{
				VlanId:   vlan,
				BridgeId: "br-test",
			},
		}
		_, _ = service.CreateVLAN(ctx, createReq)
	}

	req := &platformv1.ListVLANsRequest{
		BridgeId: "br-test",
	}

	resp, err := service.ListVLANs(ctx, req)
	if err != nil {
		t.Fatalf("ListVLANs failed: %v", err)
	}

	if len(resp.GetVlans()) != 2 {
		t.Errorf("Expected 2 VLANs, got %d", len(resp.GetVlans()))
	}
}

func TestSDNGRPCService_ListVLANs_MissingBridgeID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.ListVLANsRequest{}

	_, err := service.ListVLANs(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing bridge ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test AuthenticatePort

func TestSDNGRPCService_AuthenticatePort_Success(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	// Create a valid PEM certificate for testing
	pemCert := generateTestCert(t, "testcn")

	req := &platformv1.AuthenticatePortRequest{
		BridgeId:    "br-test",
		PortId:      "eth0",
		Certificate: pemCert,
		Format:      "PEM",
	}

	resp, err := service.AuthenticatePort(ctx, req)
	if err != nil {
		t.Fatalf("AuthenticatePort failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetAuth() == nil {
		t.Error("Expected auth in response")
	}

	if !resp.GetAuth().GetAuthenticated() {
		t.Error("Expected authenticated to be true")
	}

	if resp.GetAuth().GetCertificateCn() != "testcn" {
		t.Errorf("Expected certificate CN 'testcn', got '%s'", resp.GetAuth().GetCertificateCn())
	}
}

func TestSDNGRPCService_AuthenticatePort_MissingBridgeID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.AuthenticatePortRequest{
		PortId:      "eth0",
		Certificate: []byte("cert"),
	}

	_, err := service.AuthenticatePort(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing bridge ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_AuthenticatePort_MissingPortID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.AuthenticatePortRequest{
		BridgeId:    "br-test",
		Certificate: []byte("cert"),
	}

	_, err := service.AuthenticatePort(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing port ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_AuthenticatePort_MissingCertificate(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.AuthenticatePortRequest{
		BridgeId: "br-test",
		PortId:   "eth0",
	}

	_, err := service.AuthenticatePort(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing certificate")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_AuthenticatePort_InvalidFormat(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.AuthenticatePortRequest{
		BridgeId:    "br-test",
		PortId:      "eth0",
		Certificate: []byte("invalid cert data"),
		Format:      "INVALID",
	}

	_, err := service.AuthenticatePort(ctx, req)
	if err == nil {
		t.Fatal("Expected error for invalid certificate format")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_AuthenticatePort_InvalidPEM(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.AuthenticatePortRequest{
		BridgeId:    "br-test",
		PortId:      "eth0",
		Certificate: []byte("not a valid PEM"),
		Format:      "PEM",
	}

	_, err := service.AuthenticatePort(ctx, req)
	if err == nil {
		t.Fatal("Expected error for invalid PEM")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test RevokePortAuth

func TestSDNGRPCService_RevokePortAuth_Success(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.RevokePortAuthRequest{
		BridgeId: "br-test",
		PortId:   "eth0",
	}

	resp, err := service.RevokePortAuth(ctx, req)
	if err != nil {
		t.Fatalf("RevokePortAuth failed: %v", err)
	}

	if !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestSDNGRPCService_RevokePortAuth_MissingBridgeID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.RevokePortAuthRequest{
		PortId: "eth0",
	}

	_, err := service.RevokePortAuth(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing bridge ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_RevokePortAuth_MissingPortID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.RevokePortAuthRequest{
		BridgeId: "br-test",
	}

	_, err := service.RevokePortAuth(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing port ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test GetPortStats

func TestSDNGRPCService_GetPortStats_Success(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.GetPortStatsRequest{
		BridgeId: "br-test",
		PortId:   "eth0",
	}

	resp, err := service.GetPortStats(ctx, req)
	if err != nil {
		t.Fatalf("GetPortStats failed: %v", err)
	}

	if resp.GetStats() == nil {
		t.Error("Expected stats in response")
	}

	if resp.GetStats().GetPacketsReceived() != 1000 {
		t.Errorf("Expected 1000 packets received, got %d", resp.GetStats().GetPacketsReceived())
	}
}

func TestSDNGRPCService_GetPortStats_MissingBridgeID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.GetPortStatsRequest{
		PortId: "eth0",
	}

	_, err := service.GetPortStats(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing bridge ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_GetPortStats_MissingPortID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.GetPortStatsRequest{
		BridgeId: "br-test",
	}

	_, err := service.GetPortStats(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing port ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test GetFlowStats

func TestSDNGRPCService_GetFlowStats_Success(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.GetFlowStatsRequest{
		BridgeId: "br-test",
		FlowId:   "flow-123",
	}

	resp, err := service.GetFlowStats(ctx, req)
	if err != nil {
		t.Fatalf("GetFlowStats failed: %v", err)
	}

	if resp.GetStats() == nil {
		t.Error("Expected stats in response")
	}

	if resp.GetStats().GetPacketCount() != 10000 {
		t.Errorf("Expected 10000 packets, got %d", resp.GetStats().GetPacketCount())
	}
}

func TestSDNGRPCService_GetFlowStats_MissingBridgeID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.GetFlowStatsRequest{
		FlowId: "flow-123",
	}

	_, err := service.GetFlowStats(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing bridge ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_GetFlowStats_MissingFlowID(t *testing.T) {
	service, _ := newTestSDNService()
	ctx := context.Background()

	req := &platformv1.GetFlowStatsRequest{
		BridgeId: "br-test",
	}

	_, err := service.GetFlowStats(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing flow ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test error type definitions

func TestErrNilSDNService_Error(t *testing.T) {
	err := ErrNilSDNService{}
	expected := "sdn service is nil"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingBridgeID_Error(t *testing.T) {
	err := ErrMissingBridgeID{}
	expected := "bridge ID is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingBridgeConfig_Error(t *testing.T) {
	err := ErrMissingBridgeConfig{}
	expected := "bridge configuration is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingBridgeName_Error(t *testing.T) {
	err := ErrMissingBridgeName{}
	expected := "bridge name is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingPortID_Error(t *testing.T) {
	err := ErrMissingPortID{}
	expected := "port ID is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingPortConfig_Error(t *testing.T) {
	err := ErrMissingPortConfig{}
	expected := "port configuration is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingPortName_Error(t *testing.T) {
	err := ErrMissingPortName{}
	expected := "port name is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingFlowID_Error(t *testing.T) {
	err := ErrMissingFlowID{}
	expected := "flow ID is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingFlowConfig_Error(t *testing.T) {
	err := ErrMissingFlowConfig{}
	expected := "flow configuration is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingVLANConfig_Error(t *testing.T) {
	err := ErrMissingVLANConfig{}
	expected := "VLAN configuration is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrInvalidVLANID_Error(t *testing.T) {
	err := ErrInvalidVLANID{}
	expected := "VLAN ID must be between 1 and 4094"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingCertificate_Error(t *testing.T) {
	err := ErrMissingCertificate{}
	expected := "certificate (PEM or DER) is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestSDNGRPCService_flowTableToInt(t *testing.T) {
	service, _ := newTestSDNService()

	tests := []struct {
		table    platformv1.FlowTable
		expected int
	}{
		{platformv1.FlowTable_FLOW_TABLE_0, 0},
		{platformv1.FlowTable_FLOW_TABLE_1, 1},
		{platformv1.FlowTable_FLOW_TABLE_2, 2},
		{platformv1.FlowTable_FLOW_TABLE_3, 3},
		{platformv1.FlowTable_FLOW_TABLE_DROP, 255},
		{platformv1.FlowTable_FLOW_TABLE_UNSPECIFIED, 0},
	}

	for _, tc := range tests {
		result := service.flowTableToInt(tc.table)
		if result != tc.expected {
			t.Errorf("flowTableToInt(%v) = %d, expected %d", tc.table, result, tc.expected)
		}
	}
}

func TestSDNGRPCService_intToFlowTable(t *testing.T) {
	service, _ := newTestSDNService()

	tests := []struct {
		input    int
		expected platformv1.FlowTable
	}{
		{0, platformv1.FlowTable_FLOW_TABLE_0},
		{1, platformv1.FlowTable_FLOW_TABLE_1},
		{2, platformv1.FlowTable_FLOW_TABLE_2},
		{3, platformv1.FlowTable_FLOW_TABLE_3},
		{255, platformv1.FlowTable_FLOW_TABLE_DROP},
		{99, platformv1.FlowTable_FLOW_TABLE_UNSPECIFIED},
	}

	for _, tc := range tests {
		result := service.intToFlowTable(tc.input)
		if result != tc.expected {
			t.Errorf("intToFlowTable(%d) = %v, expected %v", tc.input, result, tc.expected)
		}
	}
}

func TestSDNGRPCService_buildMatchString(t *testing.T) {
	service, _ := newTestSDNService()

	tests := []struct {
		name     string
		match    *platformv1.FlowMatch
		expected string
	}{
		{
			name:     "nil match",
			match:    nil,
			expected: "",
		},
		{
			name: "in_port only",
			match: &platformv1.FlowMatch{
				InPort: "1",
			},
			expected: "in_port=1",
		},
		{
			name: "multiple fields",
			match: &platformv1.FlowMatch{
				InPort:  "1",
				VlanId:  100,
				IpProto: 6,
				TcpDst:  80,
			},
			expected: "in_port=1,dl_vlan=100,nw_proto=6,tcp_dst=80",
		},
		{
			name: "ethernet addresses",
			match: &platformv1.FlowMatch{
				EthSrc: "aa:bb:cc:dd:ee:ff",
				EthDst: "11:22:33:44:55:66",
			},
			expected: "dl_src=aa:bb:cc:dd:ee:ff,dl_dst=11:22:33:44:55:66",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := service.buildMatchString(tc.match)
			if result != tc.expected {
				t.Errorf("buildMatchString() = '%s', expected '%s'", result, tc.expected)
			}
		})
	}
}

func TestSDNGRPCService_buildActionsString(t *testing.T) {
	service, _ := newTestSDNService()

	tests := []struct {
		name     string
		actions  []*platformv1.FlowAction
		expected string
	}{
		{
			name:     "nil actions",
			actions:  nil,
			expected: "NORMAL",
		},
		{
			name:     "empty actions",
			actions:  []*platformv1.FlowAction{},
			expected: "NORMAL",
		},
		{
			name: "output action",
			actions: []*platformv1.FlowAction{
				{Type: platformv1.FlowActionType_FLOW_ACTION_OUTPUT, Port: "2"},
			},
			expected: "output:2",
		},
		{
			name: "drop action",
			actions: []*platformv1.FlowAction{
				{Type: platformv1.FlowActionType_FLOW_ACTION_DROP},
			},
			expected: "drop",
		},
		{
			name: "multiple actions",
			actions: []*platformv1.FlowAction{
				{Type: platformv1.FlowActionType_FLOW_ACTION_SET_VLAN, VlanId: 100},
				{Type: platformv1.FlowActionType_FLOW_ACTION_OUTPUT, Port: "3"},
			},
			expected: "mod_vlan_vid:100,output:3",
		},
		{
			name: "strip vlan and goto table",
			actions: []*platformv1.FlowAction{
				{Type: platformv1.FlowActionType_FLOW_ACTION_STRIP_VLAN},
				{Type: platformv1.FlowActionType_FLOW_ACTION_GOTO_TABLE, TableId: 1},
			},
			expected: "strip_vlan,goto_table:1",
		},
		{
			name: "controller action",
			actions: []*platformv1.FlowAction{
				{Type: platformv1.FlowActionType_FLOW_ACTION_CONTROLLER},
			},
			expected: "CONTROLLER",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := service.buildActionsString(tc.actions)
			if result != tc.expected {
				t.Errorf("buildActionsString() = '%s', expected '%s'", result, tc.expected)
			}
		})
	}
}

// Test error mapping

func TestSDNGRPCService_mapError_BridgeNotFound(t *testing.T) {
	service, _ := newTestSDNService()

	err := ErrSDNBridgeNotFound{BridgeName: "br-missing"}
	result := service.mapError("GetBridge", err)

	st, ok := status.FromError(result)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got %v", st.Code())
	}
}

func TestSDNGRPCService_mapError_PortNotFound(t *testing.T) {
	service, _ := newTestSDNService()

	err := ErrSDNPortNotFound{PortName: "eth-missing"}
	result := service.mapError("GetPort", err)

	st, ok := status.FromError(result)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got %v", st.Code())
	}
}

func TestSDNGRPCService_mapError_BridgeAlreadyExists(t *testing.T) {
	service, _ := newTestSDNService()

	err := ErrSDNBridgeAlreadyExists{BridgeName: "br-exists"}
	result := service.mapError("CreateBridge", err)

	st, ok := status.FromError(result)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.AlreadyExists {
		t.Errorf("Expected AlreadyExists, got %v", st.Code())
	}
}

func TestSDNGRPCService_mapError_InvalidRequest(t *testing.T) {
	service, _ := newTestSDNService()

	err := ErrSDNInvalidRequest{Reason: "bad input"}
	result := service.mapError("AddPort", err)

	st, ok := status.FromError(result)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_mapError_OperationFailed(t *testing.T) {
	service, _ := newTestSDNService()

	err := ErrSDNOperationFailed{Operation: "AddFlow", Cause: errors.New("failed")}
	result := service.mapError("AddFlow", err)

	st, ok := status.FromError(result)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal, got %v", st.Code())
	}
}

func TestSDNGRPCService_mapError_NilError(t *testing.T) {
	service, _ := newTestSDNService()

	result := service.mapError("operation", nil)
	if result != nil {
		t.Error("Expected nil result for nil error")
	}
}

func TestSDNGRPCService_mapError_PortAlreadyExists(t *testing.T) {
	service, _ := newTestSDNService()

	err := ErrSDNPortAlreadyExists{PortName: "eth-exists"}
	result := service.mapError("AddPort", err)

	st, ok := status.FromError(result)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.AlreadyExists {
		t.Errorf("Expected AlreadyExists, got %v", st.Code())
	}
}

func TestSDNGRPCService_mapError_GenericError(t *testing.T) {
	service, _ := newTestSDNService()

	err := errors.New("generic error")
	result := service.mapError("SomeOperation", err)

	st, ok := status.FromError(result)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal, got %v", st.Code())
	}
}

// Test NilService errors for all methods

func TestSDNGRPCService_AllMethods_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewSDNGRPCService(logger, nil)
	ctx := context.Background()

	// Test all methods return FailedPrecondition for nil service
	tests := []struct {
		name string
		fn   func() error
	}{
		{"DeleteBridge", func() error {
			_, err := service.DeleteBridge(ctx, &platformv1.DeleteBridgeRequest{Id: "test"})
			return err
		}},
		{"GetBridge", func() error {
			_, err := service.GetBridge(ctx, &platformv1.GetBridgeRequest{Id: "test"})
			return err
		}},
		{"ListBridges", func() error {
			_, err := service.ListBridges(ctx, &platformv1.ListBridgesRequest{})
			return err
		}},
		{"AddPort", func() error {
			_, err := service.AddPort(ctx, &platformv1.AddPortRequest{BridgeId: "test", Config: &platformv1.PortConfig{Name: "p"}})
			return err
		}},
		{"DeletePort", func() error {
			_, err := service.DeletePort(ctx, &platformv1.DeletePortRequest{BridgeId: "test", PortId: "p"})
			return err
		}},
		{"GetPort", func() error {
			_, err := service.GetPort(ctx, &platformv1.GetPortRequest{PortId: "p"})
			return err
		}},
		{"ListPorts", func() error {
			_, err := service.ListPorts(ctx, &platformv1.ListPortsRequest{BridgeId: "test"})
			return err
		}},
		{"AddFlow", func() error {
			_, err := service.AddFlow(ctx, &platformv1.AddFlowRequest{Config: &platformv1.FlowConfig{BridgeId: "test"}})
			return err
		}},
		{"DeleteFlow", func() error {
			_, err := service.DeleteFlow(ctx, &platformv1.DeleteFlowRequest{BridgeId: "test", FlowId: "f"})
			return err
		}},
		{"ListFlows", func() error {
			_, err := service.ListFlows(ctx, &platformv1.ListFlowsRequest{BridgeId: "test"})
			return err
		}},
		{"FlushFlows", func() error {
			_, err := service.FlushFlows(ctx, &platformv1.FlushFlowsRequest{BridgeId: "test"})
			return err
		}},
		{"CreateVLAN", func() error {
			_, err := service.CreateVLAN(ctx, &platformv1.CreateVLANRequest{Config: &platformv1.VLANConfig{VlanId: 100, BridgeId: "test"}})
			return err
		}},
		{"DeleteVLAN", func() error {
			_, err := service.DeleteVLAN(ctx, &platformv1.DeleteVLANRequest{BridgeId: "test", VlanId: 100})
			return err
		}},
		{"ListVLANs", func() error {
			_, err := service.ListVLANs(ctx, &platformv1.ListVLANsRequest{BridgeId: "test"})
			return err
		}},
		{"AuthenticatePort", func() error {
			_, err := service.AuthenticatePort(ctx, &platformv1.AuthenticatePortRequest{BridgeId: "test", PortId: "p", Certificate: []byte("c")})
			return err
		}},
		{"RevokePortAuth", func() error {
			_, err := service.RevokePortAuth(ctx, &platformv1.RevokePortAuthRequest{BridgeId: "test", PortId: "p"})
			return err
		}},
		{"GetPortStats", func() error {
			_, err := service.GetPortStats(ctx, &platformv1.GetPortStatsRequest{BridgeId: "test", PortId: "p"})
			return err
		}},
		{"GetFlowStats", func() error {
			_, err := service.GetFlowStats(ctx, &platformv1.GetFlowStatsRequest{BridgeId: "test", FlowId: "f"})
			return err
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil {
				t.Error("Expected error for nil service")
				return
			}

			st, ok := status.FromError(err)
			if !ok {
				t.Error("Expected gRPC status error")
				return
			}

			if st.Code() != codes.FailedPrecondition {
				t.Errorf("Expected FailedPrecondition, got %v", st.Code())
			}
		})
	}
}

// Test helper functions for coverage

func TestSDNGRPCService_ovsBridgeToProto_NilBridge(t *testing.T) {
	service, _ := newTestSDNService()

	result := service.ovsBridgeToProto(nil)
	if result != nil {
		t.Error("Expected nil result for nil bridge")
	}
}

func TestSDNGRPCService_ovsBridgeToProto_WithNetdevDatapath(t *testing.T) {
	service, _ := newTestSDNService()

	bridge := &ovs.Bridge{
		UUID:         "br-uuid",
		Name:         "br0",
		DatapathType: "netdev",
		Ports:        []string{"p1", "p2"},
		STP:          true,
		ExternalIDs:  map[string]string{"key": "value"},
		OtherConfig:  map[string]string{"opt": "val"},
	}

	result := service.ovsBridgeToProto(bridge)
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.GetConfig().GetType() != platformv1.BridgeType_BRIDGE_TYPE_LINUX {
		t.Errorf("Expected LINUX bridge type, got %v", result.GetConfig().GetType())
	}

	if result.GetConfig().GetStpEnabled() != true {
		t.Error("Expected STP enabled")
	}
}

func TestSDNGRPCService_ovsBridgeToProto_EmptyUUID(t *testing.T) {
	service, _ := newTestSDNService()

	bridge := &ovs.Bridge{
		UUID: "",
		Name: "br0",
	}

	result := service.ovsBridgeToProto(bridge)
	if result.GetId() != "br0" {
		t.Errorf("Expected ID to be bridge name 'br0', got '%s'", result.GetId())
	}
}

func TestSDNGRPCService_ovsPortToProto_NilPort(t *testing.T) {
	service, _ := newTestSDNService()

	result := service.ovsPortToProto(nil, "br0")
	if result != nil {
		t.Error("Expected nil result for nil port")
	}
}

func TestSDNGRPCService_ovsPortToProto_VLANAccessMode(t *testing.T) {
	service, _ := newTestSDNService()

	port := &ovs.Port{
		UUID:     "port-uuid",
		Name:     "eth0",
		VLANMode: "access",
		Tag:      100,
		Trunks:   []int64{10, 20},
		MAC:      "aa:bb:cc:dd:ee:ff",
	}

	result := service.ovsPortToProto(port, "br0")
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.GetConfig().GetType() != platformv1.PortType_PORT_TYPE_INTERNAL {
		t.Errorf("Expected INTERNAL port type for access mode, got %v", result.GetConfig().GetType())
	}

	if result.GetConfig().GetVlan() != 100 {
		t.Errorf("Expected VLAN 100, got %d", result.GetConfig().GetVlan())
	}
}

func TestSDNGRPCService_ovsPortToProto_EmptyUUID(t *testing.T) {
	service, _ := newTestSDNService()

	port := &ovs.Port{
		UUID: "",
		Name: "eth0",
	}

	result := service.ovsPortToProto(port, "br0")
	if result.GetId() != "eth0" {
		t.Errorf("Expected ID to be port name 'eth0', got '%s'", result.GetId())
	}
}

func TestSDNGRPCService_ovsFlowToProto_NilFlow(t *testing.T) {
	service, _ := newTestSDNService()

	result := service.ovsFlowToProto(nil, "br0")
	if result != nil {
		t.Error("Expected nil result for nil flow")
	}
}

func TestSDNGRPCService_ovsFlowToProto_WithCookie(t *testing.T) {
	service, _ := newTestSDNService()

	flow := &ovs.Flow{
		Cookie:      "0xABCD",
		Table:       1,
		Priority:    200,
		Match:       "in_port=1,dl_vlan=100",
		Actions:     "output:2",
		Duration:    3600,
		IdleAge:     60,
		HardAge:     120,
		PacketCount: 1000,
		ByteCount:   100000,
	}

	result := service.ovsFlowToProto(flow, "br0")
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.GetId() != "0xABCD" {
		t.Errorf("Expected flow ID '0xABCD', got '%s'", result.GetId())
	}

	if result.GetConfig().GetTable() != platformv1.FlowTable_FLOW_TABLE_1 {
		t.Errorf("Expected FLOW_TABLE_1, got %v", result.GetConfig().GetTable())
	}
}

func TestSDNGRPCService_ovsFlowToProto_EmptyCookie(t *testing.T) {
	service, _ := newTestSDNService()

	flow := &ovs.Flow{
		Cookie: "",
		Match:  "in_port=1",
	}

	result := service.ovsFlowToProto(flow, "br0")
	if result.GetId() != "in_port=1" {
		t.Errorf("Expected flow ID from match, got '%s'", result.GetId())
	}
}

func TestSDNGRPCService_mergeBridgeWithOVS_NilCached(t *testing.T) {
	service, _ := newTestSDNService()

	ovsBridge := &ovs.Bridge{
		UUID:  "br-uuid",
		Name:  "br0",
		Ports: []string{"p1", "p2"},
	}

	result := service.mergeBridgeWithOVS(nil, ovsBridge)
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.GetConfig().GetName() != "br0" {
		t.Errorf("Expected bridge name 'br0', got '%s'", result.GetConfig().GetName())
	}
}

func TestSDNGRPCService_mergeBridgeWithOVS_NilOVSBridge(t *testing.T) {
	service, _ := newTestSDNService()

	cached := &platformv1.Bridge{
		Id: "cached-bridge",
		Config: &platformv1.BridgeConfig{
			Name: "cached",
		},
	}

	result := service.mergeBridgeWithOVS(cached, nil)
	if result != cached {
		t.Error("Expected cached bridge to be returned")
	}
}

func TestSDNGRPCService_mergeBridgeWithOVS_BothProvided(t *testing.T) {
	service, _ := newTestSDNService()

	cached := &platformv1.Bridge{
		Id: "cached-bridge",
		Config: &platformv1.BridgeConfig{
			Name: "cached",
		},
		Stats: &platformv1.BridgeStats{
			TotalPorts: 1,
		},
	}

	ovsBridge := &ovs.Bridge{
		UUID:  "ovs-uuid",
		Name:  "ovs-br",
		Ports: []string{"p1", "p2", "p3"},
	}

	result := service.mergeBridgeWithOVS(cached, ovsBridge)
	if result.GetStats().GetTotalPorts() != 3 {
		t.Errorf("Expected 3 ports from OVS, got %d", result.GetStats().GetTotalPorts())
	}
}

func TestSDNGRPCService_mergePortWithOVS_NilCached(t *testing.T) {
	service, _ := newTestSDNService()

	ovsPort := &ovs.Port{
		UUID:   "port-uuid",
		Name:   "eth0",
		Tag:    100,
		Trunks: []int64{10, 20},
	}

	result := service.mergePortWithOVS(nil, ovsPort)
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.GetConfig().GetName() != "eth0" {
		t.Errorf("Expected port name 'eth0', got '%s'", result.GetConfig().GetName())
	}
}

func TestSDNGRPCService_mergePortWithOVS_NilOVSPort(t *testing.T) {
	service, _ := newTestSDNService()

	cached := &platformv1.Port{
		Id: "cached-port",
		Config: &platformv1.PortConfig{
			Name: "cached",
			Vlan: 50,
		},
	}

	result := service.mergePortWithOVS(cached, nil)
	if result != cached {
		t.Error("Expected cached port to be returned")
	}
}

func TestSDNGRPCService_mergePortWithOVS_BothProvided(t *testing.T) {
	service, _ := newTestSDNService()

	cached := &platformv1.Port{
		Id: "cached-port",
		Config: &platformv1.PortConfig{
			Name: "cached",
			Vlan: 50,
		},
	}

	ovsPort := &ovs.Port{
		UUID:   "ovs-uuid",
		Name:   "ovs-port",
		Tag:    200,
		Trunks: []int64{100, 200, 300},
	}

	result := service.mergePortWithOVS(cached, ovsPort)
	if result.GetConfig().GetVlan() != 200 {
		t.Errorf("Expected VLAN 200 from OVS, got %d", result.GetConfig().GetVlan())
	}

	if len(result.GetConfig().GetTrunkVlans()) != 3 {
		t.Errorf("Expected 3 trunk VLANs, got %d", len(result.GetConfig().GetTrunkVlans()))
	}
}

func TestSDNGRPCService_protoFlowConfigToOVS_NilConfig(t *testing.T) {
	service, _ := newTestSDNService()

	result := service.protoFlowConfigToOVS(nil)
	if result != nil {
		t.Error("Expected nil result for nil config")
	}
}

func TestSDNGRPCService_protoFlowConfigToOVS_FullConfig(t *testing.T) {
	service, _ := newTestSDNService()

	config := &platformv1.FlowConfig{
		BridgeId: "br0",
		Table:    platformv1.FlowTable_FLOW_TABLE_1,
		Priority: 100,
		Match: &platformv1.FlowMatch{
			InPort: "1",
			VlanId: 100,
		},
		Actions: []*platformv1.FlowAction{
			{Type: platformv1.FlowActionType_FLOW_ACTION_OUTPUT, Port: "2"},
		},
		IdleTimeout: 60,
		HardTimeout: 120,
	}

	result := service.protoFlowConfigToOVS(config)
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Table != 1 {
		t.Errorf("Expected table 1, got %d", result.Table)
	}

	if result.Priority != 100 {
		t.Errorf("Expected priority 100, got %d", result.Priority)
	}

	if result.IdleTimeout != 60 {
		t.Errorf("Expected idle timeout 60, got %d", result.IdleTimeout)
	}
}

func TestSDNGRPCService_generateFlowID_NilConfig(t *testing.T) {
	service, _ := newTestSDNService()

	result := service.generateFlowID(nil)
	if result != "" {
		t.Errorf("Expected empty string for nil config, got '%s'", result)
	}
}

func TestSDNGRPCService_generateFlowID_ValidConfig(t *testing.T) {
	service, _ := newTestSDNService()

	config := &platformv1.FlowConfig{
		BridgeId: "br0",
		Table:    platformv1.FlowTable_FLOW_TABLE_1,
		Priority: 100,
	}

	result := service.generateFlowID(config)
	if result == "" {
		t.Error("Expected non-empty flow ID")
	}
}

func TestSDNGRPCService_generateSubscriptionID(t *testing.T) {
	service, _ := newTestSDNService()

	id1 := service.generateSubscriptionID()
	if id1 == "" {
		t.Error("Expected non-empty subscription ID")
	}

	// Subscription IDs should be unique based on timestamp
	time.Sleep(time.Millisecond)
	id2 := service.generateSubscriptionID()
	if id1 == id2 {
		t.Error("Expected different subscription IDs")
	}
}

func TestSdnItoa_Zero(t *testing.T) {
	result := sdnItoa(0)
	if result != "0" {
		t.Errorf("Expected '0', got '%s'", result)
	}
}

func TestSdnItoa_Positive(t *testing.T) {
	result := sdnItoa(12345)
	if result != "12345" {
		t.Errorf("Expected '12345', got '%s'", result)
	}
}

func TestSdnItoa_Negative(t *testing.T) {
	result := sdnItoa(-9876)
	if result != "-9876" {
		t.Errorf("Expected '-9876', got '%s'", result)
	}
}

func TestSdnItoa64_Zero(t *testing.T) {
	result := sdnItoa64(0)
	if result != "0" {
		t.Errorf("Expected '0', got '%s'", result)
	}
}

func TestSdnItoa64_Positive(t *testing.T) {
	result := sdnItoa64(9876543210)
	if result != "9876543210" {
		t.Errorf("Expected '9876543210', got '%s'", result)
	}
}

func TestSdnItoa64_Negative(t *testing.T) {
	result := sdnItoa64(-1234567890)
	if result != "-1234567890" {
		t.Errorf("Expected '-1234567890', got '%s'", result)
	}
}

// Test buildMatchString with all match types

func TestSDNGRPCService_buildMatchString_AllFields(t *testing.T) {
	service, _ := newTestSDNService()

	match := &platformv1.FlowMatch{
		InPort:  "1",
		VlanId:  100,
		EthSrc:  "aa:bb:cc:dd:ee:ff",
		EthDst:  "11:22:33:44:55:66",
		EthType: 0x0800,
		IpSrc:   "192.168.1.0/24",
		IpDst:   "10.0.0.0/8",
		IpProto: 6,
		TcpSrc:  1234,
		TcpDst:  80,
		UdpSrc:  5678,
		UdpDst:  53,
	}

	result := service.buildMatchString(match)

	// Verify result is not empty for populated match
	if result == "" {
		t.Error("Expected non-empty match string")
	}
}

// Test buildActionsString with valid action types

func TestSDNGRPCService_buildActionsString_SetField(t *testing.T) {
	service, _ := newTestSDNService()

	action := &platformv1.FlowAction{
		Type:  platformv1.FlowActionType_FLOW_ACTION_SET_FIELD,
		Field: "eth_src",
		Value: "aa:bb:cc:dd:ee:ff",
	}

	result := service.buildActionsString([]*platformv1.FlowAction{action})
	if result != "set_field:aa:bb:cc:dd:ee:ff->eth_src" {
		t.Errorf("buildActionsString() = '%s', expected 'set_field:aa:bb:cc:dd:ee:ff->eth_src'", result)
	}
}

// Test StreamFlowLogs

type mockFlowLogStream struct {
	ctx     context.Context
	sent    []*platformv1.FlowLogEntry
	sendErr error
}

func (m *mockFlowLogStream) Send(entry *platformv1.FlowLogEntry) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sent = append(m.sent, entry)
	return nil
}

func (m *mockFlowLogStream) Context() context.Context {
	return m.ctx
}

func (m *mockFlowLogStream) SetHeader(metadata.MD) error  { return nil }
func (m *mockFlowLogStream) SendHeader(metadata.MD) error { return nil }
func (m *mockFlowLogStream) SetTrailer(metadata.MD)       {}
func (m *mockFlowLogStream) SendMsg(interface{}) error    { return nil }
func (m *mockFlowLogStream) RecvMsg(interface{}) error    { return nil }

func TestSDNGRPCService_StreamFlowLogs_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewSDNGRPCService(logger, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := &mockFlowLogStream{ctx: ctx}
	req := &platformv1.StreamFlowLogsRequest{BridgeId: "br-test"}

	err := service.StreamFlowLogs(req, stream)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestSDNGRPCService_StreamFlowLogs_MissingBridgeID(t *testing.T) {
	service, _ := newTestSDNService()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := &mockFlowLogStream{ctx: ctx}
	req := &platformv1.StreamFlowLogsRequest{}

	err := service.StreamFlowLogs(req, stream)
	if err == nil {
		t.Fatal("Expected error for missing bridge ID")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestSDNGRPCService_StreamFlowLogs_ContextCancelled(t *testing.T) {
	service, _ := newTestSDNService()

	ctx, cancel := context.WithCancel(context.Background())
	stream := &mockFlowLogStream{ctx: ctx}
	req := &platformv1.StreamFlowLogsRequest{BridgeId: "br-test"}

	// Cancel context immediately
	cancel()

	err := service.StreamFlowLogs(req, stream)
	if err == nil {
		t.Fatal("Expected error when context cancelled")
	}

	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got %v", err)
	}
}
