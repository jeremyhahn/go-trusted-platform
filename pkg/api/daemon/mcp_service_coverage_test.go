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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// =============================================================================
// Mock Policy Engine for coverage tests
// =============================================================================

// =============================================================================
// VTPMCreate Coverage Tests
// =============================================================================

func TestMCPServiceProvider_VTPMCreate_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockVTPMService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
	})

	result, err := provider.VTPMCreate(ctx, "test-vtpm", "rsa", false, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestMCPServiceProvider_VTPMCreate_RejectsUndocumentedAlgorithm(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: newMCPMockVTPMService(),
	})

	for _, algorithm := range []string{"RSA2048", "ECDSA"} {
		_, err := provider.VTPMCreate(ctx, "test-vtpm", algorithm, false, nil)
		var invalid vtpm.ErrInvalidEKAlgorithm
		if !errors.As(err, &invalid) {
			t.Errorf("VTPMCreate(%q): err = %v, want vtpm.ErrInvalidEKAlgorithm", algorithm, err)
		}
		_, err = provider.VTPMCreateTemplate(ctx, "tpl", "desc", algorithm, false)
		if !errors.As(err, &invalid) {
			t.Errorf("VTPMCreateTemplate(%q): err = %v, want vtpm.ErrInvalidEKAlgorithm", algorithm, err)
		}
	}
}

func TestMCPServiceProvider_VTPMCreate_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.VTPMCreate(ctx, "test", "RSA", false, nil)
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

// =============================================================================
// VTPMList Coverage Tests
// =============================================================================

func TestMCPServiceProvider_VTPMList_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockVTPMService()

	// Create some bundles first using the mock service
	_, _ = mockSvc.CreateBundle(ctx, &vtpm.CreateBundleOptions{Hostname: "bundle1"})
	_, _ = mockSvc.CreateBundle(ctx, &vtpm.CreateBundleOptions{Hostname: "bundle2"})

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
	})

	result, err := provider.VTPMList(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 bundles, got %d", len(result))
	}
}

func TestMCPServiceProvider_VTPMList_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.VTPMList(ctx, nil)
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_VTPMList_EmptyList(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockVTPMService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
	})

	result, err := provider.VTPMList(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 bundles, got %d", len(result))
	}
}

// =============================================================================
// DNSAddRecord Coverage Tests
// =============================================================================

func TestMCPServiceProvider_DNSAddRecord_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	err := provider.DNSAddRecord(ctx, "test.example.com", "A", "192.168.1.1", 300)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_DNSAddRecord_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	err := provider.DNSAddRecord(ctx, "test.example.com", "A", "192.168.1.1", 300)
	if err == nil {
		t.Error("expected error for nil service")
	}
	// DNS service uses ErrDNSServiceNotAvailable instead of ErrServiceNotAvailable
	if _, ok := err.(ErrDNSServiceNotAvailable); !ok {
		t.Errorf("expected ErrDNSServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_DNSAddRecord_ValidationErrors(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	tests := []struct {
		name       string
		recordName string
		recordType string
		value      string
		ttl        int
		wantErr    bool
	}{
		{
			name:       "empty name",
			recordName: "",
			recordType: "A",
			value:      "192.168.1.1",
			ttl:        300,
			wantErr:    true,
		},
		{
			name:       "empty type",
			recordName: "test.example.com",
			recordType: "",
			value:      "192.168.1.1",
			ttl:        300,
			wantErr:    true,
		},
		{
			name:       "empty value",
			recordName: "test.example.com",
			recordType: "A",
			value:      "",
			ttl:        300,
			wantErr:    true,
		},
		{
			name:       "negative ttl",
			recordName: "test.example.com",
			recordType: "A",
			value:      "192.168.1.1",
			ttl:        -1,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := provider.DNSAddRecord(ctx, tt.recordName, tt.recordType, tt.value, tt.ttl)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if tt.wantErr && status.Code(err) != codes.InvalidArgument {
				t.Errorf("status.Code(%v) = %v, want InvalidArgument", err, status.Code(err))
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// =============================================================================
// DNSDeleteRecord Coverage Tests
// =============================================================================

func TestMCPServiceProvider_DNSDeleteRecord_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	// Add a record first
	_ = mockSvc.AddRecord(ctx, "test.example.com", "A", "192.168.1.1", 300)

	err := provider.DNSDeleteRecord(ctx, "test.example.com", "A")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_DNSDeleteRecord_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	err := provider.DNSDeleteRecord(ctx, "test.example.com", "A")
	if err == nil {
		t.Error("expected error for nil service")
	}
	// DNS service uses ErrDNSServiceNotAvailable instead of ErrServiceNotAvailable
	if _, ok := err.(ErrDNSServiceNotAvailable); !ok {
		t.Errorf("expected ErrDNSServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_DNSDeleteRecord_ValidationErrors(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	tests := []struct {
		name       string
		recordName string
		recordType string
		wantErr    bool
	}{
		{
			name:       "empty name",
			recordName: "",
			recordType: "A",
			wantErr:    true,
		},
		{
			name:       "empty type",
			recordName: "test.example.com",
			recordType: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := provider.DNSDeleteRecord(ctx, tt.recordName, tt.recordType)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// =============================================================================
// DeviceRegister Coverage Tests
// =============================================================================

func TestMCPServiceProvider_DeviceRegister_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.DeviceRegister(ctx, &mcp.DeviceRegisterRequest{Model: "device1", Serial: "server"})
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_DeviceRegister_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDeviceService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: mockSvc,
	})

	result, err := provider.DeviceRegister(ctx, &mcp.DeviceRegisterRequest{Model: "device1", Serial: "server"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

// TestMCPServiceProvider_DeviceRegister_AssignsAnID is the #525
// regression on the MCP transport. The provider built a Device with no
// ID and called Save, which requires one, so the MCP create verb was
// refused exactly as gRPC, Unix and QUIC were. The assertion is on the
// assigned ID, not merely a nil-free result, because a result that
// carries a zero ID cannot be read back.
func TestMCPServiceProvider_DeviceRegister_AssignsAnID(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDeviceService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: mockSvc,
	})

	result, err := provider.DeviceRegister(ctx, &mcp.DeviceRegisterRequest{Model: "model-525", Serial: "SN-525"})
	if err != nil {
		t.Fatalf("DeviceRegister returned an error: %v", err)
	}
	dev, ok := result.(*deviceentities.Device)
	if !ok {
		t.Fatalf("expected a *entities.Device, got %T", result)
	}
	if dev.ID == 0 {
		t.Fatal("DeviceRegister returned a device with no ID; it cannot be read back")
	}

	// Readable afterwards under the assigned ID.
	got, err := provider.DeviceGet(ctx, itoa(dev.ID))
	if err != nil {
		t.Fatalf("DeviceGet on the created device failed: %v", err)
	}
	if got == nil {
		t.Fatal("DeviceGet returned no device")
	}
}

// TestMCPServiceProvider_DeviceRegister_SaveErrorSurfaces is the failure
// case: a storage refusal must reach the caller rather than being
// reported as a successful registration.
func TestMCPServiceProvider_DeviceRegister_SaveErrorSurfaces(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: &failingDeviceCreateService{mcpMockDeviceService: newMCPMockDeviceService()},
	})

	if _, err := provider.DeviceRegister(ctx, &mcp.DeviceRegisterRequest{Model: "model-525", Serial: "SN-525"}); err == nil {
		t.Fatal("expected the storage failure to surface from DeviceRegister")
	}
}

// TestMCPServiceProvider_DeviceRegister_MapsEveryField is the #533
// regression: device_register once stored its name argument as the model
// and its device_type argument as the serial, so a device registered with
// a serial could not be found by it. Every request field must land on the
// stored device under its own name.
func TestMCPServiceProvider_DeviceRegister_MapsEveryField(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: newMCPMockDeviceService(),
	})

	req := &mcp.DeviceRegisterRequest{
		Serial:     "SN-533",
		Model:      "model-533",
		EKCert:     "ek-pem",
		AttestPub:  "ak-pub",
		AttestCert: "ak-cert",
		SigningPub: "signing-pub",
		HashAlgoID: 11,
	}
	result, err := provider.DeviceRegister(ctx, req)
	if err != nil {
		t.Fatalf("DeviceRegister: %v", err)
	}

	found, err := provider.DeviceFindBySerial(ctx, "SN-533")
	if err != nil {
		t.Fatalf("DeviceFindBySerial after register: %v", err)
	}
	dev, ok := found.(*deviceentities.Device)
	if !ok {
		t.Fatalf("expected *deviceentities.Device, got %T", found)
	}
	if dev != result {
		t.Error("find_by_serial returned a different device than the one registered")
	}

	if dev.Serial != req.Serial || dev.Model != req.Model || dev.EKCert != req.EKCert ||
		dev.AttestPub != req.AttestPub || dev.AttestCert != req.AttestCert ||
		dev.SigningPub != req.SigningPub || dev.HashAlgoId != req.HashAlgoID {
		t.Errorf("stored device = %+v, want the fields of request %+v", *dev, *req)
	}
}

func TestMCPServiceProvider_DeviceRegister_SerialRequired(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: newMCPMockDeviceService(),
	})

	for name, req := range map[string]*mcp.DeviceRegisterRequest{
		"nil request":  nil,
		"empty serial": {Model: "model-only"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := provider.DeviceRegister(ctx, req)
			var missing ErrMissingRequiredField
			if !errors.As(err, &missing) || missing.Field != "serial" {
				t.Fatalf("error = %v, want ErrMissingRequiredField{serial}", err)
			}
		})
	}
}

func TestMCPServiceProvider_DeviceFindBySerial_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("no device service", func(t *testing.T) {
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})
		_, err := provider.DeviceFindBySerial(ctx, "SN-533")
		var notAvailable ErrServiceNotAvailable
		if !errors.As(err, &notAvailable) {
			t.Fatalf("error = %v, want ErrServiceNotAvailable", err)
		}
	})

	t.Run("unknown serial", func(t *testing.T) {
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
			DeviceService: newMCPMockDeviceService(),
		})
		_, err := provider.DeviceFindBySerial(ctx, "SN-missing")
		var notFound ErrDeviceNotFound
		if !errors.As(err, &notFound) {
			t.Fatalf("error = %v, want ErrDeviceNotFound", err)
		}
	})
}

// failingDeviceCreateService fails only the create verb so the error
// path is exercised without disturbing the other operations.
type failingDeviceCreateService struct {
	*mcpMockDeviceService
}

func (f *failingDeviceCreateService) Create(context.Context, *deviceentities.Device) error {
	return errors.New("storage write failed")
}

// =============================================================================
// DeviceGet Coverage Tests
// =============================================================================

func TestMCPServiceProvider_DeviceGet_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDeviceService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: mockSvc,
	})

	// Register a device first
	if _, err := provider.DeviceRegister(ctx, &mcp.DeviceRegisterRequest{Model: "device1", Serial: "server"}); err != nil {
		t.Fatalf("register device: %v", err)
	}

	result, err := provider.DeviceGet(ctx, "1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestMCPServiceProvider_DeviceGet_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.DeviceGet(ctx, "1")
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_DeviceGet_InvalidID(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDeviceService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: mockSvc,
	})

	_, err := provider.DeviceGet(ctx, "invalid")
	if err == nil {
		t.Error("expected error for invalid ID")
	}
}

func TestMCPServiceProvider_DeviceGet_NotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDeviceService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: mockSvc,
	})

	_, err := provider.DeviceGet(ctx, "999")
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

// =============================================================================
// SDNGetPolicy Coverage Tests
// =============================================================================

// =============================================================================
// SDNListPolicies Coverage Tests
// =============================================================================

// =============================================================================
// SDNSetPortState Coverage Tests
// =============================================================================

// =============================================================================
// SDNApplyPolicy Coverage Tests
// =============================================================================

// =============================================================================
// Health, Liveness, Readiness Coverage Tests
// =============================================================================

func TestMCPServiceProvider_Health_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.Health(ctx)
	if err == nil {
		t.Error("expected error for nil health service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_Liveness_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.Liveness(ctx)
	if err == nil {
		t.Error("expected error for nil health service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_Readiness_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.Readiness(ctx)
	if err == nil {
		t.Error("expected error for nil health service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

// =============================================================================
// SDNListBridges Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNListBridges_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.SDNListBridges(ctx)
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

// =============================================================================
// SDNListFlows Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNListFlows_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.SDNListFlows(ctx, "br0")
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

// =============================================================================
// SDNListVLANs Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNListVLANs_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.SDNListVLANs(ctx, "br0")
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

// =============================================================================
// SDNGetPortState Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNGetPortState_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.SDNGetPortState(ctx, "br0", "port1")
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

// =============================================================================
// SDNGetPortStats Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNGetPortStats_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.SDNGetPortStats(ctx, "br0", "port1")
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

// =============================================================================
// SDNGetFlowStats Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNGetFlowStats_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.SDNGetFlowStats(ctx, "br0", "0x1")
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}
