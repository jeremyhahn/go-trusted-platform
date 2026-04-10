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
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// =============================================================================
// SDNListBridges Tests - Comprehensive Coverage
// =============================================================================

func TestMCPServiceProvider_SDNListBridges_NilService_TableDriven(t *testing.T) {
	testCases := []struct {
		name           string
		sdnService     *SDNService
		expectedErrSvc string
	}{
		{
			name:           "nil_sdn_service_returns_error",
			sdnService:     nil,
			expectedErrSvc: "sdn",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				SDNService: tc.sdnService,
				Logger:     slog.Default(),
			})

			_, err := provider.SDNListBridges(ctx)
			if err == nil {
				t.Fatal("expected error for nil SDN service")
			}

			svcErr, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
			if svcErr.Service != tc.expectedErrSvc {
				t.Errorf("expected service=%q, got %q", tc.expectedErrSvc, svcErr.Service)
			}
		})
	}
}

// Note: Tests that require actual OVS client interaction are skipped
// because they require a real OVS installation. These are covered by
// integration tests in test/integration/sdn/

// =============================================================================
// SDNGetPortState Tests - Comprehensive Coverage
// =============================================================================

func TestMCPServiceProvider_SDNGetPortState_NilService_TableDriven(t *testing.T) {
	testCases := []struct {
		name           string
		bridgeName     string
		portName       string
		expectedErrSvc string
	}{
		{
			name:           "nil_service_with_valid_params",
			bridgeName:     "br0",
			portName:       "port1",
			expectedErrSvc: "sdn",
		},
		{
			name:           "nil_service_with_different_params",
			bridgeName:     "test-bridge",
			portName:       "eth0",
			expectedErrSvc: "sdn",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				SDNService: nil,
				Logger:     slog.Default(),
			})

			_, err := provider.SDNGetPortState(ctx, tc.bridgeName, tc.portName)
			if err == nil {
				t.Fatal("expected error for nil SDN service")
			}

			svcErr, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
			if svcErr.Service != tc.expectedErrSvc {
				t.Errorf("expected service=%q, got %q", tc.expectedErrSvc, svcErr.Service)
			}
		})
	}
}

// Note: SDNGetPortState tests that require OVS client are in integration tests

// =============================================================================
// VTPMDelete Tests - Comprehensive Coverage
// =============================================================================

// bridgesMockVTPMService implements vtpm.VTPMService for testing VTPMDelete
type bridgesMockVTPMService struct {
	bundles     map[string]*vtpm.Bundle
	shouldError bool
}

func newBridgesMockVTPMService() *bridgesMockVTPMService {
	return &bridgesMockVTPMService{
		bundles: make(map[string]*vtpm.Bundle),
	}
}

func (m *bridgesMockVTPMService) CreateBundle(ctx context.Context, opts *vtpm.CreateBundleOptions) (*vtpm.Bundle, error) {
	bundle := &vtpm.Bundle{
		ID:        opts.Hostname,
		Mode:      opts.Mode,
		CreatedAt: time.Now(),
	}
	m.bundles[bundle.ID] = bundle
	return bundle, nil
}

func (m *bridgesMockVTPMService) GetBundle(ctx context.Context, id string) (*vtpm.Bundle, error) {
	if m.shouldError {
		return nil, vtpm.ErrBundleNotFound{ID: id}
	}
	if bundle, ok := m.bundles[id]; ok {
		return bundle, nil
	}
	return nil, vtpm.ErrBundleNotFound{ID: id}
}

func (m *bridgesMockVTPMService) DeleteBundle(ctx context.Context, id string) error {
	if m.shouldError {
		return vtpm.ErrBundleNotFound{ID: id}
	}
	if _, ok := m.bundles[id]; !ok {
		return vtpm.ErrBundleNotFound{ID: id}
	}
	delete(m.bundles, id)
	return nil
}

func (m *bridgesMockVTPMService) ListBundles(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error) {
	bundles := make([]*vtpm.Bundle, 0, len(m.bundles))
	for _, b := range m.bundles {
		bundles = append(bundles, b)
	}
	return bundles, nil
}

func (m *bridgesMockVTPMService) CreateTemplate(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
	return nil, nil
}

func (m *bridgesMockVTPMService) CloneTemplate(ctx context.Context, opts *vtpm.CloneOptions) (*vtpm.Bundle, error) {
	return nil, nil
}

func (m *bridgesMockVTPMService) GetTemplate(ctx context.Context, id string) (*vtpm.Template, error) {
	return nil, vtpm.ErrTemplateNotFound{ID: id}
}

func (m *bridgesMockVTPMService) DeleteTemplate(ctx context.Context, id string) error {
	return nil
}

func (m *bridgesMockVTPMService) ListTemplates(ctx context.Context) ([]*vtpm.Template, error) {
	return nil, nil
}

func (m *bridgesMockVTPMService) ExportBundle(ctx context.Context, id string, w io.Writer) error {
	return nil
}

func (m *bridgesMockVTPMService) ImportBundle(ctx context.Context, r io.Reader) (*vtpm.Bundle, error) {
	return nil, nil
}

func (m *bridgesMockVTPMService) ValidateBundle(ctx context.Context, id string) error {
	return nil
}

func (m *bridgesMockVTPMService) GetBundlePath(id string) string {
	return "/var/lib/vtpm/bundles/" + id
}

func (m *bridgesMockVTPMService) GetTPMSocketPath(id string) string {
	return "/var/lib/vtpm/bundles/" + id + "/swtpm-sock"
}

func (m *bridgesMockVTPMService) GetNVRAMPath(id string) string {
	return "/var/lib/vtpm/bundles/" + id + "/OVMF_VARS.fd"
}

func (m *bridgesMockVTPMService) Start(ctx context.Context, bundleID string) error {
	return nil
}

func (m *bridgesMockVTPMService) Stop(ctx context.Context, bundleID string) error {
	return nil
}

func (m *bridgesMockVTPMService) IsRunning(bundleID string) bool {
	return false
}

func (m *bridgesMockVTPMService) Quote(ctx context.Context, bundleID string, nonce []byte, pcrs []int) (*vtpm.QuoteResult, error) {
	return nil, nil
}

func (m *bridgesMockVTPMService) Seal(ctx context.Context, bundleID string, data []byte, opts *vtpm.SealOptions) ([]byte, error) {
	return nil, nil
}

func (m *bridgesMockVTPMService) Unseal(ctx context.Context, bundleID string, sealedData []byte, authValue string) ([]byte, error) {
	return nil, nil
}

func (m *bridgesMockVTPMService) ExtendPCR(ctx context.Context, bundleID string, pcrIndex int, data []byte) error {
	return nil
}

func (m *bridgesMockVTPMService) ReadPCR(ctx context.Context, bundleID string, pcrIndex int) ([]byte, error) {
	return nil, nil
}

func (m *bridgesMockVTPMService) Close() error {
	return nil
}

func TestMCPServiceProvider_VTPMDelete_NilService_TableDriven(t *testing.T) {
	testCases := []struct {
		name           string
		bundleName     string
		expectedErrSvc string
	}{
		{
			name:           "nil_service_returns_error",
			bundleName:     "test-bundle",
			expectedErrSvc: "vtpm",
		},
		{
			name:           "nil_service_with_empty_name",
			bundleName:     "",
			expectedErrSvc: "vtpm",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				VTPMService: nil,
				Logger:      slog.Default(),
			})

			err := provider.VTPMDelete(ctx, tc.bundleName)
			if err == nil {
				t.Fatal("expected error for nil VTPM service")
			}

			svcErr, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
			if svcErr.Service != tc.expectedErrSvc {
				t.Errorf("expected service=%q, got %q", tc.expectedErrSvc, svcErr.Service)
			}
		})
	}
}

func TestMCPServiceProvider_VTPMDelete_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newBridgesMockVTPMService()

	// Pre-create a bundle
	mockSvc.bundles["test-bundle"] = &vtpm.Bundle{
		ID:        "test-bundle",
		CreatedAt: time.Now(),
	}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
		Logger:      slog.Default(),
	})

	err := provider.VTPMDelete(ctx, "test-bundle")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify bundle was deleted
	if _, exists := mockSvc.bundles["test-bundle"]; exists {
		t.Error("bundle should have been deleted")
	}
}

func TestMCPServiceProvider_VTPMDelete_BundleNotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newBridgesMockVTPMService()

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
		Logger:      slog.Default(),
	})

	err := provider.VTPMDelete(ctx, "nonexistent-bundle")
	if err == nil {
		t.Fatal("expected error for non-existent bundle")
	}

	_, ok := err.(vtpm.ErrBundleNotFound)
	if !ok {
		t.Errorf("expected vtpm.ErrBundleNotFound, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_VTPMDelete_MultipleBundles(t *testing.T) {
	testCases := []struct {
		name      string
		bundleID  string
		exists    bool
		expectErr bool
	}{
		{
			name:      "delete_existing_bundle_1",
			bundleID:  "bundle-1",
			exists:    true,
			expectErr: false,
		},
		{
			name:      "delete_existing_bundle_2",
			bundleID:  "bundle-2",
			exists:    true,
			expectErr: false,
		},
		{
			name:      "delete_nonexistent_bundle",
			bundleID:  "bundle-3",
			exists:    false,
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			mockSvc := newBridgesMockVTPMService()

			// Pre-create bundles that should exist
			if tc.exists {
				mockSvc.bundles[tc.bundleID] = &vtpm.Bundle{
					ID:        tc.bundleID,
					CreatedAt: time.Now(),
				}
			}

			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				VTPMService: mockSvc,
				Logger:      slog.Default(),
			})

			err := provider.VTPMDelete(ctx, tc.bundleID)
			if tc.expectErr {
				if err == nil {
					t.Fatal("expected error")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				// Verify bundle was deleted
				if _, exists := mockSvc.bundles[tc.bundleID]; exists {
					t.Error("bundle should have been deleted")
				}
			}
		})
	}
}

func TestMCPServiceProvider_VTPMDelete_ErrorMessage(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: nil,
		Logger:      slog.Default(),
	})

	err := provider.VTPMDelete(ctx, "test-bundle")
	if err == nil {
		t.Fatal("expected error")
	}

	errMsg := err.Error()
	if errMsg == "" {
		t.Error("expected non-empty error message")
	}
}
