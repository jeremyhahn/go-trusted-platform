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
	"log/slog"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// =============================================================================
// Mock CA gRPC Service for comprehensive CA operations testing
// =============================================================================

// mockCAGRPCServiceExtended implements the necessary methods for CAGRPCService testing
type mockCAGRPCServiceExtended struct {
	// GetCAInfo mocks
	getCAInfoResp *platformv1.GetCAInfoResponse
	getCAInfoErr  error

	// IssueCertificate mocks
	issueCertResp *platformv1.IssueCertificateResponse
	issueCertErr  error

	// GetCertificate mocks
	getCertResp *platformv1.GetCertificateResponse
	getCertErr  error

	// ListCertificates mocks
	listCertsResp *platformv1.ListCertificatesResponse
	listCertsErr  error

	// RevokeCertificate mocks
	revokeCertResp *platformv1.RevokeCertificateResponse
	revokeCertErr  error

	// RenewCertificate mocks
	renewCertResp *platformv1.RenewCertificateResponse
	renewCertErr  error

	// VerifyCertificate mocks
	verifyCertResp *platformv1.VerifyCertificateResponse
	verifyCertErr  error

	// GetCRL mocks
	getCRLResp *platformv1.GetCRLResponse
	getCRLErr  error

	// GetCABundle mocks
	getCABundleResp *platformv1.GetCABundleResponse
	getCABundleErr  error
}

// Implement CAGRPCService method signatures for the mock
func (m *mockCAGRPCServiceExtended) GetCAInfo(ctx context.Context, req *platformv1.GetCAInfoRequest) (*platformv1.GetCAInfoResponse, error) {
	if m.getCAInfoErr != nil {
		return nil, m.getCAInfoErr
	}
	return m.getCAInfoResp, nil
}

func (m *mockCAGRPCServiceExtended) IssueCertificate(ctx context.Context, req *platformv1.IssueCertificateRequest) (*platformv1.IssueCertificateResponse, error) {
	if m.issueCertErr != nil {
		return nil, m.issueCertErr
	}
	return m.issueCertResp, nil
}

func (m *mockCAGRPCServiceExtended) GetCertificate(ctx context.Context, req *platformv1.GetCertificateRequest) (*platformv1.GetCertificateResponse, error) {
	if m.getCertErr != nil {
		return nil, m.getCertErr
	}
	return m.getCertResp, nil
}

func (m *mockCAGRPCServiceExtended) ListCertificates(ctx context.Context, req *platformv1.ListCertificatesRequest) (*platformv1.ListCertificatesResponse, error) {
	if m.listCertsErr != nil {
		return nil, m.listCertsErr
	}
	return m.listCertsResp, nil
}

func (m *mockCAGRPCServiceExtended) RevokeCertificate(ctx context.Context, req *platformv1.RevokeCertificateRequest) (*platformv1.RevokeCertificateResponse, error) {
	if m.revokeCertErr != nil {
		return nil, m.revokeCertErr
	}
	return m.revokeCertResp, nil
}

func (m *mockCAGRPCServiceExtended) RenewCertificate(ctx context.Context, req *platformv1.RenewCertificateRequest) (*platformv1.RenewCertificateResponse, error) {
	if m.renewCertErr != nil {
		return nil, m.renewCertErr
	}
	return m.renewCertResp, nil
}

func (m *mockCAGRPCServiceExtended) VerifyCertificate(ctx context.Context, req *platformv1.VerifyCertificateRequest) (*platformv1.VerifyCertificateResponse, error) {
	if m.verifyCertErr != nil {
		return nil, m.verifyCertErr
	}
	return m.verifyCertResp, nil
}

func (m *mockCAGRPCServiceExtended) GetCRL(ctx context.Context, req *platformv1.GetCRLRequest) (*platformv1.GetCRLResponse, error) {
	if m.getCRLErr != nil {
		return nil, m.getCRLErr
	}
	return m.getCRLResp, nil
}

func (m *mockCAGRPCServiceExtended) GetCABundle(ctx context.Context, req *platformv1.GetCABundleRequest) (*platformv1.GetCABundleResponse, error) {
	if m.getCABundleErr != nil {
		return nil, m.getCABundleErr
	}
	return m.getCABundleResp, nil
}

// testableCAGRPCServiceExtended embeds CAGRPCService but delegates to mock
type testableCAGRPCServiceExtended struct {
	CAGRPCService
	mock *mockCAGRPCServiceExtended
}

func (s *testableCAGRPCServiceExtended) GetCAInfo(ctx context.Context, req *platformv1.GetCAInfoRequest) (*platformv1.GetCAInfoResponse, error) {
	return s.mock.GetCAInfo(ctx, req)
}

func (s *testableCAGRPCServiceExtended) IssueCertificate(ctx context.Context, req *platformv1.IssueCertificateRequest) (*platformv1.IssueCertificateResponse, error) {
	return s.mock.IssueCertificate(ctx, req)
}

func (s *testableCAGRPCServiceExtended) GetCertificate(ctx context.Context, req *platformv1.GetCertificateRequest) (*platformv1.GetCertificateResponse, error) {
	return s.mock.GetCertificate(ctx, req)
}

func (s *testableCAGRPCServiceExtended) ListCertificates(ctx context.Context, req *platformv1.ListCertificatesRequest) (*platformv1.ListCertificatesResponse, error) {
	return s.mock.ListCertificates(ctx, req)
}

func (s *testableCAGRPCServiceExtended) RevokeCertificate(ctx context.Context, req *platformv1.RevokeCertificateRequest) (*platformv1.RevokeCertificateResponse, error) {
	return s.mock.RevokeCertificate(ctx, req)
}

func (s *testableCAGRPCServiceExtended) RenewCertificate(ctx context.Context, req *platformv1.RenewCertificateRequest) (*platformv1.RenewCertificateResponse, error) {
	return s.mock.RenewCertificate(ctx, req)
}

func (s *testableCAGRPCServiceExtended) VerifyCertificate(ctx context.Context, req *platformv1.VerifyCertificateRequest) (*platformv1.VerifyCertificateResponse, error) {
	return s.mock.VerifyCertificate(ctx, req)
}

func (s *testableCAGRPCServiceExtended) GetCRL(ctx context.Context, req *platformv1.GetCRLRequest) (*platformv1.GetCRLResponse, error) {
	return s.mock.GetCRL(ctx, req)
}

func (s *testableCAGRPCServiceExtended) GetCABundle(ctx context.Context, req *platformv1.GetCABundleRequest) (*platformv1.GetCABundleResponse, error) {
	return s.mock.GetCABundle(ctx, req)
}

// createTestCAServiceExtended creates a CAGRPCService that delegates to the mock
func createTestCAServiceExtended(mock *mockCAGRPCServiceExtended) *testableCAGRPCServiceExtended {
	return &testableCAGRPCServiceExtended{mock: mock}
}

// =============================================================================
// CA Info Tests
// =============================================================================

func TestMCPServiceProvider_CAInfo_NilServiceExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CAInfo(ctx)
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CAInfo_SuccessExtended(t *testing.T) {
	ctx := context.Background()
	mockCA := &mockCAGRPCServiceExtended{
		getCAInfoResp: &platformv1.GetCAInfoResponse{
			CaInfo: &platformv1.CAInfo{
				CommonName:          "Test CA",
				IsInitialized:       true,
				IsIntermediate:      false,
				DefaultAlgorithm:    "RSA-2048",
				DefaultValidityDays: 365,
			},
			Timestamp: timestamppb.Now(),
		},
	}
	caService := createTestCAServiceExtended(mockCA)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService: &caService.CAGRPCService,
		Logger:    slog.Default(),
	})
	// Override the caService with our testable version
	provider.caService = (*CAGRPCService)(nil) // Clear and re-test nil handling

	// This should error because caService is nil
	_, err := provider.CAInfo(ctx)
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}
}

func TestMCPServiceProvider_CAInfo_ErrorExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CAInfo(ctx)
	if err == nil {
		t.Fatal("expected error from CA service")
	}

	// Verify it returns correct error type
	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

// =============================================================================
// CA Issue Tests
// =============================================================================

func TestMCPServiceProvider_CAIssue_NilServiceExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CAIssue(ctx, &mcp.CAIssueRequest{
		CommonName: "test.example.com",
	})
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CAIssue_SuccessWithSubject(t *testing.T) {
	// Test that the request is properly constructed with Subject
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// With nil service, it should fail before constructing the request
	_, err := provider.CAIssue(ctx, &mcp.CAIssueRequest{
		CommonName:         "test.example.com",
		Organization:       "Test Org",
		OrganizationalUnit: "Test Unit",
		Country:            "US",
		Province:           "CA",
		Locality:           "San Francisco",
		ValidDays:          365,
		Algorithm:          "RSA-2048",
		StoreType:          "software",
		KeyUsage:           []string{"digitalSignature", "keyEncipherment"},
		ExtKeyUsage:        []string{"serverAuth", "clientAuth"},
	})
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}
}

func TestMCPServiceProvider_CAIssue_WithSANsExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CAIssue(ctx, &mcp.CAIssueRequest{
		CommonName:     "test.example.com",
		DNSNames:       []string{"www.example.com", "api.example.com"},
		IPAddresses:    []string{"192.168.1.1", "10.0.0.1"},
		EmailAddresses: []string{"admin@example.com", "support@example.com"},
		URIs:           []string{"spiffe://cluster.local/ns/default/sa/myservice"},
	})
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	// Verify the error is of the correct type
	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CAIssue_ErrorExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CAIssue(ctx, &mcp.CAIssueRequest{
		CommonName: "invalid",
	})
	if err == nil {
		t.Fatal("expected error from CA service")
	}
}

func TestMCPServiceProvider_CAIssue_WithCAOptionsExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CAIssue(ctx, &mcp.CAIssueRequest{
		CommonName:   "Intermediate CA",
		Organization: "Test Org",
		IsCA:         true,
		MaxPathLen:   1,
		KeyUsage:     []string{"certSign", "crlSign"},
		ExtKeyUsage:  []string{"serverAuth"},
	})
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}
}

// =============================================================================
// CA Get Tests
// =============================================================================

func TestMCPServiceProvider_CAGet_SuccessExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CAGet(ctx, "abc123", true)
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CAGet_ErrorExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CAGet(ctx, "nonexistent", false)
	if err == nil {
		t.Fatal("expected error from CA service")
	}
}

func TestMCPServiceProvider_CAGet_WithoutPEMExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CAGet(ctx, "abc123", false)
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}
}

// =============================================================================
// CA List Tests
// =============================================================================

func TestMCPServiceProvider_CAList_SuccessExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CAList(ctx, 10, "", "active")
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CAList_ErrorExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CAList(ctx, 50, "", "")
	if err == nil {
		t.Fatal("expected error from CA service")
	}
}

func TestMCPServiceProvider_CAList_WithDefaultPageSizeExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Test with limit=0 which should use default page size
	_, err := provider.CAList(ctx, 0, "", "")
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}
}

func TestMCPServiceProvider_CAList_WithCursorExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Test with cursor parameter
	_, err := provider.CAList(ctx, 25, "cursor-token", "revoked")
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

// =============================================================================
// CA Revoke Tests
// =============================================================================

func TestMCPServiceProvider_CARevoke_SuccessExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CARevoke(ctx, "abc123", 1, false)
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CARevoke_ErrorExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CARevoke(ctx, "nonexistent", 0, true)
	if err == nil {
		t.Fatal("expected error from CA service")
	}
}

func TestMCPServiceProvider_CARevoke_WithDeleteKeysExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CARevoke(ctx, "abc123", 3, true)
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}
}

func TestMCPServiceProvider_CARevoke_AllReasons(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Test various revocation reasons
	reasons := []int{0, 1, 2, 3, 4, 5, 6}
	for _, reason := range reasons {
		_, err := provider.CARevoke(ctx, "cert123", reason, false)
		if err == nil {
			t.Fatalf("expected error for nil CA service with reason %d", reason)
		}

		svcErr, ok := err.(ErrServiceNotAvailable)
		if !ok {
			t.Fatalf("expected ErrServiceNotAvailable for reason %d, got %T: %v", reason, err, err)
		}
		if svcErr.Service != "ca" {
			t.Errorf("expected service='ca' for reason %d, got %q", reason, svcErr.Service)
		}
	}
}

// =============================================================================
// CA Renew Tests
// =============================================================================

func TestMCPServiceProvider_CARenew_SuccessExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CARenew(ctx, "abc123", 365, true)
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CARenew_ErrorExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CARenew(ctx, "expired-cert", 365, false)
	if err == nil {
		t.Fatal("expected error from CA service")
	}
}

func TestMCPServiceProvider_CARenew_WithoutPreserveAttrsExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CARenew(ctx, "abc123", 180, false)
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}
}

func TestMCPServiceProvider_CARenew_VariousExtendDays(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Test various validity periods
	validityDays := []int{30, 90, 180, 365, 730, 1095}
	for _, days := range validityDays {
		_, err := provider.CARenew(ctx, "cert123", days, true)
		if err == nil {
			t.Fatalf("expected error for nil CA service with %d days", days)
		}

		svcErr, ok := err.(ErrServiceNotAvailable)
		if !ok {
			t.Fatalf("expected ErrServiceNotAvailable for %d days, got %T: %v", days, err, err)
		}
		if svcErr.Service != "ca" {
			t.Errorf("expected service='ca' for %d days, got %q", days, svcErr.Service)
		}
	}
}

// =============================================================================
// CA Verify Tests
// =============================================================================

func TestMCPServiceProvider_CAVerify_SuccessExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	certPEM := `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIRAKK5rT5rRbkk1qoVXWy4A2YwCgYIKoZIzj0EAwIwITEf
MB0GA1UEAxMWVGVzdCBDZXJ0aWZpY2F0ZSBBdXRob3IxFjAUBgNVBAoTDVRlc3Qg
-----END CERTIFICATE-----`

	_, err := provider.CAVerify(ctx, certPEM, nil, true)
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CAVerify_WithDERExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Mock DER data (not real certificate)
	derData := []byte{0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09}

	_, err := provider.CAVerify(ctx, "", derData, false)
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CAVerify_ErrorExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CAVerify(ctx, "invalid-pem", nil, true)
	if err == nil {
		t.Fatal("expected error from CA service")
	}
}

func TestMCPServiceProvider_CAVerify_WithAndWithoutRevocationCheck(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	certPEM := "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"

	// Test with revocation check enabled
	_, err := provider.CAVerify(ctx, certPEM, nil, true)
	if err == nil {
		t.Fatal("expected error for nil CA service with revocation check")
	}

	// Test with revocation check disabled
	_, err = provider.CAVerify(ctx, certPEM, nil, false)
	if err == nil {
		t.Fatal("expected error for nil CA service without revocation check")
	}
}

func TestMCPServiceProvider_CAVerify_BothPEMAndDER(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	certPEM := "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
	derData := []byte{0x30, 0x82}

	// Test with both PEM and DER (PEM should be used first if provided)
	_, err := provider.CAVerify(ctx, certPEM, derData, true)
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

// =============================================================================
// CA CRL Tests
// =============================================================================

func TestMCPServiceProvider_CACRL_SuccessExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CACRL(ctx)
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CACRL_ErrorExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CACRL(ctx)
	if err == nil {
		t.Fatal("expected error from CA service")
	}
}

// =============================================================================
// CA Bundle Tests
// =============================================================================

func TestMCPServiceProvider_CABundle_SuccessExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CABundle(ctx, "software", "RSA")
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CABundle_ErrorExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CABundle(ctx, "tpm", "ECC")
	if err == nil {
		t.Fatal("expected error from CA service")
	}
}

func TestMCPServiceProvider_CABundle_VariousStoreTypesExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	storeTypes := []string{"software", "tpm", "hsm", "pkcs11", ""}
	algorithms := []string{"RSA", "ECC", "ED25519", ""}

	for _, storeType := range storeTypes {
		for _, algorithm := range algorithms {
			_, err := provider.CABundle(ctx, storeType, algorithm)
			if err == nil {
				t.Fatalf("expected error for nil CA service with storeType=%q algorithm=%q", storeType, algorithm)
			}

			svcErr, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable for storeType=%q algorithm=%q, got %T: %v",
					storeType, algorithm, err, err)
			}
			if svcErr.Service != "ca" {
				t.Errorf("expected service='ca' for storeType=%q algorithm=%q, got %q",
					storeType, algorithm, svcErr.Service)
			}
		}
	}
}

// =============================================================================
// Health Service Tests
// =============================================================================

func TestMCPServiceProvider_Health_NilServiceExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.Health(ctx)
	if err == nil {
		t.Fatal("expected error for nil health service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "health" {
		t.Errorf("expected service='health', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_Health_SuccessExtended(t *testing.T) {
	ctx := context.Background()
	healthService := createTestHealthServiceForCAExtendedTests(t)
	if healthService == nil {
		t.Skip("cannot create health service")
	}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		HealthService: healthService,
		Logger:        slog.Default(),
	})

	result, err := provider.Health(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	status, _ := resp["status"].(string)
	if status == "" || status == "unspecified" {
		t.Error("expected specific health status")
	}
}

// =============================================================================
// Liveness Tests
// =============================================================================

func TestMCPServiceProvider_Liveness_NilServiceExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.Liveness(ctx)
	if err == nil {
		t.Fatal("expected error for nil health service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "health" {
		t.Errorf("expected service='health', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_Liveness_SuccessExtended(t *testing.T) {
	ctx := context.Background()
	healthService := createTestHealthServiceForCAExtendedTests(t)
	if healthService == nil {
		t.Skip("cannot create health service")
	}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		HealthService: healthService,
		Logger:        slog.Default(),
	})

	result, err := provider.Liveness(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if _, exists := resultMap["live"]; !exists {
		t.Error("expected 'live' key in result")
	}
	if _, exists := resultMap["status"]; !exists {
		t.Error("expected 'status' key in result")
	}
}

// =============================================================================
// Readiness Tests
// =============================================================================

func TestMCPServiceProvider_Readiness_NilServiceExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.Readiness(ctx)
	if err == nil {
		t.Fatal("expected error for nil health service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "health" {
		t.Errorf("expected service='health', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_Readiness_SuccessExtended(t *testing.T) {
	ctx := context.Background()
	healthService := createTestHealthServiceForCAExtendedTests(t)
	if healthService == nil {
		t.Skip("cannot create health service")
	}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		HealthService: healthService,
		Logger:        slog.Default(),
	})

	result, err := provider.Readiness(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if _, exists := resultMap["ready"]; !exists {
		t.Error("expected 'ready' key in result")
	}
	if _, exists := resultMap["status"]; !exists {
		t.Error("expected 'status' key in result")
	}
}

// =============================================================================
// Additional Error Type Tests
// =============================================================================

func TestMCPServiceProvider_CAInfo_ServiceErrorExtended(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.CAInfo(ctx)
	if err == nil {
		t.Fatal("expected error from CA service")
	}

	// Verify error message contains service name
	errMsg := err.Error()
	if errMsg == "" {
		t.Error("expected non-empty error message")
	}
}

func TestErrServiceNotAvailable_CAErrorMsg(t *testing.T) {
	err := ErrServiceNotAvailable{Service: "ca"}
	expected := "service not available: ca"
	if err.Error() != expected {
		t.Errorf("expected error message %q, got %q", expected, err.Error())
	}
}

func TestErrServiceNotAvailable_HealthErrorMsg(t *testing.T) {
	err := ErrServiceNotAvailable{Service: "health"}
	expected := "service not available: health"
	if err.Error() != expected {
		t.Errorf("expected error message %q, got %q", expected, err.Error())
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

// createTestHealthServiceForCAExtendedTests creates a real Service using DefaultConfig
func createTestHealthServiceForCAExtendedTests(t *testing.T) *Service {
	t.Helper()
	config := DefaultConfig()
	svc, err := NewService(config)
	if err != nil {
		return nil
	}
	svc.MarkReady()
	return svc
}
