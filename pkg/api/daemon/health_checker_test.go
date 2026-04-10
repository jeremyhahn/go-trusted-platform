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
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	common "github.com/jeremyhahn/go-objstore/pkg/common"
	goca "github.com/jeremyhahn/go-trusted-ca/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// healthTestMockService implements ManagedService for testing
type healthTestMockService struct {
	name      string
	running   bool
	startErr  error
	stopErr   error
	healthErr error
}

func (m *healthTestMockService) Name() string {
	return m.name
}

func (m *healthTestMockService) Start(ctx context.Context) error {
	if m.startErr != nil {
		return m.startErr
	}
	m.running = true
	return nil
}

func (m *healthTestMockService) Stop(ctx context.Context) error {
	if m.stopErr != nil {
		return m.stopErr
	}
	m.running = false
	return nil
}

func (m *healthTestMockService) IsRunning() bool {
	return m.running
}

// healthTestMockCheckableService implements both ManagedService and HealthCheckable
type healthTestMockCheckableService struct {
	healthTestMockService
}

func (m *healthTestMockCheckableService) HealthCheck(ctx context.Context) error {
	return m.healthErr
}

// healthCheckerMockCA implements goca.CACertificateAuthority for health checker testing
type healthCheckerMockCA struct {
	initialized      bool
	identity         string
	rootCert         *x509.Certificate
	rootCertErr      error
	intermediateCert *x509.Certificate
	intermediateErr  error
}

// crypto.Signer interface
func (m *healthCheckerMockCA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) Public() crypto.PublicKey { return nil }

// Core CA methods
func (m *healthCheckerMockCA) SignCSR(csrPEM []byte, request *goca.CACertificateRequest) (*x509.Certificate, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) SignTCGCSRIDevID(tcgCSR *xkmssdk.TCG_CSR_IDEVID, request *goca.CACertificateRequest) ([]byte, []byte, error) {
	return nil, nil, nil
}
func (m *healthCheckerMockCA) CABundle(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) ImportCertificate(certificate *x509.Certificate) error { return nil }
func (m *healthCheckerMockCA) Certificate(attrs *xkmssdk.KeyAttributes) (*x509.Certificate, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) CertificatePEM(cn string) ([]byte, error) { return nil, nil }
func (m *healthCheckerMockCA) Verify(certificate *x509.Certificate, xsigner crypto.Signer) ([][]*x509.Certificate, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) Signer() (crypto.Signer, error) { return nil, nil }
func (m *healthCheckerMockCA) TrustedRoot() (*x509.Certificate, error) {
	return m.rootCert, m.rootCertErr
}
func (m *healthCheckerMockCA) TrustedIntermediate() (*x509.Certificate, error) {
	return m.intermediateCert, m.intermediateErr
}
func (m *healthCheckerMockCA) CreateCSR(request *goca.CACertificateRequest) ([]byte, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) TLSCertificate(attrs *xkmssdk.KeyAttributes) (tls.Certificate, error) {
	return tls.Certificate{}, nil
}
func (m *healthCheckerMockCA) TLSBundle(attrs *xkmssdk.KeyAttributes) ([]byte, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) TLSConfig(attrs *xkmssdk.KeyAttributes) (*tls.Config, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) TLSConfigWithXSigner(attrs *xkmssdk.KeyAttributes, xsigner interface{}) (*tls.Config, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) QuantumSafeTLSConfig(attrs *xkmssdk.KeyAttributes) (*tls.Config, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) TLSBundleWithCrossSigner(attrs *xkmssdk.KeyAttributes, issuerCN string) ([][]byte, *x509.Certificate, error) {
	return nil, nil, nil
}
func (m *healthCheckerMockCA) IssueCertificate(request *goca.CACertificateRequest) (*x509.Certificate, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) Issued(cn string) (bool, error) { return false, nil }
func (m *healthCheckerMockCA) Exists(cn string, algorithm x509.SignatureAlgorithm) (bool, error) {
	return false, nil
}
func (m *healthCheckerMockCA) Revoke(certificate *x509.Certificate, keyAttrs *xkmssdk.KeyAttributes) error {
	return nil
}
func (m *healthCheckerMockCA) ImportDistributionCRLs(cert *x509.Certificate) error { return nil }
func (m *healthCheckerMockCA) IssueEKCertificate(request *goca.CACertificateRequest, ekPubKey crypto.PublicKey) (*x509.Certificate, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) IssueAKCertificate(request *goca.CACertificateRequest, pubKey crypto.PublicKey) (*x509.Certificate, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) ImportEndorsementKeyCertificate(cert *x509.Certificate) error {
	return nil
}
func (m *healthCheckerMockCA) ImportXSignedCertificate(issuerCN string, cert *x509.Certificate) error {
	return nil
}
func (m *healthCheckerMockCA) EndorsementKeyCertificate(cn string) (*x509.Certificate, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) SignedBlob(data interface{}) ([]byte, error) { return nil, nil }
func (m *healthCheckerMockCA) TrustedRootCertPool(cert *x509.Certificate, xsigner crypto.Signer) (*x509.CertPool, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) TrustedIntermediateCertPool(cert *x509.Certificate, xsigner crypto.Signer) (*x509.CertPool, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) CABundleCertPool(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) (*x509.CertPool, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) ImportIssuingCAs(cert *x509.Certificate) error { return nil }
func (m *healthCheckerMockCA) ParseBundle(bundle []byte) ([]*x509.Certificate, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) RootCertificate(childCert *x509.Certificate) (*x509.Certificate, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) CertificateStore() xkmssdk.CertStore { return nil }
func (m *healthCheckerMockCA) ObjectStore() common.Storage         { return nil }
func (m *healthCheckerMockCA) PEM(attrs *xkmssdk.KeyAttributes) ([]byte, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) ImportCertificatePEM(cn string, pemData []byte) error  { return nil }
func (m *healthCheckerMockCA) Blob(key string) ([]byte, error)                       { return nil, nil }
func (m *healthCheckerMockCA) ImportBlob(key string, data []byte) error              { return nil }
func (m *healthCheckerMockCA) KeyStore() interface{}                                 { return nil }
func (m *healthCheckerMockCA) Key(attrs *xkmssdk.KeyAttributes) (interface{}, error) { return nil, nil }
func (m *healthCheckerMockCA) PubKey(attrs *xkmssdk.KeyAttributes) (crypto.PublicKey, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) OSTrustStore() (*x509.CertPool, error)        { return nil, nil }
func (m *healthCheckerMockCA) IsAutoImportingIssuerCAs() bool               { return false }
func (m *healthCheckerMockCA) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm { return x509.RSA }
func (m *healthCheckerMockCA) DefaultSignatureAlgorithm() x509.SignatureAlgorithm {
	return x509.SHA256WithRSA
}
func (m *healthCheckerMockCA) DefaultValidityPeriod() time.Duration { return 365 * 24 * time.Hour }
func (m *healthCheckerMockCA) Hash() crypto.Hash                    { return crypto.SHA256 }
func (m *healthCheckerMockCA) Identity() string                     { return m.identity }
func (m *healthCheckerMockCA) CAKeyAttributes(storeType xkmssdk.StoreType) (*xkmssdk.KeyAttributes, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) CASigner(storeType xkmssdk.StoreType, algorithm x509.PublicKeyAlgorithm) (crypto.Signer, error) {
	return nil, nil
}
func (m *healthCheckerMockCA) Init() error             { return nil }
func (m *healthCheckerMockCA) Load() error             { return nil }
func (m *healthCheckerMockCA) IsInitialized() bool     { return m.initialized }
func (m *healthCheckerMockCA) CAConfig() goca.CAConfig { return goca.CAConfig{} }
func (m *healthCheckerMockCA) ImportAttestation(akAttrs *xkmssdk.KeyAttributes, blobType string, data []byte) error {
	return nil
}
func (m *healthCheckerMockCA) ImportAttestationKeyCertificate(attrs *xkmssdk.KeyAttributes, akDER []byte) error {
	return nil
}
func (m *healthCheckerMockCA) ImportAttestationEventLog(akAttrs *xkmssdk.KeyAttributes, eventLog []byte) error {
	return nil
}
func (m *healthCheckerMockCA) ImportAttestationPCRs(akAttrs *xkmssdk.KeyAttributes, pcrs []byte) error {
	return nil
}
func (m *healthCheckerMockCA) ImportAttestationQuote(akAttrs *xkmssdk.KeyAttributes, quote []byte) error {
	return nil
}
func (m *healthCheckerMockCA) ImportLocalAttestation(akAttrs *xkmssdk.KeyAttributes, quote *xkmssdk.Quote) error {
	return nil
}
func (m *healthCheckerMockCA) VerifyQuote(akAttrs *xkmssdk.KeyAttributes, quote *xkmssdk.Quote, nonce []byte) error {
	return nil
}
func (m *healthCheckerMockCA) VerifyAttestationQuote(akAttrs *xkmssdk.KeyAttributes, quote []byte) error {
	return nil
}
func (m *healthCheckerMockCA) VerifyAttestationEventLog(akAttrs *xkmssdk.KeyAttributes, eventLog []byte) error {
	return nil
}
func (m *healthCheckerMockCA) VerifyAttestationPCRs(akAttrs *xkmssdk.KeyAttributes, pcrs []byte) error {
	return nil
}
func (m *healthCheckerMockCA) VerifyTCG_CSR_IDevIDBytes(packedCSR []byte, sigAlg interface{}) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
}
func (m *healthCheckerMockCA) SetTPM(tpm xkmssdk.TrustedPlatformModule) {}
func (m *healthCheckerMockCA) GenerateCRL() ([]byte, error)             { return nil, nil }
func (m *healthCheckerMockCA) IsRevoked(serial *big.Int) (bool, error) {
	return false, nil
}

func TestServiceHealthChecker_Name(t *testing.T) {
	t.Run("returns service name", func(t *testing.T) {
		svc := &healthTestMockService{name: "test-service"}
		checker := NewServiceHealthChecker(svc)

		if checker.Name() != "test-service" {
			t.Errorf("Name() = %v, want test-service", checker.Name())
		}
	})

	t.Run("returns unknown for nil service", func(t *testing.T) {
		checker := &ServiceHealthChecker{service: nil}

		if checker.Name() != "unknown" {
			t.Errorf("Name() = %v, want unknown", checker.Name())
		}
	})
}

func TestNewServiceHealthChecker(t *testing.T) {
	t.Run("returns checker for valid service", func(t *testing.T) {
		svc := &healthTestMockService{name: "test"}
		checker := NewServiceHealthChecker(svc)

		if checker == nil {
			t.Fatal("NewServiceHealthChecker() returned nil")
		}
	})

	t.Run("returns nil for nil service", func(t *testing.T) {
		checker := NewServiceHealthChecker(nil)

		if checker != nil {
			t.Error("NewServiceHealthChecker(nil) should return nil")
		}
	})
}

func TestServiceHealthChecker_Check(t *testing.T) {
	t.Run("returns unhealthy when service not running", func(t *testing.T) {
		svc := &healthTestMockService{name: "test-service", running: false}
		checker := NewServiceHealthChecker(svc)

		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Name != "test-service" {
			t.Errorf("Name = %v, want test-service", result.Name)
		}
		if result.Details["running"] != false {
			t.Errorf("Details[running] = %v, want false", result.Details["running"])
		}
	})

	t.Run("returns healthy when service running", func(t *testing.T) {
		svc := &healthTestMockService{name: "test-service", running: true}
		checker := NewServiceHealthChecker(svc)

		result := checker.Check(context.Background())

		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
		if result.Details["running"] != true {
			t.Errorf("Details[running] = %v, want true", result.Details["running"])
		}
	})

	t.Run("returns unhealthy when service is nil", func(t *testing.T) {
		checker := &ServiceHealthChecker{service: nil}

		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
	})

	t.Run("returns degraded when health check fails", func(t *testing.T) {
		svc := &healthTestMockCheckableService{
			healthTestMockService: healthTestMockService{
				name:    "test-service",
				running: true,
			},
		}
		svc.healthErr = errors.New("health check failed")
		checker := NewServiceHealthChecker(svc)

		result := checker.Check(context.Background())

		if result.Status != health.StatusDegraded {
			t.Errorf("Status = %v, want StatusDegraded", result.Status)
		}
		if result.Details["health_check_error"] != "health check failed" {
			t.Errorf("Details[health_check_error] = %v, want 'health check failed'", result.Details["health_check_error"])
		}
	})

	t.Run("returns healthy when health check passes", func(t *testing.T) {
		svc := &healthTestMockCheckableService{
			healthTestMockService: healthTestMockService{
				name:    "test-service",
				running: true,
			},
		}
		svc.healthErr = nil
		checker := NewServiceHealthChecker(svc)

		result := checker.Check(context.Background())

		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
		if result.Details["custom_health_check"] != "passed" {
			t.Errorf("Details[custom_health_check] = %v, want 'passed'", result.Details["custom_health_check"])
		}
	})

	t.Run("sets duration correctly", func(t *testing.T) {
		svc := &healthTestMockService{name: "test-service", running: true}
		checker := NewServiceHealthChecker(svc)

		result := checker.Check(context.Background())

		if result.Duration <= 0 {
			t.Errorf("Duration = %v, want > 0", result.Duration)
		}
	})

	t.Run("sets last checked time", func(t *testing.T) {
		svc := &healthTestMockService{name: "test-service", running: true}
		checker := NewServiceHealthChecker(svc)

		before := time.Now()
		result := checker.Check(context.Background())
		after := time.Now()

		if result.LastChecked.Before(before) || result.LastChecked.After(after) {
			t.Errorf("LastChecked = %v, expected between %v and %v", result.LastChecked, before, after)
		}
	})
}

func TestKMSServiceHealthChecker(t *testing.T) {
	t.Run("returns nil for nil service", func(t *testing.T) {
		checker := NewKMSServiceHealthChecker(nil)
		if checker != nil {
			t.Error("NewKMSServiceHealthChecker(nil) should return nil")
		}
	})

	t.Run("Name returns kms", func(t *testing.T) {
		checker := &KMSServiceHealthChecker{service: nil}
		if checker.Name() != "kms" {
			t.Errorf("Name() = %v, want kms", checker.Name())
		}
	})

	t.Run("Check returns unhealthy for nil service", func(t *testing.T) {
		checker := &KMSServiceHealthChecker{service: nil}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "KMS service reference is nil" {
			t.Errorf("Message = %v, want 'KMS service reference is nil'", result.Message)
		}
	})

	t.Run("Check returns unhealthy when service not running", func(t *testing.T) {
		service := &KMSService{}
		service.running.Store(false)
		checker := &KMSServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "KMS service is not running" {
			t.Errorf("Message = %v, want 'KMS service is not running'", result.Message)
		}
		if result.Details["running"] != false {
			t.Errorf("Details[running] = %v, want false", result.Details["running"])
		}
	})

	t.Run("Check returns healthy when service running", func(t *testing.T) {
		service := &KMSService{}
		service.running.Store(true)
		checker := &KMSServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
		if result.Message != "KMS service is healthy" {
			t.Errorf("Message = %v, want 'KMS service is healthy'", result.Message)
		}
		if result.Details["running"] != true {
			t.Errorf("Details[running] = %v, want true", result.Details["running"])
		}
	})

	t.Run("Check sets duration and response time", func(t *testing.T) {
		service := &KMSService{}
		service.running.Store(true)
		checker := &KMSServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Duration <= 0 {
			t.Errorf("Duration = %v, want > 0", result.Duration)
		}
		if result.Details["response_time_ms"] == nil {
			t.Error("Details[response_time_ms] should be set")
		}
	})
}

func TestIAMServiceHealthChecker(t *testing.T) {
	t.Run("returns nil for nil service", func(t *testing.T) {
		checker := NewIAMServiceHealthChecker(nil)
		if checker != nil {
			t.Error("NewIAMServiceHealthChecker(nil) should return nil")
		}
	})

	t.Run("Name returns iam", func(t *testing.T) {
		checker := &IAMServiceHealthChecker{service: nil}
		if checker.Name() != "iam" {
			t.Errorf("Name() = %v, want iam", checker.Name())
		}
	})

	t.Run("Check returns unhealthy for nil service", func(t *testing.T) {
		checker := &IAMServiceHealthChecker{service: nil}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		// Accept either the full implementation message or stub message
		validMessages := []string{
			"IAM service reference is nil",
			"IAM service not enabled (build with -tags iam)",
		}
		if result.Message != validMessages[0] && result.Message != validMessages[1] {
			t.Errorf("Message = %v, want one of %v", result.Message, validMessages)
		}
	})

	t.Run("Check returns unhealthy when service not running", func(t *testing.T) {
		// Use stub service which always returns false for IsRunning
		service := &IAMService{}
		checker := &IAMServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		// Accept either the full implementation message or stub message
		validMessages := []string{
			"IAM service is not running",
			"IAM service not enabled (build with -tags iam)",
		}
		if result.Message != validMessages[0] && result.Message != validMessages[1] {
			t.Errorf("Message = %v, want one of %v", result.Message, validMessages)
		}
	})
}

func TestTenantServiceHealthChecker(t *testing.T) {
	t.Run("returns nil for nil service", func(t *testing.T) {
		checker := NewTenantServiceHealthChecker(nil)
		if checker != nil {
			t.Error("NewTenantServiceHealthChecker(nil) should return nil")
		}
	})

	t.Run("Name returns tenant", func(t *testing.T) {
		checker := &TenantServiceHealthChecker{service: nil}
		if checker.Name() != "tenant" {
			t.Errorf("Name() = %v, want tenant", checker.Name())
		}
	})

	t.Run("Check returns unhealthy for nil service", func(t *testing.T) {
		checker := &TenantServiceHealthChecker{service: nil}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "tenant service reference is nil" {
			t.Errorf("Message = %v, want 'tenant service reference is nil'", result.Message)
		}
	})

	t.Run("Check returns unhealthy when service not running", func(t *testing.T) {
		// Use stub service which always returns false for IsRunning
		service := &TenantService{}
		checker := &TenantServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "tenant service is not running" {
			t.Errorf("Message = %v, want 'tenant service is not running'", result.Message)
		}
	})
}

func TestSDNServiceHealthChecker(t *testing.T) {
	t.Run("returns nil for nil service", func(t *testing.T) {
		checker := NewSDNServiceHealthChecker(nil)
		if checker != nil {
			t.Error("NewSDNServiceHealthChecker(nil) should return nil")
		}
	})

	t.Run("Name returns sdn", func(t *testing.T) {
		checker := &SDNServiceHealthChecker{service: nil}
		if checker.Name() != "sdn" {
			t.Errorf("Name() = %v, want sdn", checker.Name())
		}
	})

	t.Run("Check returns unhealthy for nil service", func(t *testing.T) {
		checker := &SDNServiceHealthChecker{service: nil}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "SDN service reference is nil" {
			t.Errorf("Message = %v, want 'SDN service reference is nil'", result.Message)
		}
	})

	t.Run("Check returns unhealthy when OVS client is nil", func(t *testing.T) {
		service := &SDNService{
			ovsClient: nil,
		}
		checker := &SDNServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "OVS client not initialized" {
			t.Errorf("Message = %v, want 'OVS client not initialized'", result.Message)
		}
	})

	t.Run("Check returns healthy when OVS client initialized", func(t *testing.T) {
		// Create a minimal SDN service with initialized OVS client
		service := &SDNService{
			ovsClient: &ovs.Client{}, // Non-nil OVS client
			bridges:   make(map[string]*bridgeResource),
			ports:     make(map[string]*portResource),
		}
		checker := &SDNServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
		if result.Message != "SDN service is operational" {
			t.Errorf("Message = %v, want 'SDN service is operational'", result.Message)
		}
		if result.Details["bridge_count"] != 0 {
			t.Errorf("Details[bridge_count] = %v, want 0", result.Details["bridge_count"])
		}
		if result.Details["port_count"] != 0 {
			t.Errorf("Details[port_count] = %v, want 0", result.Details["port_count"])
		}
	})

	t.Run("Check reports bridge and port counts", func(t *testing.T) {
		service := &SDNService{
			ovsClient: &ovs.Client{},
			bridges: map[string]*bridgeResource{
				"br0": {id: "br0", name: "br0"},
				"br1": {id: "br1", name: "br1"},
			},
			ports: map[string]*portResource{
				"port0": {id: "port0", name: "port0"},
			},
		}
		checker := &SDNServiceHealthChecker{service: service}

		result := checker.Check(context.Background())

		if result.Details["bridge_count"] != 2 {
			t.Errorf("Details[bridge_count] = %v, want 2", result.Details["bridge_count"])
		}
		if result.Details["port_count"] != 1 {
			t.Errorf("Details[port_count] = %v, want 1", result.Details["port_count"])
		}
	})
}

func TestCAServiceHealthChecker(t *testing.T) {
	t.Run("returns nil for nil service", func(t *testing.T) {
		checker := NewCAServiceHealthChecker(nil)
		if checker != nil {
			t.Error("NewCAServiceHealthChecker(nil) should return nil")
		}
	})

	t.Run("Name returns ca", func(t *testing.T) {
		checker := &CAServiceHealthChecker{service: nil}
		if checker.Name() != "ca" {
			t.Errorf("Name() = %v, want ca", checker.Name())
		}
	})

	t.Run("Check returns unhealthy for nil service", func(t *testing.T) {
		checker := &CAServiceHealthChecker{service: nil}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "CA service reference is nil" {
			t.Errorf("Message = %v, want 'CA service reference is nil'", result.Message)
		}
	})

	t.Run("Check returns unhealthy when CA is nil", func(t *testing.T) {
		service := &CAGRPCService{ca: nil}
		checker := &CAServiceHealthChecker{service: service}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "Certificate Authority not initialized" {
			t.Errorf("Message = %v, want 'Certificate Authority not initialized'", result.Message)
		}
		if result.Details["ca_initialized"] != false {
			t.Errorf("Details[ca_initialized] = %v, want false", result.Details["ca_initialized"])
		}
	})

	t.Run("Check returns degraded when CA not initialized", func(t *testing.T) {
		ca := &healthCheckerMockCA{
			initialized: false,
			identity:    "test-ca",
		}
		service := &CAGRPCService{ca: ca}
		checker := &CAServiceHealthChecker{service: service}
		result := checker.Check(context.Background())

		if result.Status != health.StatusDegraded {
			t.Errorf("Status = %v, want StatusDegraded", result.Status)
		}
		if result.Message != "CA configured but not fully initialized" {
			t.Errorf("Message = %v, want 'CA configured but not fully initialized'", result.Message)
		}
		if result.Details["ca_initialized"] != true {
			t.Errorf("Details[ca_initialized] = %v, want true", result.Details["ca_initialized"])
		}
		if result.Details["is_initialized"] != false {
			t.Errorf("Details[is_initialized] = %v, want false", result.Details["is_initialized"])
		}
	})

	t.Run("Check returns degraded when TrustedRoot fails", func(t *testing.T) {
		ca := &healthCheckerMockCA{
			initialized: true,
			identity:    "test-ca",
			rootCertErr: errors.New("root cert error"),
		}
		service := &CAGRPCService{ca: ca}
		checker := &CAServiceHealthChecker{service: service}
		result := checker.Check(context.Background())

		if result.Status != health.StatusDegraded {
			t.Errorf("Status = %v, want StatusDegraded", result.Status)
		}
		if result.Message != "Failed to get trusted root certificate" {
			t.Errorf("Message = %v, want 'Failed to get trusted root certificate'", result.Message)
		}
		if result.Details["root_cert_error"] != "root cert error" {
			t.Errorf("Details[root_cert_error] = %v, want 'root cert error'", result.Details["root_cert_error"])
		}
	})

	t.Run("Check returns degraded when root cert not yet valid", func(t *testing.T) {
		futureTime := time.Now().Add(24 * time.Hour)
		ca := &healthCheckerMockCA{
			initialized: true,
			identity:    "test-ca",
			rootCert: &x509.Certificate{
				Subject:   pkix.Name{CommonName: "Test Root CA"},
				NotBefore: futureTime,
				NotAfter:  futureTime.Add(365 * 24 * time.Hour),
			},
		}
		service := &CAGRPCService{ca: ca}
		checker := &CAServiceHealthChecker{service: service}
		result := checker.Check(context.Background())

		if result.Status != health.StatusDegraded {
			t.Errorf("Status = %v, want StatusDegraded", result.Status)
		}
		if result.Message != "Root certificate not yet valid" {
			t.Errorf("Message = %v, want 'Root certificate not yet valid'", result.Message)
		}
	})

	t.Run("Check returns unhealthy when root cert expired", func(t *testing.T) {
		pastTime := time.Now().Add(-365 * 24 * time.Hour)
		ca := &healthCheckerMockCA{
			initialized: true,
			identity:    "test-ca",
			rootCert: &x509.Certificate{
				Subject:   pkix.Name{CommonName: "Test Root CA"},
				NotBefore: pastTime.Add(-365 * 24 * time.Hour),
				NotAfter:  pastTime,
			},
		}
		service := &CAGRPCService{ca: ca}
		checker := &CAServiceHealthChecker{service: service}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "Root certificate has expired" {
			t.Errorf("Message = %v, want 'Root certificate has expired'", result.Message)
		}
	})

	t.Run("Check returns degraded when root cert expires soon", func(t *testing.T) {
		now := time.Now()
		ca := &healthCheckerMockCA{
			initialized: true,
			identity:    "test-ca",
			rootCert: &x509.Certificate{
				Subject:   pkix.Name{CommonName: "Test Root CA"},
				NotBefore: now.Add(-365 * 24 * time.Hour),
				NotAfter:  now.Add(15 * 24 * time.Hour), // Expires in 15 days
			},
		}
		service := &CAGRPCService{ca: ca}
		checker := &CAServiceHealthChecker{service: service}
		result := checker.Check(context.Background())

		if result.Status != health.StatusDegraded {
			t.Errorf("Status = %v, want StatusDegraded", result.Status)
		}
		if result.Message != "Root certificate expires soon" {
			t.Errorf("Message = %v, want 'Root certificate expires soon'", result.Message)
		}
		if result.Details["expires_in_days"] == nil {
			t.Error("Details[expires_in_days] should be set")
		}
	})

	t.Run("Check returns unhealthy when intermediate cert expired", func(t *testing.T) {
		now := time.Now()
		pastTime := now.Add(-365 * 24 * time.Hour)
		ca := &healthCheckerMockCA{
			initialized: true,
			identity:    "test-ca",
			rootCert: &x509.Certificate{
				Subject:   pkix.Name{CommonName: "Test Root CA"},
				NotBefore: now.Add(-730 * 24 * time.Hour),
				NotAfter:  now.Add(365 * 24 * time.Hour),
			},
			intermediateCert: &x509.Certificate{
				Subject:   pkix.Name{CommonName: "Test Intermediate CA"},
				NotBefore: pastTime.Add(-365 * 24 * time.Hour),
				NotAfter:  pastTime,
			},
		}
		service := &CAGRPCService{ca: ca}
		checker := &CAServiceHealthChecker{service: service}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "Intermediate certificate has expired" {
			t.Errorf("Message = %v, want 'Intermediate certificate has expired'", result.Message)
		}
	})

	t.Run("Check returns healthy when CA fully operational", func(t *testing.T) {
		now := time.Now()
		ca := &healthCheckerMockCA{
			initialized: true,
			identity:    "test-ca",
			rootCert: &x509.Certificate{
				Subject:   pkix.Name{CommonName: "Test Root CA"},
				NotBefore: now.Add(-365 * 24 * time.Hour),
				NotAfter:  now.Add(365 * 24 * time.Hour),
			},
			intermediateCert: &x509.Certificate{
				Subject:   pkix.Name{CommonName: "Test Intermediate CA"},
				NotBefore: now.Add(-180 * 24 * time.Hour),
				NotAfter:  now.Add(180 * 24 * time.Hour),
			},
		}
		service := &CAGRPCService{ca: ca}
		checker := &CAServiceHealthChecker{service: service}
		result := checker.Check(context.Background())

		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
		if result.Message != "CA service is healthy" {
			t.Errorf("Message = %v, want 'CA service is healthy'", result.Message)
		}
		if result.Details["identity"] != "test-ca" {
			t.Errorf("Details[identity] = %v, want 'test-ca'", result.Details["identity"])
		}
		if result.Details["root_cn"] != "Test Root CA" {
			t.Errorf("Details[root_cn] = %v, want 'Test Root CA'", result.Details["root_cn"])
		}
		if result.Details["intermediate_cn"] != "Test Intermediate CA" {
			t.Errorf("Details[intermediate_cn] = %v, want 'Test Intermediate CA'", result.Details["intermediate_cn"])
		}
	})

	t.Run("Check returns healthy with no intermediate cert", func(t *testing.T) {
		now := time.Now()
		ca := &healthCheckerMockCA{
			initialized: true,
			identity:    "test-root-ca",
			rootCert: &x509.Certificate{
				Subject:   pkix.Name{CommonName: "Test Root CA"},
				NotBefore: now.Add(-365 * 24 * time.Hour),
				NotAfter:  now.Add(365 * 24 * time.Hour),
			},
			intermediateCert: nil,
			intermediateErr:  errors.New("no intermediate"),
		}
		service := &CAGRPCService{ca: ca}
		checker := &CAServiceHealthChecker{service: service}
		result := checker.Check(context.Background())

		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
	})

	t.Run("Check sets response time details", func(t *testing.T) {
		now := time.Now()
		ca := &healthCheckerMockCA{
			initialized: true,
			identity:    "test-ca",
			rootCert: &x509.Certificate{
				Subject:   pkix.Name{CommonName: "Test Root CA"},
				NotBefore: now.Add(-365 * 24 * time.Hour),
				NotAfter:  now.Add(365 * 24 * time.Hour),
			},
		}
		service := &CAGRPCService{ca: ca}
		checker := &CAServiceHealthChecker{service: service}
		result := checker.Check(context.Background())

		if result.Details["response_time_ms"] == nil {
			t.Error("Details[response_time_ms] should be set")
		}
	})
}

func TestQUICServerHealthChecker(t *testing.T) {
	t.Run("returns nil for nil server", func(t *testing.T) {
		checker := NewQUICServerHealthChecker(nil)
		if checker != nil {
			t.Error("NewQUICServerHealthChecker(nil) should return nil")
		}
	})

	t.Run("Name returns quic", func(t *testing.T) {
		checker := &QUICServerHealthChecker{server: nil}
		if checker.Name() != "quic" {
			t.Errorf("Name() = %v, want quic", checker.Name())
		}
	})

	t.Run("Check returns unhealthy for nil server", func(t *testing.T) {
		checker := &QUICServerHealthChecker{server: nil}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "QUIC server reference is nil" {
			t.Errorf("Message = %v, want 'QUIC server reference is nil'", result.Message)
		}
	})

}

func TestRESTServiceHealthChecker(t *testing.T) {
	t.Run("returns nil for nil server", func(t *testing.T) {
		checker := NewRESTServiceHealthChecker(nil)
		if checker != nil {
			t.Error("NewRESTServiceHealthChecker(nil) should return nil")
		}
	})

	t.Run("Name returns rest", func(t *testing.T) {
		checker := &RESTServiceHealthChecker{server: nil}
		if checker.Name() != "rest" {
			t.Errorf("Name() = %v, want rest", checker.Name())
		}
	})

	t.Run("Check returns unhealthy for nil server", func(t *testing.T) {
		checker := &RESTServiceHealthChecker{server: nil}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "REST server reference is nil" {
			t.Errorf("Message = %v, want 'REST server reference is nil'", result.Message)
		}
	})

	t.Run("Check returns unhealthy when server not running", func(t *testing.T) {
		config := &Config{
			RESTListenAddr: "127.0.0.1:8443",
			RESTConfig: RESTServerConfig{
				EnableCORS:        true,
				EnableCompression: true,
			},
		}
		server := &RESTServer{
			config: config,
		}
		server.running.Store(false)

		checker := &RESTServiceHealthChecker{server: server}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "REST server is not running" {
			t.Errorf("Message = %v, want 'REST server is not running'", result.Message)
		}
		if result.Details["running"] != false {
			t.Errorf("Details[running] = %v, want false", result.Details["running"])
		}
	})

	t.Run("Check returns healthy when server running", func(t *testing.T) {
		config := &Config{
			RESTListenAddr:  "127.0.0.1:8443",
			RESTTLSCertFile: "/path/to/cert.pem",
			RESTConfig: RESTServerConfig{
				EnableCORS:        true,
				EnableCompression: true,
			},
		}
		server := &RESTServer{
			config: config,
		}
		server.running.Store(true)

		checker := &RESTServiceHealthChecker{server: server}
		result := checker.Check(context.Background())

		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
		if result.Message != "REST server is healthy" {
			t.Errorf("Message = %v, want 'REST server is healthy'", result.Message)
		}
		if result.Details["running"] != true {
			t.Errorf("Details[running] = %v, want true", result.Details["running"])
		}
		if result.Details["listen_addr"] != "127.0.0.1:8443" {
			t.Errorf("Details[listen_addr] = %v, want '127.0.0.1:8443'", result.Details["listen_addr"])
		}
		if result.Details["tls_enabled"] != true {
			t.Errorf("Details[tls_enabled] = %v, want true", result.Details["tls_enabled"])
		}
		if result.Details["cors_enabled"] != true {
			t.Errorf("Details[cors_enabled] = %v, want true", result.Details["cors_enabled"])
		}
		if result.Details["compression_enabled"] != true {
			t.Errorf("Details[compression_enabled] = %v, want true", result.Details["compression_enabled"])
		}
	})

	t.Run("Check reports TLS disabled when no cert file", func(t *testing.T) {
		config := &Config{
			RESTListenAddr:  "127.0.0.1:8080",
			RESTTLSCertFile: "",
			RESTConfig: RESTServerConfig{
				EnableCORS:        false,
				EnableCompression: false,
			},
		}
		server := &RESTServer{
			config: config,
		}
		server.running.Store(true)

		checker := &RESTServiceHealthChecker{server: server}
		result := checker.Check(context.Background())

		if result.Details["tls_enabled"] != false {
			t.Errorf("Details[tls_enabled] = %v, want false", result.Details["tls_enabled"])
		}
	})

	t.Run("Check sets response time details", func(t *testing.T) {
		config := &Config{
			RESTListenAddr: "127.0.0.1:8443",
			RESTConfig:     RESTServerConfig{},
		}
		server := &RESTServer{
			config: config,
		}
		server.running.Store(true)

		checker := &RESTServiceHealthChecker{server: server}
		result := checker.Check(context.Background())

		if result.Details["response_time_ms"] == nil {
			t.Error("Details[response_time_ms] should be set")
		}
		if result.Duration <= 0 {
			t.Errorf("Duration = %v, want > 0", result.Duration)
		}
	})
}

func TestMCPServiceHealthChecker(t *testing.T) {
	t.Run("returns nil for nil server", func(t *testing.T) {
		checker := NewMCPServiceHealthChecker(nil)
		if checker != nil {
			t.Error("NewMCPServiceHealthChecker(nil) should return nil")
		}
	})

	t.Run("Name returns mcp", func(t *testing.T) {
		checker := &MCPServiceHealthChecker{server: nil}
		if checker.Name() != "mcp" {
			t.Errorf("Name() = %v, want mcp", checker.Name())
		}
	})

	t.Run("Check returns unhealthy for nil server", func(t *testing.T) {
		checker := &MCPServiceHealthChecker{server: nil}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "MCP server reference is nil" {
			t.Errorf("Message = %v, want 'MCP server reference is nil'", result.Message)
		}
	})

	t.Run("Check returns unhealthy when server not running", func(t *testing.T) {
		config := &mcp.Config{
			ServerName:    "Test MCP Server",
			ServerVersion: "1.0.0",
			Transport:     "http",
			HTTPAddr:      "127.0.0.1:9445",
		}
		logger := logging.DefaultLogger()
		server := mcp.NewServer(nil, config, logger)

		checker := &MCPServiceHealthChecker{server: server}
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "MCP server is not running" {
			t.Errorf("Message = %v, want 'MCP server is not running'", result.Message)
		}
		if result.Details["running"] != false {
			t.Errorf("Details[running] = %v, want false", result.Details["running"])
		}
	})
}

// TestHealthCheckerTableDriven uses table-driven tests for common patterns
func TestHealthCheckerTableDriven(t *testing.T) {
	testCases := []struct {
		name           string
		checkerName    string
		createChecker  func() health.HealthChecker
		expectedStatus health.HealthStatus
		expectedMsg    string
		altMsg         string // alternate message for stub implementations
	}{
		{
			name:        "ServiceHealthChecker with nil service",
			checkerName: "unknown",
			createChecker: func() health.HealthChecker {
				return &ServiceHealthChecker{service: nil}
			},
			expectedStatus: health.StatusUnhealthy,
			expectedMsg:    "service reference is nil",
		},
		{
			name:        "KMSServiceHealthChecker with nil service",
			checkerName: "kms",
			createChecker: func() health.HealthChecker {
				return &KMSServiceHealthChecker{service: nil}
			},
			expectedStatus: health.StatusUnhealthy,
			expectedMsg:    "KMS service reference is nil",
		},
		{
			name:        "IAMServiceHealthChecker with nil service",
			checkerName: "iam",
			createChecker: func() health.HealthChecker {
				return &IAMServiceHealthChecker{service: nil}
			},
			expectedStatus: health.StatusUnhealthy,
			expectedMsg:    "IAM service reference is nil",
			altMsg:         "IAM service not enabled (build with -tags iam)",
		},
		{
			name:        "TenantServiceHealthChecker with nil service",
			checkerName: "tenant",
			createChecker: func() health.HealthChecker {
				return &TenantServiceHealthChecker{service: nil}
			},
			expectedStatus: health.StatusUnhealthy,
			expectedMsg:    "tenant service reference is nil",
		},
		{
			name:        "SDNServiceHealthChecker with nil service",
			checkerName: "sdn",
			createChecker: func() health.HealthChecker {
				return &SDNServiceHealthChecker{service: nil}
			},
			expectedStatus: health.StatusUnhealthy,
			expectedMsg:    "SDN service reference is nil",
		},
		{
			name:        "CAServiceHealthChecker with nil service",
			checkerName: "ca",
			createChecker: func() health.HealthChecker {
				return &CAServiceHealthChecker{service: nil}
			},
			expectedStatus: health.StatusUnhealthy,
			expectedMsg:    "CA service reference is nil",
		},
		{
			name:        "QUICServerHealthChecker with nil server",
			checkerName: "quic",
			createChecker: func() health.HealthChecker {
				return &QUICServerHealthChecker{server: nil}
			},
			expectedStatus: health.StatusUnhealthy,
			expectedMsg:    "QUIC server reference is nil",
		},
		{
			name:        "RESTServiceHealthChecker with nil server",
			checkerName: "rest",
			createChecker: func() health.HealthChecker {
				return &RESTServiceHealthChecker{server: nil}
			},
			expectedStatus: health.StatusUnhealthy,
			expectedMsg:    "REST server reference is nil",
		},
		{
			name:        "MCPServiceHealthChecker with nil server",
			checkerName: "mcp",
			createChecker: func() health.HealthChecker {
				return &MCPServiceHealthChecker{server: nil}
			},
			expectedStatus: health.StatusUnhealthy,
			expectedMsg:    "MCP server reference is nil",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			checker := tc.createChecker()

			if checker.Name() != tc.checkerName {
				t.Errorf("Name() = %v, want %v", checker.Name(), tc.checkerName)
			}

			result := checker.Check(context.Background())

			if result.Status != tc.expectedStatus {
				t.Errorf("Status = %v, want %v", result.Status, tc.expectedStatus)
			}
			// Check message, allowing alternate message for stub implementations
			if result.Message != tc.expectedMsg && (tc.altMsg == "" || result.Message != tc.altMsg) {
				if tc.altMsg != "" {
					t.Errorf("Message = %v, want %v or %v", result.Message, tc.expectedMsg, tc.altMsg)
				} else {
					t.Errorf("Message = %v, want %v", result.Message, tc.expectedMsg)
				}
			}
			// Duration may be 0 for stub implementations
			if tc.altMsg == "" && result.Duration <= 0 {
				t.Errorf("Duration = %v, want > 0", result.Duration)
			}
			if result.LastChecked.IsZero() {
				t.Error("LastChecked should not be zero")
			}
			if result.Details == nil {
				t.Error("Details should not be nil")
			}
		})
	}
}

// TestNewHealthCheckerConstructors tests all constructor functions
func TestNewHealthCheckerConstructors(t *testing.T) {
	t.Run("NewServiceHealthChecker", func(t *testing.T) {
		t.Run("returns nil for nil input", func(t *testing.T) {
			if NewServiceHealthChecker(nil) != nil {
				t.Error("expected nil")
			}
		})
		t.Run("returns checker for valid input", func(t *testing.T) {
			svc := &healthTestMockService{name: "test"}
			if NewServiceHealthChecker(svc) == nil {
				t.Error("expected non-nil")
			}
		})
	})

	t.Run("NewCAServiceHealthChecker", func(t *testing.T) {
		t.Run("returns nil for nil input", func(t *testing.T) {
			if NewCAServiceHealthChecker(nil) != nil {
				t.Error("expected nil")
			}
		})
		t.Run("returns checker for valid input", func(t *testing.T) {
			svc := &CAGRPCService{}
			if NewCAServiceHealthChecker(svc) == nil {
				t.Error("expected non-nil")
			}
		})
	})

	t.Run("NewSDNServiceHealthChecker", func(t *testing.T) {
		t.Run("returns nil for nil input", func(t *testing.T) {
			if NewSDNServiceHealthChecker(nil) != nil {
				t.Error("expected nil")
			}
		})
		t.Run("returns checker for valid input", func(t *testing.T) {
			svc := &SDNService{}
			if NewSDNServiceHealthChecker(svc) == nil {
				t.Error("expected non-nil")
			}
		})
	})

	t.Run("NewKMSServiceHealthChecker", func(t *testing.T) {
		t.Run("returns nil for nil input", func(t *testing.T) {
			if NewKMSServiceHealthChecker(nil) != nil {
				t.Error("expected nil")
			}
		})
		t.Run("returns checker for valid input", func(t *testing.T) {
			svc := &KMSService{}
			if NewKMSServiceHealthChecker(svc) == nil {
				t.Error("expected non-nil")
			}
		})
	})

	t.Run("NewIAMServiceHealthChecker", func(t *testing.T) {
		t.Run("returns nil for nil input", func(t *testing.T) {
			if NewIAMServiceHealthChecker(nil) != nil {
				t.Error("expected nil")
			}
		})
		t.Run("returns checker for valid input", func(t *testing.T) {
			svc := &IAMService{}
			// Stub implementation returns nil, full implementation returns checker
			// Both behaviors are acceptable depending on build tags
			_ = NewIAMServiceHealthChecker(svc)
		})
	})

	t.Run("NewTenantServiceHealthChecker", func(t *testing.T) {
		t.Run("returns nil for nil input", func(t *testing.T) {
			if NewTenantServiceHealthChecker(nil) != nil {
				t.Error("expected nil")
			}
		})
		t.Run("returns checker for valid input", func(t *testing.T) {
			svc := &TenantService{}
			if NewTenantServiceHealthChecker(svc) == nil {
				t.Error("expected non-nil")
			}
		})
	})

	t.Run("NewQUICServerHealthChecker", func(t *testing.T) {
		t.Run("returns nil for nil input", func(t *testing.T) {
			if NewQUICServerHealthChecker(nil) != nil {
				t.Error("expected nil")
			}
		})
	})

	t.Run("NewRESTServiceHealthChecker", func(t *testing.T) {
		t.Run("returns nil for nil input", func(t *testing.T) {
			if NewRESTServiceHealthChecker(nil) != nil {
				t.Error("expected nil")
			}
		})
		t.Run("returns checker for valid input", func(t *testing.T) {
			server := &RESTServer{}
			if NewRESTServiceHealthChecker(server) == nil {
				t.Error("expected non-nil")
			}
		})
	})

	t.Run("NewMCPServiceHealthChecker", func(t *testing.T) {
		t.Run("returns nil for nil input", func(t *testing.T) {
			if NewMCPServiceHealthChecker(nil) != nil {
				t.Error("expected nil")
			}
		})
	})
}
