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

package v1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"log/slog"
	"math/big"
	"testing"
	"time"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	dnsentities "github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
)

func TestNewSDNEnrollmentHookAdapter_CreatesValidAdapter(t *testing.T) {
	logger := slog.Default()

	// Create a minimal SDN enrollment hook
	// We can't easily instantiate it without full dependencies, but we can verify
	// the adapter function is created successfully
	var sdnHook *policy.SDNEnrollmentHook

	// This should not panic even with a nil hook
	adapter := NewSDNEnrollmentHookAdapter(sdnHook, logger)

	// Verify it returns a function
	if adapter == nil {
		t.Fatal("expected adapter to be non-nil")
	}
}

func TestRegistryParams_SDNEnrollmentHookField(t *testing.T) {
	// Verify that RegistryParams has the SDNEnrollmentHook field
	params := RegistryParams{}

	// This test just ensures the field exists and can be set
	params.SDNEnrollmentHook = nil

	if params.SDNEnrollmentHook != nil {
		t.Error("expected SDNEnrollmentHook to be nil when not set")
	}
}

func TestEnrollmentHookProfileService_GetBySerial_NilHook(t *testing.T) {
	// Create a service with a nil hook
	service := NewEnrollmentHookProfileService(nil)

	ctx := context.Background()
	_, err := service.GetBySerial(ctx, "NON-EXISTENT")
	if err != device.ErrProfileServiceNotInitialized {
		t.Errorf("expected ErrProfileServiceNotInitialized, got %v", err)
	}
}

func TestEnrollmentHookProfileService_GetBySerial_EmptyHook(t *testing.T) {
	// Create an empty hook (with nil pendingActivations map)
	// The zero-value SDNEnrollmentHook has nil internal sync.Map which
	// will return false for any Load operation
	hook := &policy.SDNEnrollmentHook{}

	service := NewEnrollmentHookProfileService(hook)

	// With an empty hook, GetBySerial should return not found
	ctx := context.Background()
	_, err := service.GetBySerial(ctx, "TEST-SERIAL")
	if err != device.ErrProfileNotFoundBySerial {
		t.Errorf("expected ErrProfileNotFoundBySerial, got %v", err)
	}
}

func TestNewEnrollmentHookProfileService_ReturnsService(t *testing.T) {
	// Test that the constructor returns a valid service
	service := NewEnrollmentHookProfileService(nil)
	if service == nil {
		t.Fatal("expected service to be non-nil")
	}

	// Test with a zero-value hook
	hook := &policy.SDNEnrollmentHook{}
	service = NewEnrollmentHookProfileService(hook)
	if service == nil {
		t.Fatal("expected service to be non-nil with hook")
	}
}

// mockTLSARegistrar is a mock implementation of TLSARegistrar for testing.
type mockTLSARegistrar struct {
	addedRecords []*dnsentities.TLSARecord
	addedZones   []string
	shouldError  bool
}

func (m *mockTLSARegistrar) AddTLSARecord(ctx context.Context, zoneName string, record *dnsentities.TLSARecord) error {
	if m.shouldError {
		return errors.New("mock error: failed to add TLSA record")
	}
	m.addedRecords = append(m.addedRecords, record)
	m.addedZones = append(m.addedZones, zoneName)
	return nil
}

// createTestCertificate creates a test X.509 certificate for testing.
func createTestCertificate(commonName string, dnsNames []string) (*x509.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

func TestNewTLSAGenerationHook_CreatesValidHook(t *testing.T) {
	logger := slog.Default()
	dnsService := &mockTLSARegistrar{}
	daneConfig := &dns.DANEConfig{
		Enabled:             true,
		AutoGenerate:        true,
		DefaultPort:         443,
		DefaultTTL:          3600,
		DefaultUsage:        3,
		DefaultSelector:     1,
		DefaultMatchingType: 1,
	}
	zoneName := "example.com."

	hook := NewTLSAGenerationHook(dnsService, daneConfig, zoneName, logger)

	if hook == nil {
		t.Fatal("expected hook to be non-nil")
	}
}

func TestNewTLSAGenerationHook_GeneratesTLSARecord(t *testing.T) {
	logger := slog.Default()
	dnsService := &mockTLSARegistrar{}
	daneConfig := &dns.DANEConfig{
		Enabled:             true,
		AutoGenerate:        true,
		DefaultPort:         443,
		DefaultTTL:          3600,
		DefaultUsage:        3,
		DefaultSelector:     1,
		DefaultMatchingType: 1,
	}
	zoneName := "example.com."

	hook := NewTLSAGenerationHook(dnsService, daneConfig, zoneName, logger)

	// Create a test certificate
	cert, err := createTestCertificate("www.example.com", nil)
	if err != nil {
		t.Fatalf("failed to create test certificate: %v", err)
	}

	// Create hook context
	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		Certificate: cert,
	}

	// Execute the hook
	err = hook(ctx)
	if err != nil {
		t.Fatalf("hook returned error: %v", err)
	}

	// Verify a TLSA record was added
	if len(dnsService.addedRecords) != 1 {
		t.Fatalf("expected 1 TLSA record, got %d", len(dnsService.addedRecords))
	}

	record := dnsService.addedRecords[0]

	// Verify record name
	expectedName := "_443._tcp.www.example.com."
	if record.Name != expectedName {
		t.Errorf("expected record name %s, got %s", expectedName, record.Name)
	}

	// Verify TLSA parameters
	if record.Usage != 3 {
		t.Errorf("expected usage 3, got %d", record.Usage)
	}
	if record.Selector != 1 {
		t.Errorf("expected selector 1, got %d", record.Selector)
	}
	if record.MatchingType != 1 {
		t.Errorf("expected matchingType 1, got %d", record.MatchingType)
	}
	if record.TTL != 3600 {
		t.Errorf("expected TTL 3600, got %d", record.TTL)
	}

	// Verify the hash is a valid hex-encoded SHA-256 hash (64 characters)
	if len(record.Data) != 64 {
		t.Errorf("expected hash length 64, got %d", len(record.Data))
	}

	// Verify zone name
	if len(dnsService.addedZones) != 1 || dnsService.addedZones[0] != zoneName {
		t.Errorf("expected zone %s, got %v", zoneName, dnsService.addedZones)
	}
}

func TestNewTLSAGenerationHook_UsesDNSNameAsFallback(t *testing.T) {
	logger := slog.Default()
	dnsService := &mockTLSARegistrar{}
	daneConfig := &dns.DANEConfig{
		Enabled:             true,
		AutoGenerate:        true,
		DefaultPort:         8443,
		DefaultTTL:          7200,
		DefaultUsage:        3,
		DefaultSelector:     1,
		DefaultMatchingType: 1,
	}
	zoneName := "example.com."

	hook := NewTLSAGenerationHook(dnsService, daneConfig, zoneName, logger)

	// Create a test certificate with empty CN but with DNS SANs
	cert, err := createTestCertificate("", []string{"api.example.com", "www.example.com"})
	if err != nil {
		t.Fatalf("failed to create test certificate: %v", err)
	}

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		Certificate: cert,
	}

	err = hook(ctx)
	if err != nil {
		t.Fatalf("hook returned error: %v", err)
	}

	if len(dnsService.addedRecords) != 1 {
		t.Fatalf("expected 1 TLSA record, got %d", len(dnsService.addedRecords))
	}

	record := dnsService.addedRecords[0]

	// Should use the first DNS SAN
	expectedName := "_8443._tcp.api.example.com."
	if record.Name != expectedName {
		t.Errorf("expected record name %s, got %s", expectedName, record.Name)
	}

	// Verify custom port and TTL
	if record.TTL != 7200 {
		t.Errorf("expected TTL 7200, got %d", record.TTL)
	}
}

func TestNewTLSAGenerationHook_SkipsNilCertificate(t *testing.T) {
	logger := slog.Default()
	dnsService := &mockTLSARegistrar{}
	daneConfig := &dns.DANEConfig{
		Enabled:      true,
		AutoGenerate: true,
		DefaultPort:  443,
		DefaultTTL:   3600,
	}
	zoneName := "example.com."

	hook := NewTLSAGenerationHook(dnsService, daneConfig, zoneName, logger)

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		Certificate: nil,
	}

	err := hook(ctx)
	if err != nil {
		t.Fatalf("hook returned error: %v", err)
	}

	// No records should be added
	if len(dnsService.addedRecords) != 0 {
		t.Errorf("expected 0 TLSA records, got %d", len(dnsService.addedRecords))
	}
}

func TestNewTLSAGenerationHook_SkipsNoHostname(t *testing.T) {
	logger := slog.Default()
	dnsService := &mockTLSARegistrar{}
	daneConfig := &dns.DANEConfig{
		Enabled:      true,
		AutoGenerate: true,
		DefaultPort:  443,
		DefaultTTL:   3600,
	}
	zoneName := "example.com."

	hook := NewTLSAGenerationHook(dnsService, daneConfig, zoneName, logger)

	// Create a certificate with neither CN nor DNS SANs
	cert, err := createTestCertificate("", nil)
	if err != nil {
		t.Fatalf("failed to create test certificate: %v", err)
	}

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		Certificate: cert,
	}

	err = hook(ctx)
	if err != nil {
		t.Fatalf("hook returned error: %v", err)
	}

	// No records should be added
	if len(dnsService.addedRecords) != 0 {
		t.Errorf("expected 0 TLSA records, got %d", len(dnsService.addedRecords))
	}
}

func TestNewTLSAGenerationHook_HandlesAddError(t *testing.T) {
	logger := slog.Default()
	dnsService := &mockTLSARegistrar{shouldError: true}
	daneConfig := &dns.DANEConfig{
		Enabled:      true,
		AutoGenerate: true,
		DefaultPort:  443,
		DefaultTTL:   3600,
	}
	zoneName := "example.com."

	hook := NewTLSAGenerationHook(dnsService, daneConfig, zoneName, logger)

	cert, err := createTestCertificate("www.example.com", nil)
	if err != nil {
		t.Fatalf("failed to create test certificate: %v", err)
	}

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		Certificate: cert,
	}

	// Hook should not return an error (it logs but doesn't fail certificate issuance)
	err = hook(ctx)
	if err != nil {
		t.Fatalf("hook should not return error even when AddTLSARecord fails: %v", err)
	}
}

func TestNewTLSAGenerationHook_UsesDefaultValues(t *testing.T) {
	logger := slog.Default()
	dnsService := &mockTLSARegistrar{}
	// Create config with zero values to test defaults
	daneConfig := &dns.DANEConfig{
		Enabled:      true,
		AutoGenerate: true,
		// DefaultPort, DefaultTTL, DefaultUsage, DefaultSelector, DefaultMatchingType are all 0
	}
	zoneName := "example.com."

	hook := NewTLSAGenerationHook(dnsService, daneConfig, zoneName, logger)

	cert, err := createTestCertificate("www.example.com", nil)
	if err != nil {
		t.Fatalf("failed to create test certificate: %v", err)
	}

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		Certificate: cert,
	}

	err = hook(ctx)
	if err != nil {
		t.Fatalf("hook returned error: %v", err)
	}

	if len(dnsService.addedRecords) != 1 {
		t.Fatalf("expected 1 TLSA record, got %d", len(dnsService.addedRecords))
	}

	record := dnsService.addedRecords[0]

	// Verify defaults are applied
	expectedName := "_443._tcp.www.example.com." // default port 443
	if record.Name != expectedName {
		t.Errorf("expected record name %s, got %s", expectedName, record.Name)
	}
	if record.Usage != 3 { // default DANE-EE
		t.Errorf("expected usage 3, got %d", record.Usage)
	}
	if record.Selector != 1 { // default SPKI
		t.Errorf("expected selector 1, got %d", record.Selector)
	}
	if record.MatchingType != 1 { // default SHA-256
		t.Errorf("expected matchingType 1, got %d", record.MatchingType)
	}
	if record.TTL != 3600 { // default TTL
		t.Errorf("expected TTL 3600, got %d", record.TTL)
	}
}

func TestNewTLSAGenerationHook_CorrectSPKIHash(t *testing.T) {
	logger := slog.Default()
	dnsService := &mockTLSARegistrar{}
	daneConfig := &dns.DANEConfig{
		Enabled:             true,
		AutoGenerate:        true,
		DefaultPort:         443,
		DefaultTTL:          3600,
		DefaultUsage:        3,
		DefaultSelector:     1,
		DefaultMatchingType: 1,
	}
	zoneName := "example.com."

	hook := NewTLSAGenerationHook(dnsService, daneConfig, zoneName, logger)

	cert, err := createTestCertificate("www.example.com", nil)
	if err != nil {
		t.Fatalf("failed to create test certificate: %v", err)
	}

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		Certificate: cert,
	}

	err = hook(ctx)
	if err != nil {
		t.Fatalf("hook returned error: %v", err)
	}

	if len(dnsService.addedRecords) != 1 {
		t.Fatalf("expected 1 TLSA record, got %d", len(dnsService.addedRecords))
	}

	record := dnsService.addedRecords[0]

	// Independently compute the expected SPKI hash
	spkiDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal SPKI: %v", err)
	}
	expectedHash := sha256.Sum256(spkiDER)
	expectedHashHex := hex.EncodeToString(expectedHash[:])

	if record.Data != expectedHashHex {
		t.Errorf("expected hash %s, got %s", expectedHashHex, record.Data)
	}
}

func TestTLSARegistrar_InterfaceCompliance(t *testing.T) {
	// Verify mockTLSARegistrar satisfies TLSARegistrar interface
	var _ TLSARegistrar = (*mockTLSARegistrar)(nil)
}

func TestRegistryParams_DNSConfigField(t *testing.T) {
	// Verify that RegistryParams has the DNSConfig field
	params := RegistryParams{}

	// This test just ensures the field exists and can be set
	params.DNSConfig = nil

	if params.DNSConfig != nil {
		t.Error("expected DNSConfig to be nil when not set")
	}

	// Set a config
	params.DNSConfig = &dns.Config{
		DANE: &dns.DANEConfig{
			Enabled:      true,
			AutoGenerate: true,
		},
	}

	if params.DNSConfig == nil {
		t.Error("expected DNSConfig to be non-nil after setting")
	}

	if params.DNSConfig.DANE == nil {
		t.Error("expected DANE config to be non-nil")
	}
}
