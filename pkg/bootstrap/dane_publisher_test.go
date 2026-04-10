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

package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/dane"

	dnsconfig "github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// testDNSService is a minimal test double implementing DANEDNSService.
type testDNSService struct {
	zones         map[string]*entities.Zone
	addErr        error
	saveSignErr   error
	zoneErr       error
	addedRecords  []*entities.TLSARecord
	saveSignCalls int
}

func newTestDNSService() *testDNSService {
	return &testDNSService{
		zones: make(map[string]*entities.Zone),
	}
}

func (s *testDNSService) AddTLSARecord(
	ctx context.Context,
	zoneName string,
	record *entities.TLSARecord,
) error {
	if s.addErr != nil {
		return s.addErr
	}
	zone, ok := s.zones[zoneName]
	if !ok {
		return errors.New("zone not found")
	}
	zone.AddTLSARecord(record)
	s.addedRecords = append(s.addedRecords, record)
	return nil
}

func (s *testDNSService) SaveAndSign(
	ctx context.Context,
	zone *entities.Zone,
) error {
	s.saveSignCalls++
	if s.saveSignErr != nil {
		return s.saveSignErr
	}
	return nil
}

func (s *testDNSService) Zone(
	ctx context.Context,
	zoneName string,
) (*entities.Zone, error) {
	if s.zoneErr != nil {
		return nil, s.zoneErr
	}
	zone, ok := s.zones[zoneName]
	if !ok {
		return nil, errors.New("zone not found")
	}
	return zone, nil
}

// testCert generates a self-signed test certificate with the given common name.
func testCert(t *testing.T, cn string, isCA bool) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         isCA,
	}
	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign
		template.BasicConstraintsValid = true
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create test certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse test certificate: %v", err)
	}

	return cert
}

// daneTestLogger creates a silent logger for DANE publisher tests.
func daneTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, io.Discard)
}

func testDANEConfig(publishEE bool) *dnsconfig.DANEConfig {
	return &dnsconfig.DANEConfig{
		Enabled:             true,
		AutoGenerate:        true,
		DefaultPort:         443,
		DefaultTTL:          3600,
		DefaultUsage:        dane.UsageDANETA,
		DefaultSelector:     dane.SelectorSPKI,
		DefaultMatchingType: dane.MatchingSHA256,
		PublishDANEEE:       publishEE,
		RolloverTTL:         0,
	}
}

func TestPublishForCertificate_DANETA_Success(t *testing.T) {
	ctx := context.Background()
	logger := daneTestLogger()
	config := testDANEConfig(false)

	caCert := testCert(t, "Test CA", true)
	leafCert := testCert(t, "leaf.example.com", false)

	svc := newTestDNSService()
	svc.zones["example.com."] = &entities.Zone{Name: "example.com."}

	publisher := NewDANEPublisher(svc, config, logger)
	err := publisher.PublishForCertificate(ctx, leafCert, caCert, "leaf.example.com", 443, "example.com.")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(svc.addedRecords) != 1 {
		t.Fatalf("expected 1 record added, got %d", len(svc.addedRecords))
	}

	record := svc.addedRecords[0]
	if record.Usage != dane.UsageDANETA {
		t.Errorf("expected usage DANE-TA (%d), got %d", dane.UsageDANETA, record.Usage)
	}
	if record.Name != "_443._tcp.leaf.example.com." {
		t.Errorf("expected name _443._tcp.leaf.example.com., got %s", record.Name)
	}
	if record.Selector != dane.SelectorSPKI {
		t.Errorf("expected selector %d, got %d", dane.SelectorSPKI, record.Selector)
	}
	if record.MatchingType != dane.MatchingSHA256 {
		t.Errorf("expected matching type %d, got %d", dane.MatchingSHA256, record.MatchingType)
	}
	if record.TTL != 3600 {
		t.Errorf("expected TTL 3600, got %d", record.TTL)
	}

	// Verify the data is valid hex-encoded TLSA data.
	expectedData, err := dane.ComputeTLSAData(caCert, dane.SelectorSPKI, dane.MatchingSHA256)
	if err != nil {
		t.Fatalf("failed to compute expected TLSA data: %v", err)
	}
	if record.Data != hex.EncodeToString(expectedData) {
		t.Errorf("TLSA data mismatch: expected %s, got %s", hex.EncodeToString(expectedData), record.Data)
	}

	if svc.saveSignCalls != 1 {
		t.Errorf("expected 1 SaveAndSign call, got %d", svc.saveSignCalls)
	}
}

func TestPublishForCertificate_DANEEE_WhenEnabled(t *testing.T) {
	ctx := context.Background()
	logger := daneTestLogger()
	config := testDANEConfig(true)

	caCert := testCert(t, "Test CA", true)
	leafCert := testCert(t, "leaf.example.com", false)

	svc := newTestDNSService()
	svc.zones["example.com."] = &entities.Zone{Name: "example.com."}

	publisher := NewDANEPublisher(svc, config, logger)
	err := publisher.PublishForCertificate(ctx, leafCert, caCert, "leaf.example.com", 443, "example.com.")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(svc.addedRecords) != 2 {
		t.Fatalf("expected 2 records added (DANE-TA + DANE-EE), got %d", len(svc.addedRecords))
	}

	// First record: DANE-TA from CA cert.
	if svc.addedRecords[0].Usage != dane.UsageDANETA {
		t.Errorf("first record: expected usage DANE-TA (%d), got %d", dane.UsageDANETA, svc.addedRecords[0].Usage)
	}

	// Second record: DANE-EE from leaf cert.
	if svc.addedRecords[1].Usage != dane.UsageDANEEE {
		t.Errorf("second record: expected usage DANE-EE (%d), got %d", dane.UsageDANEEE, svc.addedRecords[1].Usage)
	}

	// Verify DANE-EE data matches leaf cert.
	expectedData, err := dane.ComputeTLSAData(leafCert, dane.SelectorSPKI, dane.MatchingSHA256)
	if err != nil {
		t.Fatalf("failed to compute expected TLSA data: %v", err)
	}
	if svc.addedRecords[1].Data != hex.EncodeToString(expectedData) {
		t.Errorf("DANE-EE data mismatch")
	}
}

func TestPublishForCertificate_DANEEE_WhenDisabled(t *testing.T) {
	ctx := context.Background()
	logger := daneTestLogger()
	config := testDANEConfig(false)

	caCert := testCert(t, "Test CA", true)
	leafCert := testCert(t, "leaf.example.com", false)

	svc := newTestDNSService()
	svc.zones["example.com."] = &entities.Zone{Name: "example.com."}

	publisher := NewDANEPublisher(svc, config, logger)
	err := publisher.PublishForCertificate(ctx, leafCert, caCert, "leaf.example.com", 443, "example.com.")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Only DANE-TA should be published.
	if len(svc.addedRecords) != 1 {
		t.Fatalf("expected 1 record (DANE-TA only), got %d", len(svc.addedRecords))
	}
	if svc.addedRecords[0].Usage != dane.UsageDANETA {
		t.Errorf("expected usage DANE-TA (%d), got %d", dane.UsageDANETA, svc.addedRecords[0].Usage)
	}
}

func TestPublishForCertificate_NilCACert(t *testing.T) {
	ctx := context.Background()
	logger := daneTestLogger()
	config := testDANEConfig(false)

	leafCert := testCert(t, "leaf.example.com", false)

	svc := newTestDNSService()
	svc.zones["example.com."] = &entities.Zone{Name: "example.com."}

	publisher := NewDANEPublisher(svc, config, logger)
	err := publisher.PublishForCertificate(ctx, leafCert, nil, "leaf.example.com", 443, "example.com.")
	if err == nil {
		t.Fatal("expected error for nil CA cert, got nil")
	}

	var caEmpty ErrCABundleEmpty
	if !errors.As(err, &caEmpty) {
		t.Errorf("expected ErrCABundleEmpty, got %T: %v", err, err)
	}
}

func TestPublishForCertificate_NilLeafCert_DANEEEEnabled(t *testing.T) {
	ctx := context.Background()
	logger := daneTestLogger()
	config := testDANEConfig(true)

	caCert := testCert(t, "Test CA", true)

	svc := newTestDNSService()
	svc.zones["example.com."] = &entities.Zone{Name: "example.com."}

	publisher := NewDANEPublisher(svc, config, logger)
	err := publisher.PublishForCertificate(ctx, nil, caCert, "leaf.example.com", 443, "example.com.")
	if err == nil {
		t.Fatal("expected error for nil leaf cert with DANE-EE enabled, got nil")
	}

	var tlsaErr ErrTLSAComputeFailed
	if !errors.As(err, &tlsaErr) {
		t.Errorf("expected ErrTLSAComputeFailed, got %T: %v", err, err)
	}
}

func TestPublishForCertificate_ZoneNotFound(t *testing.T) {
	ctx := context.Background()
	logger := daneTestLogger()
	config := testDANEConfig(false)

	caCert := testCert(t, "Test CA", true)
	leafCert := testCert(t, "leaf.example.com", false)

	svc := newTestDNSService()
	// No zone added -- AddTLSARecord will fail.

	publisher := NewDANEPublisher(svc, config, logger)
	err := publisher.PublishForCertificate(ctx, leafCert, caCert, "leaf.example.com", 443, "example.com.")
	if err == nil {
		t.Fatal("expected error for missing zone, got nil")
	}

	var pubErr ErrDANEPublishFailed
	if !errors.As(err, &pubErr) {
		t.Errorf("expected ErrDANEPublishFailed, got %T: %v", err, err)
	}
}

func TestPublishForCertificate_SaveAndSignError(t *testing.T) {
	ctx := context.Background()
	logger := daneTestLogger()
	config := testDANEConfig(false)

	caCert := testCert(t, "Test CA", true)
	leafCert := testCert(t, "leaf.example.com", false)

	svc := newTestDNSService()
	svc.zones["example.com."] = &entities.Zone{Name: "example.com."}
	svc.saveSignErr = errors.New("dnssec signing failed")

	publisher := NewDANEPublisher(svc, config, logger)
	err := publisher.PublishForCertificate(ctx, leafCert, caCert, "leaf.example.com", 443, "example.com.")
	if err == nil {
		t.Fatal("expected error from SaveAndSign failure, got nil")
	}

	var pubErr ErrDANEPublishFailed
	if !errors.As(err, &pubErr) {
		t.Errorf("expected ErrDANEPublishFailed, got %T: %v", err, err)
	}
}

func TestPublishForCertificate_AddTLSARecordError(t *testing.T) {
	ctx := context.Background()
	logger := daneTestLogger()
	config := testDANEConfig(false)

	caCert := testCert(t, "Test CA", true)
	leafCert := testCert(t, "leaf.example.com", false)

	svc := newTestDNSService()
	svc.zones["example.com."] = &entities.Zone{Name: "example.com."}
	svc.addErr = errors.New("datastore write failed")

	publisher := NewDANEPublisher(svc, config, logger)
	err := publisher.PublishForCertificate(ctx, leafCert, caCert, "leaf.example.com", 443, "example.com.")
	if err == nil {
		t.Fatal("expected error from AddTLSARecord failure, got nil")
	}

	var pubErr ErrDANEPublishFailed
	if !errors.As(err, &pubErr) {
		t.Errorf("expected ErrDANEPublishFailed, got %T: %v", err, err)
	}
}

func TestRemoveForHostname_Success(t *testing.T) {
	ctx := context.Background()
	logger := daneTestLogger()
	config := testDANEConfig(false)

	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			TLSARecords: []*entities.TLSARecord{
				{Name: "_443._tcp.leaf.example.com.", Usage: dane.UsageDANETA, Data: "aabb"},
				{Name: "_443._tcp.leaf.example.com.", Usage: dane.UsageDANEEE, Data: "ccdd"},
				{Name: "_443._tcp.other.example.com.", Usage: dane.UsageDANETA, Data: "eeff"},
			},
		},
	}

	svc := newTestDNSService()
	svc.zones["example.com."] = zone

	publisher := NewDANEPublisher(svc, config, logger)
	err := publisher.RemoveForHostname(ctx, "leaf.example.com", 443, "example.com.")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Only the "other" record should remain.
	if len(zone.RecordSet.TLSARecords) != 1 {
		t.Fatalf("expected 1 remaining TLSA record, got %d", len(zone.RecordSet.TLSARecords))
	}
	if zone.RecordSet.TLSARecords[0].Name != "_443._tcp.other.example.com." {
		t.Errorf("expected remaining record for other.example.com, got %s", zone.RecordSet.TLSARecords[0].Name)
	}
	if svc.saveSignCalls != 1 {
		t.Errorf("expected 1 SaveAndSign call, got %d", svc.saveSignCalls)
	}
}

func TestRemoveForHostname_ZoneNotFound(t *testing.T) {
	ctx := context.Background()
	logger := daneTestLogger()
	config := testDANEConfig(false)

	svc := newTestDNSService()

	publisher := NewDANEPublisher(svc, config, logger)
	err := publisher.RemoveForHostname(ctx, "leaf.example.com", 443, "example.com.")
	if err == nil {
		t.Fatal("expected error for missing zone, got nil")
	}

	var pubErr ErrDANEPublishFailed
	if !errors.As(err, &pubErr) {
		t.Errorf("expected ErrDANEPublishFailed, got %T: %v", err, err)
	}
}

func TestRemoveForHostname_NoMatchingRecords(t *testing.T) {
	ctx := context.Background()
	logger := daneTestLogger()
	config := testDANEConfig(false)

	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			TLSARecords: []*entities.TLSARecord{
				{Name: "_443._tcp.other.example.com.", Usage: dane.UsageDANETA, Data: "aabb"},
			},
		},
	}

	svc := newTestDNSService()
	svc.zones["example.com."] = zone

	publisher := NewDANEPublisher(svc, config, logger)
	err := publisher.RemoveForHostname(ctx, "leaf.example.com", 443, "example.com.")
	if err != nil {
		t.Fatalf("expected no error when no matching records, got: %v", err)
	}

	// The existing record should be untouched.
	if len(zone.RecordSet.TLSARecords) != 1 {
		t.Fatalf("expected 1 TLSA record unchanged, got %d", len(zone.RecordSet.TLSARecords))
	}
}

func TestRemoveForHostname_SaveAndSignError(t *testing.T) {
	ctx := context.Background()
	logger := daneTestLogger()
	config := testDANEConfig(false)

	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			TLSARecords: []*entities.TLSARecord{
				{Name: "_443._tcp.leaf.example.com.", Usage: dane.UsageDANETA, Data: "aabb"},
			},
		},
	}

	svc := newTestDNSService()
	svc.zones["example.com."] = zone
	svc.saveSignErr = errors.New("signing failed")

	publisher := NewDANEPublisher(svc, config, logger)
	err := publisher.RemoveForHostname(ctx, "leaf.example.com", 443, "example.com.")
	if err == nil {
		t.Fatal("expected error from SaveAndSign failure, got nil")
	}

	var pubErr ErrDANEPublishFailed
	if !errors.As(err, &pubErr) {
		t.Errorf("expected ErrDANEPublishFailed, got %T: %v", err, err)
	}
}

func TestPrePublishRollover_BothRecordsPresent(t *testing.T) {
	ctx := context.Background()
	logger := daneTestLogger()
	config := testDANEConfig(true)
	config.RolloverTTL = 7200

	newLeafCert := testCert(t, "new-leaf.example.com", false)

	// Pre-populate with an existing DANE-TA record.
	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			TLSARecords: []*entities.TLSARecord{
				{Name: "_443._tcp.leaf.example.com.", Usage: dane.UsageDANETA, Data: "existing"},
			},
		},
	}

	svc := newTestDNSService()
	svc.zones["example.com."] = zone

	publisher := NewDANEPublisher(svc, config, logger)
	err := publisher.PrePublishRollover(ctx, newLeafCert, "leaf.example.com", 443, "example.com.")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Both the existing and new records should be present.
	if len(zone.RecordSet.TLSARecords) != 2 {
		t.Fatalf("expected 2 TLSA records (old + rollover), got %d", len(zone.RecordSet.TLSARecords))
	}

	// Verify the new record uses DANE-EE and the configured RolloverTTL.
	newRecord := svc.addedRecords[0]
	if newRecord.Usage != dane.UsageDANEEE {
		t.Errorf("expected DANE-EE usage for rollover record, got %d", newRecord.Usage)
	}
	if newRecord.TTL != 7200 {
		t.Errorf("expected rollover TTL 7200, got %d", newRecord.TTL)
	}

	// Verify the data matches the new certificate.
	expectedData, err := dane.ComputeTLSAData(newLeafCert, dane.SelectorSPKI, dane.MatchingSHA256)
	if err != nil {
		t.Fatalf("failed to compute expected TLSA data: %v", err)
	}
	if newRecord.Data != hex.EncodeToString(expectedData) {
		t.Errorf("rollover record data mismatch")
	}
}

func TestPrePublishRollover_DefaultTTL(t *testing.T) {
	ctx := context.Background()
	logger := daneTestLogger()
	config := testDANEConfig(false)
	config.RolloverTTL = 0 // Should default to 2x DefaultTTL.

	newLeafCert := testCert(t, "new-leaf.example.com", false)

	svc := newTestDNSService()
	svc.zones["example.com."] = &entities.Zone{Name: "example.com."}

	publisher := NewDANEPublisher(svc, config, logger)
	err := publisher.PrePublishRollover(ctx, newLeafCert, "leaf.example.com", 443, "example.com.")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(svc.addedRecords) != 1 {
		t.Fatalf("expected 1 record, got %d", len(svc.addedRecords))
	}

	expectedTTL := uint32(7200) // 2 * 3600
	if svc.addedRecords[0].TTL != expectedTTL {
		t.Errorf("expected default rollover TTL %d, got %d", expectedTTL, svc.addedRecords[0].TTL)
	}
}

func TestPrePublishRollover_NilCert(t *testing.T) {
	ctx := context.Background()
	logger := daneTestLogger()
	config := testDANEConfig(false)

	svc := newTestDNSService()
	svc.zones["example.com."] = &entities.Zone{Name: "example.com."}

	publisher := NewDANEPublisher(svc, config, logger)
	err := publisher.PrePublishRollover(ctx, nil, "leaf.example.com", 443, "example.com.")
	if err == nil {
		t.Fatal("expected error for nil cert, got nil")
	}

	var tlsaErr ErrTLSAComputeFailed
	if !errors.As(err, &tlsaErr) {
		t.Errorf("expected ErrTLSAComputeFailed, got %T: %v", err, err)
	}
}

func TestTLSARecordName_Format(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		port     uint16
		expected string
	}{
		{
			name:     "standard HTTPS",
			hostname: "www.example.com",
			port:     443,
			expected: "_443._tcp.www.example.com.",
		},
		{
			name:     "SMTP submission",
			hostname: "mail.example.com",
			port:     25,
			expected: "_25._tcp.mail.example.com.",
		},
		{
			name:     "custom port",
			hostname: "kms.internal.example.com",
			port:     8443,
			expected: "_8443._tcp.kms.internal.example.com.",
		},
		{
			name:     "port 0",
			hostname: "host.example.com",
			port:     0,
			expected: "_0._tcp.host.example.com.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tlsaRecordName(tc.hostname, tc.port)
			if result != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, result)
			}
		})
	}
}
