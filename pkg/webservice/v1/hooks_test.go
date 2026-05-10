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
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"testing"
	"time"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	dnsentities "github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// mockAttestationImporter is a mock implementation of AttestationImporter.
type mockAttestationImporter struct {
	eventLogCalled bool
	quoteCalled    bool
	pcrsCalled     bool
	eventLogErr    error
	quoteErr       error
	pcrsErr        error
	lastAKAttrs    *xkmssdk.KeyAttributes
}

func (m *mockAttestationImporter) ImportAttestationEventLog(akAttrs *xkmssdk.KeyAttributes, eventLog []byte) error {
	m.eventLogCalled = true
	m.lastAKAttrs = akAttrs
	return m.eventLogErr
}

func (m *mockAttestationImporter) ImportAttestationQuote(akAttrs *xkmssdk.KeyAttributes, quote []byte) error {
	m.quoteCalled = true
	m.lastAKAttrs = akAttrs
	return m.quoteErr
}

func (m *mockAttestationImporter) ImportAttestationPCRs(akAttrs *xkmssdk.KeyAttributes, pcrs []byte) error {
	m.pcrsCalled = true
	m.lastAKAttrs = akAttrs
	return m.pcrsErr
}

// mockDNSRegistrar is a mock implementation of DNSRegistrar.
type mockDNSRegistrar struct {
	registerCalled bool
	registerErr    error
	lastFQDN       string
	lastIP         string
}

func (m *mockDNSRegistrar) Register(ctx context.Context, fqdn, ip string) (*dnsentities.Zone, error) {
	m.registerCalled = true
	m.lastFQDN = fqdn
	m.lastIP = ip
	if m.registerErr != nil {
		return nil, m.registerErr
	}
	return &dnsentities.Zone{}, nil
}

func createHookTestCert(cn string) *x509.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	return cert
}

// NewAttestationImportHook tests

func TestNewAttestationImportHook_SkipsNonTCGCSR(t *testing.T) {
	logger := slog.Default()
	importer := &mockAttestationImporter{}

	hook := NewAttestationImportHook(importer, logger)
	require.NotNil(t, hook)

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		IsTCGCSR: false,
		TCGData:  nil,
	}

	err := hook(ctx)
	assert.NoError(t, err)
	assert.False(t, importer.eventLogCalled)
	assert.False(t, importer.quoteCalled)
	assert.False(t, importer.pcrsCalled)
}

func TestNewAttestationImportHook_SkipsNilTCGData(t *testing.T) {
	logger := slog.Default()
	importer := &mockAttestationImporter{}

	hook := NewAttestationImportHook(importer, logger)

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		IsTCGCSR: true,
		TCGData:  nil,
	}

	err := hook(ctx)
	assert.NoError(t, err)
	assert.False(t, importer.eventLogCalled)
}

func TestNewAttestationImportHook_ImportsEventLog(t *testing.T) {
	logger := slog.Default()
	importer := &mockAttestationImporter{}

	hook := NewAttestationImportHook(importer, logger)

	cert := createHookTestCert("test-device")

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		IsTCGCSR:    true,
		Certificate: cert,
		TCGData: &trustedca.ACMETCGEnrollmentData{
			EventLog:      []byte("event-log-data"),
			ProductModel:  "TestModel",
			ProductSerial: "SN12345",
		},
	}

	err := hook(ctx)
	assert.NoError(t, err)
	assert.True(t, importer.eventLogCalled)
	assert.Equal(t, "test-device", importer.lastAKAttrs.CN)
}

func TestNewAttestationImportHook_EventLogImportError(t *testing.T) {
	logger := slog.Default()
	importer := &mockAttestationImporter{
		eventLogErr: errors.New("storage failure"),
	}

	hook := NewAttestationImportHook(importer, logger)

	cert := createHookTestCert("test-device")

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		IsTCGCSR:    true,
		Certificate: cert,
		TCGData: &trustedca.ACMETCGEnrollmentData{
			EventLog: []byte("event-log-data"),
		},
	}

	err := hook(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to import attestation event log")
}

func TestNewAttestationImportHook_EmptyEventLog(t *testing.T) {
	logger := slog.Default()
	importer := &mockAttestationImporter{}

	hook := NewAttestationImportHook(importer, logger)

	cert := createHookTestCert("test-device")

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		IsTCGCSR:    true,
		Certificate: cert,
		TCGData: &trustedca.ACMETCGEnrollmentData{
			EventLog: nil,
		},
	}

	err := hook(ctx)
	assert.NoError(t, err)
	assert.False(t, importer.eventLogCalled)
}

func TestNewAttestationImportHook_ImportsProdCaData(t *testing.T) {
	logger := slog.Default()
	importer := &mockAttestationImporter{}

	hook := NewAttestationImportHook(importer, logger)

	cert := createHookTestCert("test-device")

	// Create valid ProdCaData
	prodCaData := &xkmssdk.ProdCaData{
		Version:     1,
		QuotedSz:    4,
		SignatureSz: 3,
		NonceSz:     5,
		PCRsSz:      4,
		Quoted:      []byte("quot"),
		Signature:   []byte("sig"),
		Nonce:       []byte("nonce"),
		PCRs:        []byte("pcrs"),
	}
	packed, err := xkmssdk.PackProdCaData(prodCaData)
	require.NoError(t, err)

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		IsTCGCSR:    true,
		Certificate: cert,
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProdCaData: packed,
		},
	}

	err = hook(ctx)
	assert.NoError(t, err)
	assert.True(t, importer.quoteCalled)
	assert.True(t, importer.pcrsCalled)
}

func TestNewAttestationImportHook_QuoteImportError(t *testing.T) {
	logger := slog.Default()
	importer := &mockAttestationImporter{
		quoteErr: errors.New("storage failure"),
	}

	hook := NewAttestationImportHook(importer, logger)

	cert := createHookTestCert("test-device")

	prodCaData := &xkmssdk.ProdCaData{
		Version:     1,
		QuotedSz:    4,
		SignatureSz: 3,
		NonceSz:     5,
		PCRsSz:      4,
		Quoted:      []byte("quot"),
		Signature:   []byte("sig"),
		Nonce:       []byte("nonce"),
		PCRs:        []byte("pcrs"),
	}
	packed, err := xkmssdk.PackProdCaData(prodCaData)
	require.NoError(t, err)

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		IsTCGCSR:    true,
		Certificate: cert,
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProdCaData: packed,
		},
	}

	err = hook(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to import attestation quote")
}

func TestNewAttestationImportHook_PCRsImportError(t *testing.T) {
	logger := slog.Default()
	importer := &mockAttestationImporter{
		pcrsErr: errors.New("storage failure"),
	}

	hook := NewAttestationImportHook(importer, logger)

	cert := createHookTestCert("test-device")

	prodCaData := &xkmssdk.ProdCaData{
		Version:     1,
		QuotedSz:    4,
		SignatureSz: 3,
		NonceSz:     5,
		PCRsSz:      4,
		Quoted:      []byte("quot"),
		Signature:   []byte("sig"),
		Nonce:       []byte("nonce"),
		PCRs:        []byte("pcrs"),
	}
	packed, err := xkmssdk.PackProdCaData(prodCaData)
	require.NoError(t, err)

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		IsTCGCSR:    true,
		Certificate: cert,
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProdCaData: packed,
		},
	}

	err = hook(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to import attestation PCRs")
}

func TestNewAttestationImportHook_InvalidProdCaData(t *testing.T) {
	logger := slog.Default()
	importer := &mockAttestationImporter{}

	hook := NewAttestationImportHook(importer, logger)

	cert := createHookTestCert("test-device")

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		IsTCGCSR:    true,
		Certificate: cert,
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProdCaData: []byte("invalid-data"),
		},
	}

	err := hook(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unpack ProdCaData")
}

func TestNewAttestationImportHook_EmptyProdCaData(t *testing.T) {
	logger := slog.Default()
	importer := &mockAttestationImporter{}

	hook := NewAttestationImportHook(importer, logger)

	cert := createHookTestCert("test-device")

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		IsTCGCSR:    true,
		Certificate: cert,
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProdCaData: nil,
		},
	}

	err := hook(ctx)
	assert.NoError(t, err)
	assert.False(t, importer.quoteCalled)
	assert.False(t, importer.pcrsCalled)
}

// NewDNSRegistrationHook tests

func TestNewDNSRegistrationHook_SkipsNonTCGCSR(t *testing.T) {
	logger := slog.Default()
	dns := &mockDNSRegistrar{}

	hook := NewDNSRegistrationHook(dns, "internal.example.com", logger)
	require.NotNil(t, hook)

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		IsTCGCSR: false,
	}

	err := hook(ctx)
	assert.NoError(t, err)
	assert.False(t, dns.registerCalled)
}

func TestNewDNSRegistrationHook_SkipsNilTCGData(t *testing.T) {
	logger := slog.Default()
	dns := &mockDNSRegistrar{}

	hook := NewDNSRegistrationHook(dns, "internal.example.com", logger)

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		IsTCGCSR: true,
		TCGData:  nil,
	}

	err := hook(ctx)
	assert.NoError(t, err)
	assert.False(t, dns.registerCalled)
}

func TestNewDNSRegistrationHook_RegistersDevice(t *testing.T) {
	logger := slog.Default()
	dns := &mockDNSRegistrar{}

	hook := NewDNSRegistrationHook(dns, "internal.example.com", logger)

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		IsTCGCSR: true,
		ClientIP: "192.168.1.100",
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProductModel:  "RaspberryPi",
			ProductSerial: "SN12345",
		},
	}

	err := hook(ctx)
	assert.NoError(t, err)
	assert.True(t, dns.registerCalled)
	assert.Equal(t, "RaspberryPi-SN12345.internal.example.com", dns.lastFQDN)
	assert.Equal(t, "192.168.1.100", dns.lastIP)
}

func TestNewDNSRegistrationHook_RegisterError(t *testing.T) {
	logger := slog.Default()
	dns := &mockDNSRegistrar{
		registerErr: errors.New("dns update failed"),
	}

	hook := NewDNSRegistrationHook(dns, "internal.example.com", logger)

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		IsTCGCSR: true,
		ClientIP: "192.168.1.100",
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProductModel:  "Device",
			ProductSerial: "001",
		},
	}

	err := hook(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to register DNS record")
}
