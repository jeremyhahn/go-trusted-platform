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
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"testing"
	"time"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	dnsentities "github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
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

func (m *mockAttestationImporter) ImportAttestationEventLog(_ context.Context, akAttrs *xkmssdk.KeyAttributes, eventLog []byte) error {
	m.eventLogCalled = true
	m.lastAKAttrs = akAttrs
	return m.eventLogErr
}

func (m *mockAttestationImporter) ImportAttestationQuote(_ context.Context, akAttrs *xkmssdk.KeyAttributes, quote []byte) error {
	m.quoteCalled = true
	m.lastAKAttrs = akAttrs
	return m.quoteErr
}

func (m *mockAttestationImporter) ImportAttestationPCRs(_ context.Context, akAttrs *xkmssdk.KeyAttributes, pcrs []byte) error {
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

func (m *mockDNSRegistrar) RegisterWithNetworkZone(_ context.Context, host, networkZone, ip string) error {
	return nil
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

	hook := NewDNSRegistrationHook(dns, "internal.example.com", logger, nil)
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

	hook := NewDNSRegistrationHook(dns, "internal.example.com", logger, nil)

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

	hook := NewDNSRegistrationHook(dns, "internal.example.com", logger, nil)

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

	hook := NewDNSRegistrationHook(dns, "internal.example.com", logger, nil)

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

// TestNewDNSRegistrationHook_ZoneQualifiedRegistration verifies that when a
// profile resolver returns a network zone, RegisterWithNetworkZone is called
// for each non-BMC host in the FQDN set.
func TestNewDNSRegistrationHook_ZoneQualifiedRegistration(t *testing.T) {
	logger := slog.Default()
	registrar := &mockDNSRegistrarWithZone{}

	// Mock profile resolver that returns a profile with Zone = "control-plane".
	profiles := &mockProfileResolver{
		zone: "control-plane",
	}

	cert := createHookTestCert("lab-node-1.internal.example.com")
	hook := NewDNSRegistrationHook(registrar, "internal.example.com", logger, profiles)

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		IsTCGCSR:    true,
		ClientIP:    "192.168.1.10",
		Certificate: cert,
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProductModel:  "SuperMicro",
			ProductSerial: "SN999",
		},
	}

	err := hook(ctx)
	assert.NoError(t, err)
	assert.True(t, registrar.withZoneCalled, "RegisterWithNetworkZone must be called")
	assert.Equal(t, "control-plane", registrar.lastNetworkZone)
	assert.Equal(t, "192.168.1.10", registrar.lastZoneIP)
}

// TestNewDNSRegistrationHook_BMCNameNotZoneQualified verifies that BMC names
// are not passed to RegisterWithNetworkZone.
func TestNewDNSRegistrationHook_BMCNameNotZoneQualified(t *testing.T) {
	logger := slog.Default()
	registrar := &mockDNSRegistrarWithZone{}
	profiles := &mockProfileResolver{zone: "management"}

	cert := createHookTestCert("lab-node-1-bmc.internal.example.com")
	hook := NewDNSRegistrationHook(registrar, "internal.example.com", logger, profiles)

	ctx := &trustedca.ACMEOrderFinalizeHookContext{
		IsTCGCSR:    true,
		ClientIP:    "10.0.0.1",
		Certificate: cert,
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProductModel:  "SuperMicro",
			ProductSerial: "BMCSERIAL",
		},
	}

	err := hook(ctx)
	assert.NoError(t, err)
	// BMC name from cert CN is host=lab-node-1-bmc; must not be zone-qualified.
	// The model-serial form (SuperMicro-BMCSERIAL) is not a BMC name so may be called.
	// Key check: "lab-node-1-bmc" must never be the host argument.
	for _, h := range registrar.zoneHosts {
		assert.NotEqual(t, "lab-node-1-bmc", h, "BMC name must not be zone-qualified")
	}
}

// TestExtractHostFromFQDN verifies the helper correctly extracts the first label.
func TestExtractHostFromFQDN(t *testing.T) {
	tests := []struct {
		fqdn   string
		domain string
		want   string
	}{
		{"lab-node-1.internal.example.com", "internal.example.com", "lab-node-1"},
		{"gw.corp.local", "corp.local", "gw"},
		{"a.b.corp.local", "corp.local", ""},     // multi-label prefix
		{"corp.local", "corp.local", ""},         // exactly domain, no host
		{"other.domain.com", "internal.com", ""}, // domain mismatch
		{"", "internal.example.com", ""},
	}
	for _, tc := range tests {
		t.Run(tc.fqdn, func(t *testing.T) {
			got := extractHostFromFQDN(tc.fqdn, tc.domain)
			assert.Equal(t, tc.want, got)
		})
	}
}

// mockDNSRegistrarWithZone captures RegisterWithNetworkZone calls.
type mockDNSRegistrarWithZone struct {
	registerCalled  bool
	withZoneCalled  bool
	lastNetworkZone string
	lastZoneIP      string
	zoneHosts       []string
}

func (m *mockDNSRegistrarWithZone) Register(_ context.Context, _, _ string) (*dnsentities.Zone, error) {
	m.registerCalled = true
	return &dnsentities.Zone{}, nil
}

func (m *mockDNSRegistrarWithZone) RegisterWithNetworkZone(_ context.Context, host, networkZone, ip string) error {
	m.withZoneCalled = true
	m.lastNetworkZone = networkZone
	m.lastZoneIP = ip
	m.zoneHosts = append(m.zoneHosts, host)
	return nil
}

// mockProfileResolver is a minimal ZoneProfileResolver for hook tests.
type mockProfileResolver struct {
	zone string
	err  error
}

func (m *mockProfileResolver) FindBySerial(_ context.Context, _ string) (*deviceentities.DeviceProfile, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &deviceentities.DeviceProfile{Zone: m.zone}, nil
}

// =============================================================================
// NewDeviceRegistrationHook tests
// =============================================================================

// mockDeviceRegistrar captures Save/Update/FindBySerial calls so the
// hook's create-vs-update branching can be asserted without a real
// datastore.
type mockDeviceRegistrar struct {
	bySerial    map[string]*deviceentities.Device
	saveCalls   []*deviceentities.Device
	updateCalls []*deviceentities.Device
	saveErr     error
	updateErr   error
	lookupErr   error
}

func newMockDeviceRegistrar() *mockDeviceRegistrar {
	return &mockDeviceRegistrar{bySerial: map[string]*deviceentities.Device{}}
}

func (m *mockDeviceRegistrar) FindBySerial(_ context.Context, serial string) (*deviceentities.Device, error) {
	if m.lookupErr != nil {
		return nil, m.lookupErr
	}
	if d, ok := m.bySerial[serial]; ok {
		// Return a shallow copy so the hook's mutations don't leak
		// back into the mock's stored snapshot until Update is called.
		clone := *d
		return &clone, nil
	}
	return nil, errors.New("device not found")
}

func (m *mockDeviceRegistrar) Save(_ context.Context, d *deviceentities.Device) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.saveCalls = append(m.saveCalls, d)
	m.bySerial[d.Serial] = d
	return nil
}

func (m *mockDeviceRegistrar) Update(_ context.Context, d *deviceentities.Device) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.updateCalls = append(m.updateCalls, d)
	m.bySerial[d.Serial] = d
	return nil
}

func TestNewDeviceRegistrationHook_SkipsNonTCGCSR(t *testing.T) {
	reg := newMockDeviceRegistrar()
	hook := NewDeviceRegistrationHook(reg, slog.Default())

	err := hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:  context.Background(),
		IsTCGCSR: false,
	})
	assert.NoError(t, err)
	assert.Empty(t, reg.saveCalls)
	assert.Empty(t, reg.updateCalls)
}

func TestNewDeviceRegistrationHook_SkipsNilTCGData(t *testing.T) {
	reg := newMockDeviceRegistrar()
	hook := NewDeviceRegistrationHook(reg, slog.Default())

	err := hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:  context.Background(),
		IsTCGCSR: true,
		TCGData:  nil,
	})
	assert.NoError(t, err)
	assert.Empty(t, reg.saveCalls)
}

func TestNewDeviceRegistrationHook_SkipsMissingSerial(t *testing.T) {
	reg := newMockDeviceRegistrar()
	hook := NewDeviceRegistrationHook(reg, slog.Default())

	err := hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:  context.Background(),
		IsTCGCSR: true,
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProductModel:  "TestModel",
			ProductSerial: "",
		},
	})
	assert.NoError(t, err)
	assert.Empty(t, reg.saveCalls, "hook must not invent a serial when the TCG CSR lacks one")
}

func TestNewDeviceRegistrationHook_CreatesNewDevice(t *testing.T) {
	reg := newMockDeviceRegistrar()
	hook := NewDeviceRegistrationHook(reg, slog.Default())

	cert := createHookTestCert("Test-IDevID")
	ek := createHookTestCert("Test-EK")
	tcg := &trustedca.ACMETCGEnrollmentData{
		ProductModel:         "TestModel",
		ProductSerial:        "SN-12345",
		EKCertificate:        ek,
		AttestationPublicKey: []byte{0xab, 0xcd, 0xef},
		SigningPublicKey:     []byte{0x12, 0x34},
		EventLog:             []byte("event-log-bytes"),
	}

	err := hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:     context.Background(),
		IsTCGCSR:    true,
		Certificate: cert,
		TCGData:     tcg,
	})
	require.NoError(t, err)
	require.Len(t, reg.saveCalls, 1)
	saved := reg.saveCalls[0]
	assert.NotZero(t, saved.ID, "hook must allocate a non-zero device ID")
	assert.Equal(t, "TestModel", saved.Model)
	assert.Equal(t, "SN-12345", saved.Serial)
	assert.Contains(t, saved.EKCert, "-----BEGIN CERTIFICATE-----")
	assert.Equal(t, "abcdef", saved.AttestPub)
	assert.Equal(t, "1234", saved.SigningPub)
	assert.Equal(t, []byte("event-log-bytes"), saved.EventLog)
	assert.Equal(t, deviceentities.DeviceStateRegistered, saved.State)
	assert.False(t, saved.CreatedAt.IsZero())
}

func TestNewDeviceRegistrationHook_UpdatesExistingDeviceOnReEnroll(t *testing.T) {
	reg := newMockDeviceRegistrar()
	reg.bySerial["SN-12345"] = &deviceentities.Device{
		ID:     0xDEADBEEF,
		Serial: "SN-12345",
		Model:  "OldModel",
		State:  deviceentities.DeviceStateUnknown,
	}

	hook := NewDeviceRegistrationHook(reg, slog.Default())

	tcg := &trustedca.ACMETCGEnrollmentData{
		ProductModel:         "NewModel",
		ProductSerial:        "SN-12345",
		AttestationPublicKey: []byte{0x77},
	}
	err := hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:     context.Background(),
		IsTCGCSR:    true,
		Certificate: createHookTestCert("Test-IDevID"),
		TCGData:     tcg,
	})
	require.NoError(t, err)
	require.Empty(t, reg.saveCalls, "must not create a duplicate row when serial already exists")
	require.Len(t, reg.updateCalls, 1)
	updated := reg.updateCalls[0]
	assert.Equal(t, uint64(0xDEADBEEF), updated.ID)
	assert.Equal(t, "NewModel", updated.Model)
	assert.Equal(t, "77", updated.AttestPub)
	assert.Equal(t, deviceentities.DeviceStateRegistered, updated.State)
}

func TestNewDeviceRegistrationHook_SaveErrorPropagates(t *testing.T) {
	reg := newMockDeviceRegistrar()
	reg.saveErr = errors.New("datastore write failed")
	hook := NewDeviceRegistrationHook(reg, slog.Default())

	err := hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:     context.Background(),
		IsTCGCSR:    true,
		Certificate: createHookTestCert("Test-IDevID"),
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProductSerial: "SN-fail",
			ProductModel:  "M",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "device registration: failed to save device")
}

func TestNewDeviceRegistrationHook_UpdateErrorPropagates(t *testing.T) {
	reg := newMockDeviceRegistrar()
	reg.bySerial["SN-existing"] = &deviceentities.Device{
		ID:     1,
		Serial: "SN-existing",
	}
	reg.updateErr = errors.New("update failed")
	hook := NewDeviceRegistrationHook(reg, slog.Default())

	err := hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:     context.Background(),
		IsTCGCSR:    true,
		Certificate: createHookTestCert("Test-IDevID"),
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProductSerial: "SN-existing",
			ProductModel:  "M",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update existing device")
}

func TestNewDeviceRegistrationHook_RejectsSerialMismatch(t *testing.T) {
	// Defends against the qrdb DeviceDAO secondary-index bug where
	// FindBySerial("X") can return a record whose serial is in fact
	// "Y" (the index falls through to "return first record" when the
	// index entry is missing). Without this guard the hook would
	// UPDATE the unrelated record in-place and clobber the previously
	// enrolled device.
	reg := newMockDeviceRegistrar()
	reg.bySerial["other-serial"] = &deviceentities.Device{
		ID:     999,
		Serial: "other-serial",
		Model:  "OtherModel",
	}
	// Simulate the buggy DAO behaviour: FindBySerial("SN-new") returns
	// the unrelated "other-serial" record. The mock can't normally do
	// this since its map is keyed by serial — emulate by overriding
	// the lookup hook below.
	reg.lookupErr = nil
	// Insert a fake mismatched response by hijacking FindBySerial via
	// a one-off mock subtype.
	bad := &serialMismatchRegistrar{mockDeviceRegistrar: reg, returnDevice: reg.bySerial["other-serial"]}

	hook := NewDeviceRegistrationHook(bad, slog.Default())

	err := hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:     context.Background(),
		IsTCGCSR:    true,
		Certificate: createHookTestCert("Test-IDevID"),
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProductSerial: "SN-new",
			ProductModel:  "NewModel",
		},
	})
	require.NoError(t, err)
	// Must create a new record, NOT update the unrelated one.
	require.Len(t, reg.saveCalls, 1, "mismatch must drive a create, not an update")
	require.Empty(t, reg.updateCalls)
	assert.Equal(t, "SN-new", reg.saveCalls[0].Serial)
	assert.NotEqual(t, uint64(999), reg.saveCalls[0].ID, "must allocate a fresh ID, not reuse the unrelated record")
}

// serialMismatchRegistrar simulates the qrdb DeviceDAO secondary-index
// bug where FindBySerial returns an unrelated record. Used only for
// the regression test above.
type serialMismatchRegistrar struct {
	*mockDeviceRegistrar
	returnDevice *deviceentities.Device
}

func (s *serialMismatchRegistrar) FindBySerial(_ context.Context, _ string) (*deviceentities.Device, error) {
	clone := *s.returnDevice
	return &clone, nil
}

func TestNewDeviceRegistrationHook_TreatsTransportErrorAsCreate(t *testing.T) {
	// If FindBySerial fails with a non-not-found error (e.g. transport
	// timeout) the hook should still create a new row rather than
	// silently dropping the enrollment.
	reg := newMockDeviceRegistrar()
	reg.lookupErr = errors.New("transport timeout")
	hook := NewDeviceRegistrationHook(reg, slog.Default())

	err := hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:     context.Background(),
		IsTCGCSR:    true,
		Certificate: createHookTestCert("Test-IDevID"),
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProductSerial: "SN-new",
			ProductModel:  "M",
		},
	})
	require.NoError(t, err)
	require.Len(t, reg.saveCalls, 1)
	assert.Equal(t, "SN-new", reg.saveCalls[0].Serial)
}

// The storage not-found heuristic and the certificate PEM helpers moved to
// pkg/device alongside devicepkg.Register, where the ACME finalize hook and
// the control-plane self-registration share one implementation (#472). They
// are tested there: TestIsRecordNotFound, TestEncodeCertificatePEM.

// =============================================================================
// Zone Extension Pre-Sign Hook Tests
// =============================================================================

// mockZoneProfileResolver is a test double for ZoneProfileResolver.
type mockZoneProfileResolver struct {
	profile *deviceentities.DeviceProfile
	err     error
}

func (m *mockZoneProfileResolver) FindBySerial(_ context.Context, _ string) (*deviceentities.DeviceProfile, error) {
	return m.profile, m.err
}

func TestNewZoneExtensionPreSignHook_NilConfig(t *testing.T) {
	hook := NewZoneExtensionPreSignHook(nil, nil, slog.Default())

	ctx := &trustedca.ACMEOrderPreSignHookContext{
		Context:  context.Background(),
		IsTCGCSR: false,
	}
	exts, err := hook(ctx)
	require.NoError(t, err)
	assert.Nil(t, exts)
}

func TestNewZoneExtensionPreSignHook_EncodeZoneDisabled(t *testing.T) {
	identity := &sdn.IdentityConfig{EncodeZoneInCert: false}
	hook := NewZoneExtensionPreSignHook(nil, identity, slog.Default())

	ctx := &trustedca.ACMEOrderPreSignHookContext{
		Context:  context.Background(),
		IsTCGCSR: false,
	}
	exts, err := hook(ctx)
	require.NoError(t, err)
	assert.Nil(t, exts)
}

func TestNewZoneExtensionPreSignHook_StandardCSRUsesplatformZone(t *testing.T) {
	identity := &sdn.IdentityConfig{
		EncodeZoneInCert: true,
		PlatformZone:     "control-plane",
	}
	hook := NewZoneExtensionPreSignHook(nil, identity, slog.Default())

	ctx := &trustedca.ACMEOrderPreSignHookContext{
		Context:  context.Background(),
		IsTCGCSR: false,
	}
	exts, err := hook(ctx)
	require.NoError(t, err)
	require.Len(t, exts, 1)
	// OIDTPNetworkZone is 1.3.6.1.4.1.29377.101.21
	assert.Equal(t, []int{1, 3, 6, 1, 4, 1, 29377, 101, 21}, []int(exts[0].Id))
}

func TestNewZoneExtensionPreSignHook_TCGPathUsesPostEnrollZone(t *testing.T) {
	identity := &sdn.IdentityConfig{
		EncodeZoneInCert: true,
		PlatformZone:     "management",
	}
	profile := &deviceentities.DeviceProfile{
		Zone:                  "provisioning",
		PostEnrollmentNetwork: "control-plane",
		Networks: map[string]*deviceentities.NetworkPhaseConfig{
			"control-plane": {Zone: "control-plane"},
		},
	}
	resolver := &mockZoneProfileResolver{profile: profile}
	hook := NewZoneExtensionPreSignHook(resolver, identity, slog.Default())

	ctx := &trustedca.ACMEOrderPreSignHookContext{
		Context:  context.Background(),
		IsTCGCSR: true,
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProductSerial: "SN-1234",
			ProductModel:  "Widget-X",
		},
	}
	exts, err := hook(ctx)
	require.NoError(t, err)
	require.Len(t, exts, 1)
	// The post-enrollment zone "control-plane" should be used over the profile-level "provisioning"
	ext := exts[0]
	assert.Equal(t, []int{1, 3, 6, 1, 4, 1, 29377, 101, 21}, []int(ext.Id))
}

func TestNewZoneExtensionPreSignHook_TCGPathFallsBackToProfileZone(t *testing.T) {
	identity := &sdn.IdentityConfig{
		EncodeZoneInCert: true,
		PlatformZone:     "management",
	}
	// Profile has a zone but no post-enrollment phase-specific zone
	profile := &deviceentities.DeviceProfile{
		Zone: "operations",
	}
	resolver := &mockZoneProfileResolver{profile: profile}
	hook := NewZoneExtensionPreSignHook(resolver, identity, slog.Default())

	ctx := &trustedca.ACMEOrderPreSignHookContext{
		Context:  context.Background(),
		IsTCGCSR: true,
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProductSerial: "SN-OPSDEV",
			ProductModel:  "OpsBox",
		},
	}
	exts, err := hook(ctx)
	require.NoError(t, err)
	require.Len(t, exts, 1)
	assert.Equal(t, []int{1, 3, 6, 1, 4, 1, 29377, 101, 21}, []int(exts[0].Id))
}

func TestNewZoneExtensionPreSignHook_TCGPathProfileWithoutZoneFailsClosed(t *testing.T) {
	identity := &sdn.IdentityConfig{
		EncodeZoneInCert: true,
		PlatformZone:     "corp",
	}
	// Profile exists but declares no zone: device issuance must fail closed,
	// never fall back to the platform zone.
	profile := &deviceentities.DeviceProfile{}
	resolver := &mockZoneProfileResolver{profile: profile}
	hook := NewZoneExtensionPreSignHook(resolver, identity, slog.Default())

	ctx := &trustedca.ACMEOrderPreSignHookContext{
		Context:  context.Background(),
		IsTCGCSR: true,
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProductSerial: "SN-NOPROFILE",
			ProductModel:  "Gadget",
		},
	}
	exts, err := hook(ctx)
	require.Error(t, err)
	var zoneErr ErrDeviceZoneUnresolvable
	require.ErrorAs(t, err, &zoneErr)
	assert.Equal(t, "SN-NOPROFILE", zoneErr.Serial)
	assert.Nil(t, exts)
}

func TestNewZoneExtensionPreSignHook_TCGPathProfileLookupFailsClosed(t *testing.T) {
	identity := &sdn.IdentityConfig{
		EncodeZoneInCert: true,
		PlatformZone:     "fallback-zone",
	}
	// Profile lookup error: device issuance must fail closed.
	resolver := &mockZoneProfileResolver{err: errors.New("db unavailable")}
	hook := NewZoneExtensionPreSignHook(resolver, identity, slog.Default())

	ctx := &trustedca.ACMEOrderPreSignHookContext{
		Context:  context.Background(),
		IsTCGCSR: true,
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProductSerial: "SN-DBERR",
			ProductModel:  "Fail-Device",
		},
	}
	exts, err := hook(ctx)
	require.Error(t, err)
	var zoneErr ErrDeviceZoneUnresolvable
	require.ErrorAs(t, err, &zoneErr)
	assert.Nil(t, exts)
}

func TestNewZoneExtensionPreSignHook_NilResolverFailsClosed(t *testing.T) {
	identity := &sdn.IdentityConfig{
		EncodeZoneInCert: true,
		PlatformZone:     "default-zone",
	}
	// No resolver configured: device issuance must fail closed.
	hook := NewZoneExtensionPreSignHook(nil, identity, slog.Default())

	ctx := &trustedca.ACMEOrderPreSignHookContext{
		Context:  context.Background(),
		IsTCGCSR: true,
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProductSerial: "SN-NORESOLVER",
			ProductModel:  "Model-A",
		},
	}
	exts, err := hook(ctx)
	require.Error(t, err)
	var zoneErr ErrDeviceZoneUnresolvable
	require.ErrorAs(t, err, &zoneErr)
	assert.Nil(t, exts)
}

func TestNewZoneExtensionPreSignHook_EmptySerialFailsClosed(t *testing.T) {
	identity := &sdn.IdentityConfig{
		EncodeZoneInCert: true,
	}
	resolver := &mockZoneProfileResolver{profile: &deviceentities.DeviceProfile{Zone: "control-plane"}}
	hook := NewZoneExtensionPreSignHook(resolver, identity, slog.Default())

	ctx := &trustedca.ACMEOrderPreSignHookContext{
		Context:  context.Background(),
		IsTCGCSR: true,
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProductSerial: "   ",
			ProductModel:  "Zoneless",
		},
	}
	exts, err := hook(ctx)
	require.Error(t, err)
	var zoneErr ErrDeviceZoneUnresolvable
	require.ErrorAs(t, err, &zoneErr)
	assert.Nil(t, exts)
}

func TestNewZoneExtensionPreSignHook_NilTCGDataFailsClosed(t *testing.T) {
	identity := &sdn.IdentityConfig{
		EncodeZoneInCert: true,
	}
	hook := NewZoneExtensionPreSignHook(nil, identity, slog.Default())

	ctx := &trustedca.ACMEOrderPreSignHookContext{
		Context:  context.Background(),
		IsTCGCSR: true,
		TCGData:  nil,
	}
	exts, err := hook(ctx)
	require.Error(t, err)
	var zoneErr ErrDeviceZoneUnresolvable
	require.ErrorAs(t, err, &zoneErr)
	assert.Nil(t, exts)
}

func TestErrDeviceZoneUnresolvable_Error(t *testing.T) {
	e := ErrDeviceZoneUnresolvable{Serial: "SN-XYZ", Reason: "device profile not found"}
	assert.Contains(t, e.Error(), "SN-XYZ")
	assert.Contains(t, e.Error(), "device profile not found")
	assert.Contains(t, e.Error(), "refusing to issue")
}

func TestErrPreSignZoneResolutionFailed_Error(t *testing.T) {
	cause := errors.New("no zone found")
	e := ErrPreSignZoneResolutionFailed{Serial: "SN-001", Cause: cause}
	assert.Contains(t, e.Error(), "SN-001")
	assert.Contains(t, e.Error(), "no zone found")
	assert.Equal(t, cause, e.Unwrap())
}

func TestZoneHookExtensionContainsOIDTPNetworkZone(t *testing.T) {
	// Verify the extension OID is exactly OIDTPNetworkZone (1.3.6.1.4.1.29377.101.21)
	identity := &sdn.IdentityConfig{
		EncodeZoneInCert: true,
		PlatformZone:     "test-zone",
	}
	hook := NewZoneExtensionPreSignHook(nil, identity, slog.Default())

	ctx := &trustedca.ACMEOrderPreSignHookContext{
		Context:  context.Background(),
		IsTCGCSR: false,
	}
	exts, err := hook(ctx)
	require.NoError(t, err)
	require.Len(t, exts, 1)

	oidTPNetworkZone := pkix.Extension{}
	oidTPNetworkZone.Id = []int{1, 3, 6, 1, 4, 1, 29377, 101, 21}
	assert.Equal(t, oidTPNetworkZone.Id, exts[0].Id)
	assert.NotEmpty(t, exts[0].Value)
}

// createHookTestCertDER returns a self-signed certificate as DER, the form in
// which the ACME finalize hook receives the IAK certificate
// (TCGEnrollmentData.IAKCertificateDER).
// createHookTestCertDER issues a compliant attestation certificate: one
// carrying tcg-cap-verifiedTPMRestricted (2.23.133.11.1.3), which is what a
// CA at 0.9.4 or later stamps and the only kind the registration records.
func createHookTestCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	return createHookTestCertDERWithPolicies(t, cn, hookRestrictedPolicies)
}

// createHookTestLegacyCertDER issues what the live fleet's pre-0.9.4 CA
// stamped: residency and fixed attributes, no verifiedTPMRestricted.
func createHookTestLegacyCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	return createHookTestCertDERWithPolicies(t, cn, hookUnrestrictedPolicies)
}

// The policy arcs come from the SDK re-export, the same source the production
// check reads, so these fixtures stamp exactly what the verifier looks for.
var (
	hookRestrictedPolicies = []x509.OID{
		quicbaasca.TCGVerifiedTPMResidencyPolicy,
		quicbaasca.TCGVerifiedTPMFixedPolicy,
		quicbaasca.TCGVerifiedTPMRestrictedPolicy,
	}
	hookUnrestrictedPolicies = []x509.OID{
		quicbaasca.TCGVerifiedTPMResidencyPolicy,
		quicbaasca.TCGVerifiedTPMFixedPolicy,
	}
)

func createHookTestCertDERWithPolicies(t *testing.T, cn string, policies []x509.OID) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		Policies:     policies,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

// TestNewDeviceRegistrationHook_RecordsIAKCertificate proves a fresh
// enrollment records the IAK certificate the CA issued alongside the
// IDevID (#404). The certificate is the only trust anchor the quote
// verifier accepts (#374): a device row without it can never attest.
func TestNewDeviceRegistrationHook_RecordsIAKCertificate(t *testing.T) {
	reg := newMockDeviceRegistrar()
	hook := NewDeviceRegistrationHook(reg, slog.Default())
	iakDER := createHookTestCertDER(t, "iak-SN-404")

	err := hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:     context.Background(),
		IsTCGCSR:    true,
		Certificate: createHookTestCert("Test-IDevID"),
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProductModel:         "X10SDV",
			ProductSerial:        "SN-404",
			AttestationPublicKey: []byte{0x01},
			IAKCertificateDER:    iakDER,
		},
	})
	require.NoError(t, err)
	require.Len(t, reg.saveCalls, 1)
	saved := reg.saveCalls[0]

	block, rest := pem.Decode([]byte(saved.AttestCert))
	require.NotNil(t, block, "AttestCert must be PEM")
	assert.Empty(t, rest)
	assert.Equal(t, "CERTIFICATE", block.Type)
	assert.Equal(t, iakDER, block.Bytes, "the recorded certificate must be the one the CA issued, byte for byte")
	assert.Equal(t, "01", saved.AttestPub, "the bare key is still recorded beside the certificate")
}

// TestNewDeviceRegistrationHook_RecordsIAKCertificateOnReEnroll proves
// re-enrollment replaces the recorded certificate with the newly issued one.
func TestNewDeviceRegistrationHook_RecordsIAKCertificateOnReEnroll(t *testing.T) {
	reg := newMockDeviceRegistrar()
	reg.bySerial["SN-404"] = &deviceentities.Device{
		ID:         42,
		Serial:     "SN-404",
		AttestCert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: createHookTestCertDER(t, "iak-SN-404-v1")})),
	}
	hook := NewDeviceRegistrationHook(reg, slog.Default())
	iakDER := createHookTestCertDER(t, "iak-SN-404-v2")

	err := hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:     context.Background(),
		IsTCGCSR:    true,
		Certificate: createHookTestCert("Test-IDevID"),
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProductSerial:     "SN-404",
			IAKCertificateDER: iakDER,
		},
	})
	require.NoError(t, err)
	require.Empty(t, reg.saveCalls)
	require.Len(t, reg.updateCalls, 1)
	block, _ := pem.Decode([]byte(reg.updateCalls[0].AttestCert))
	require.NotNil(t, block)
	assert.Equal(t, iakDER, block.Bytes, "re-enrollment must record the newly issued certificate")
}

// TestNewDeviceRegistrationHook_ReEnrollWithoutIAKKeepsRecordedCertificate
// proves a finalize that carries no IAK certificate (a CA that did not issue
// one) cannot erase the certificate a previous enrollment recorded. Losing the
// anchor would silently deny the device service on its next quote.
func TestNewDeviceRegistrationHook_ReEnrollWithoutIAKKeepsRecordedCertificate(t *testing.T) {
	const recorded = "-----BEGIN CERTIFICATE-----\nrecorded\n-----END CERTIFICATE-----\n"
	reg := newMockDeviceRegistrar()
	reg.bySerial["SN-404"] = &deviceentities.Device{ID: 42, Serial: "SN-404", AttestCert: recorded}
	hook := NewDeviceRegistrationHook(reg, slog.Default())

	err := hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:     context.Background(),
		IsTCGCSR:    true,
		Certificate: createHookTestCert("Test-IDevID"),
		TCGData:     &trustedca.ACMETCGEnrollmentData{ProductSerial: "SN-404"},
	})
	require.NoError(t, err)
	require.Len(t, reg.updateCalls, 1)
	assert.Equal(t, recorded, reg.updateCalls[0].AttestCert)
}

// TestNewDeviceRegistrationHook_NoIAKLeavesAttestCertEmpty proves the hook
// never fabricates a certificate: a fresh enrollment without an IAK records
// an empty AttestCert, which the verifier reports as absence, not as trust.
func TestNewDeviceRegistrationHook_NoIAKLeavesAttestCertEmpty(t *testing.T) {
	reg := newMockDeviceRegistrar()
	hook := NewDeviceRegistrationHook(reg, slog.Default())

	err := hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:     context.Background(),
		IsTCGCSR:    true,
		Certificate: createHookTestCert("Test-IDevID"),
		TCGData:     &trustedca.ACMETCGEnrollmentData{ProductSerial: "SN-none", ProductModel: "M"},
	})
	require.NoError(t, err)
	require.Len(t, reg.saveCalls, 1)
	assert.Empty(t, reg.saveCalls[0].AttestCert)
}

func TestDeviceRegistrationHook_RecordsTheIAKCertificateAsPEM(t *testing.T) {
	// The DER the CA hands the hook has to reach the device record as a PEM
	// certificate that still parses: it is the anchor the quote verifier
	// uses (#404), and a mis-encoded one fails every quote.
	der := createHookTestCertDER(t, "iak")
	reg := newMockDeviceRegistrar()
	hook := NewDeviceRegistrationHook(reg, slog.Default())
	err := hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:  context.Background(),
		IsTCGCSR: true,
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProductSerial:     "SN-iak",
			ProductModel:      "M",
			IAKCertificateDER: der,
		},
	})
	require.NoError(t, err)
	require.Len(t, reg.saveCalls, 1)
	block, _ := pem.Decode([]byte(reg.saveCalls[0].AttestCert))
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)
	assert.Equal(t, der, block.Bytes)
	_, parseErr := x509.ParseCertificate(block.Bytes)
	assert.NoError(t, parseErr, "the PEM body must still parse as a certificate")
}

// TestNewDeviceRegistrationHook_RefusesAnIAKCertificateWithoutTheRestrictedPolicy
// is the enrollment half of the #472 follow-up. The device quote verifier
// treats a MISSING attestation certificate as an absent check (the device is
// denied service) but a PRESENT one that fails verification as a
// CRYPTOGRAPHIC failure, which the attestation service dispatches to the
// quarantine observers. A CA that does not yet stamp
// tcg-cap-verifiedTPMRestricted would therefore have every device it
// enrolls quarantine itself on its first collection.
func TestNewDeviceRegistrationHook_RefusesAnIAKCertificateWithoutTheRestrictedPolicy(t *testing.T) {
	reg := newMockDeviceRegistrar()
	hook := NewDeviceRegistrationHook(reg, slog.Default())

	err := hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:     context.Background(),
		IsTCGCSR:    true,
		Certificate: createHookTestCert("Test-IDevID"),
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProductModel:         "X10SDV",
			ProductSerial:        "SN-legacy",
			AttestationPublicKey: []byte{0x01},
			IAKCertificateDER:    createHookTestLegacyCertDER(t, "iak-SN-legacy"),
		},
	})
	require.NoError(t, err, "the device is still enrolled; only the certificate is dropped")
	require.Len(t, reg.saveCalls, 1)
	assert.Empty(t, reg.saveCalls[0].AttestCert,
		"recording it would quarantine the device on its first collection")
	assert.Equal(t, "01", reg.saveCalls[0].AttestPub, "the rest of the enrollment is recorded")
}

// A re-enrollment offering a non-compliant certificate must not replace a
// verifiable one already on the record.
func TestNewDeviceRegistrationHook_RefusedIAKCertificateKeepsTheRecordedOne(t *testing.T) {
	good := string(pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: createHookTestCertDER(t, "iak-SN-404-good")}))
	reg := newMockDeviceRegistrar()
	reg.bySerial["SN-404"] = &deviceentities.Device{ID: 42, Serial: "SN-404", AttestCert: good}
	hook := NewDeviceRegistrationHook(reg, slog.Default())

	err := hook(&trustedca.ACMEOrderFinalizeHookContext{
		Context:  context.Background(),
		IsTCGCSR: true,
		TCGData: &trustedca.ACMETCGEnrollmentData{
			ProductSerial:     "SN-404",
			IAKCertificateDER: createHookTestLegacyCertDER(t, "iak-SN-404-legacy"),
		},
	})
	require.NoError(t, err)
	require.Len(t, reg.updateCalls, 1)
	assert.Equal(t, good, reg.updateCalls[0].AttestCert)
}
