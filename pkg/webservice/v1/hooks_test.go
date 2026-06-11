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
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
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

func TestIsNotFoundErr(t *testing.T) {
	assert.False(t, isNotFoundErr(nil))
	assert.True(t, isNotFoundErr(errors.New("device not found")))
	assert.True(t, isNotFoundErr(errors.New("no such key")))
	assert.True(t, isNotFoundErr(errors.New("entity does not exist")))
	assert.True(t, isNotFoundErr(errors.New("no rows in result set")))
	assert.False(t, isNotFoundErr(errors.New("connection refused")))
}

func TestEncodeCertPEM(t *testing.T) {
	assert.Equal(t, "", encodeCertPEM(nil))
	cert := createHookTestCert("cn")
	pemStr := encodeCertPEM(cert)
	assert.Contains(t, pemStr, "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, pemStr, "-----END CERTIFICATE-----")
}
