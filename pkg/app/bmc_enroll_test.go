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

package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeResolver implements trust.Resolver for testing.
type fakeResolver struct {
	tlsErr error
}

func (f *fakeResolver) TLSConfig(_ context.Context, _ trust.Class, _ string) (*tls.Config, error) {
	if f.tlsErr != nil {
		return nil, f.tlsErr
	}
	return &tls.Config{MinVersion: tls.VersionTLS12}, nil
}

func (f *fakeResolver) CAPool(_ context.Context, _ trust.Class, _ string) (*x509.CertPool, error) {
	return x509.NewCertPool(), nil
}

func (f *fakeResolver) CABundlePEM(_ context.Context, _ trust.Class) ([]byte, error) {
	return nil, nil
}

// compile-time check.
var _ trust.Resolver = (*fakeResolver)(nil)

// fakeCertFetcher implements the certFetcher interface.
type fakeCertFetcher struct {
	cert     *x509.Certificate
	fetchErr error
	closed   bool
}

func (f *fakeCertFetcher) GetWebCertificate(_ context.Context) (*x509.Certificate, error) {
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	return f.cert, nil
}

func (f *fakeCertFetcher) Close() error {
	f.closed = true
	return nil
}

// fakeCredStore wraps bmc.MemoryStore so tests can inspect calls.
type fakeCredStore struct {
	inner    *bmc.MemoryStore
	getErr   error
	putErr   error
	getCalls int
	putCalls int
}

func newFakeCredStore() *fakeCredStore {
	return &fakeCredStore{inner: bmc.NewMemoryStore()}
}

func (f *fakeCredStore) Get(ctx context.Context, name string) (*bmc.Credentials, error) {
	f.getCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.inner.Get(ctx, name)
}

func (f *fakeCredStore) Put(ctx context.Context, name string, creds *bmc.Credentials) error {
	f.putCalls++
	if f.putErr != nil {
		return f.putErr
	}
	return f.inner.Put(ctx, name, creds)
}

func (f *fakeCredStore) Delete(ctx context.Context, name string) error {
	return f.inner.Delete(ctx, name)
}

func (f *fakeCredStore) List(ctx context.Context) ([]string, error) {
	return f.inner.List(ctx)
}

func (f *fakeCredStore) History(ctx context.Context, name string) ([]bmc.CredentialVersion, error) {
	return f.inner.History(ctx, name)
}

var _ bmc.CredentialStore = (*fakeCredStore)(nil)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// testCert builds a minimal self-signed certificate suitable for tests.
// It re-uses testIssuedCertificate from bmc_cert_test.go.

// minimalCore returns an enrollCore with only the mandatory fields wired.
// The certFetcher, certIssuer, pinUpdater, dnsRegister, and danePublish fields
// are intentionally left nil so callers can selectively enable them.
func minimalCore(t *testing.T) *enrollCore {
	t.Helper()
	dev := &entities.Device{ID: 1, State: entities.DeviceStateActivated}
	return &enrollCore{
		resolver: &fakeResolver{},
		deviceLoader: func(_ context.Context, id uint64) (*entities.Device, error) {
			return dev, nil
		},
		deviceSaver: func(_ context.Context, _ *entities.Device) error {
			return nil
		},
	}
}

// runDefault calls runEnrollCore with all-disabled flags and a minimal core.
func runDefault(ctx context.Context, core *enrollCore) (*BMCEnrollResult, error) {
	return runEnrollCore(ctx, 1, "198.51.100.102", "198.51.100.102:443", "internal.", enrollmentFlags{}, core)
}

// ---------------------------------------------------------------------------
// TestRunEnrollCore
// ---------------------------------------------------------------------------

func TestRunEnrollCore_StepTrust_Success(t *testing.T) {
	ctx := context.Background()
	core := minimalCore(t)

	result, err := runDefault(ctx, core)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Steps) == 0 {
		t.Fatal("expected steps to be populated")
	}
	step := result.Steps[0]
	if step.Name != "trust" {
		t.Errorf("Steps[0].Name = %q, want %q", step.Name, "trust")
	}
	if !step.OK {
		t.Errorf("Steps[0].OK = false, want true")
	}
}

func TestRunEnrollCore_StepTrust_Failure(t *testing.T) {
	ctx := context.Background()
	core := minimalCore(t)
	wantErr := errors.New("resolver unavailable")
	core.resolver = &fakeResolver{tlsErr: wantErr}

	result, err := runDefault(ctx, core)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if len(result.Steps) == 0 {
		t.Fatal("expected steps to be populated on failure")
	}
	step := result.Steps[0]
	if step.Name != "trust" || step.OK {
		t.Errorf("step = {%q, %v}, want {\"trust\", false}", step.Name, step.OK)
	}
}

func TestRunEnrollCore_StepFactoryCert_Skipped(t *testing.T) {
	ctx := context.Background()
	core := minimalCore(t)
	// No certFetcher → factory-cert step should be skipped with OK=true.

	result, err := runDefault(ctx, core)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	findStep(t, result, "factory-cert", true, "skipped")
}

func TestRunEnrollCore_StepFactoryCert_Success(t *testing.T) {
	ctx := context.Background()
	core := minimalCore(t)
	factoryCert := testIssuedCertificate()
	core.certFetcher = &fakeCertFetcher{cert: factoryCert}

	result, err := runDefault(ctx, core)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	step := findStep(t, result, "factory-cert", true, "captured")
	_ = step
	// PinSPKISHA256 should be set from the factory cert.
	if result.PinSPKISHA256 == "" {
		t.Error("PinSPKISHA256 should be set after factory-cert capture")
	}
	if len(result.FactoryCertPEM) == 0 {
		t.Error("FactoryCertPEM should be populated")
	}
}

func TestRunEnrollCore_StepFactoryCert_Failure(t *testing.T) {
	ctx := context.Background()
	core := minimalCore(t)
	wantErr := errors.New("TLS dial failed")
	core.certFetcher = &fakeCertFetcher{fetchErr: wantErr}

	result, err := runDefault(ctx, core)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var enrollErr ErrBMCEnrollFactoryCert
	if !errors.As(err, &enrollErr) {
		t.Errorf("err type = %T, want ErrBMCEnrollFactoryCert", err)
	}
	findStep(t, result, "factory-cert", false, "")
}

func TestRunEnrollCore_StepCredentials_Skipped(t *testing.T) {
	ctx := context.Background()
	core := minimalCore(t)
	// No credStore → credentials step should be skipped.

	result, err := runDefault(ctx, core)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	findStep(t, result, "credentials", true, "skipped")
}

func TestRunEnrollCore_StepCredentials_Success(t *testing.T) {
	ctx := context.Background()
	core := minimalCore(t)
	core.credStore = newFakeCredStore()

	result, err := runDefault(ctx, core)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	findStep(t, result, "credentials", true, "")
}

func TestRunEnrollCore_StepCredentials_GetError(t *testing.T) {
	ctx := context.Background()
	core := minimalCore(t)
	// A credStore.Get error is expected (credentials not yet stored);
	// enrollCredentials returns nil and the step is marked success.
	cs := newFakeCredStore()
	cs.getErr = errors.New("internal storage error")
	core.credStore = cs

	result, err := runDefault(ctx, core)
	if err != nil {
		t.Fatalf("expected success (Get error is not fatal), got: %v", err)
	}
	findStep(t, result, "credentials", true, "")
}

func TestRunEnrollCore_StepReplaceCertificate_Skipped_Flag(t *testing.T) {
	ctx := context.Background()
	core := minimalCore(t)
	// ReplaceCertificate=false → cert issuer is not called even if wired.
	called := false
	core.certIssuer = func(_ context.Context) (*x509.Certificate, []byte, []byte, error) {
		called = true
		return nil, nil, nil, nil
	}
	flags := enrollmentFlags{ReplaceCertificate: false}

	result, err := runEnrollCore(ctx, 1, "host", "host:443", "", flags, core)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Error("certIssuer should not be called when ReplaceCertificate is false")
	}
	findStep(t, result, "replace-certificate", true, "skipped")
}

func TestRunEnrollCore_StepReplaceCertificate_Skipped_NoIssuer(t *testing.T) {
	ctx := context.Background()
	core := minimalCore(t)
	// certIssuer=nil + flag=true → skipped because no issuer.
	flags := enrollmentFlags{ReplaceCertificate: true}

	result, err := runEnrollCore(ctx, 1, "host", "host:443", "", flags, core)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	findStep(t, result, "replace-certificate", true, "skipped")
}

func TestRunEnrollCore_StepReplaceCertificate_Success(t *testing.T) {
	ctx := context.Background()
	core := minimalCore(t)
	newCert := testIssuedCertificate()
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCert.Raw})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCert.Raw})
	core.certIssuer = func(_ context.Context) (*x509.Certificate, []byte, []byte, error) {
		return newCert, leafPEM, caPEM, nil
	}
	flags := enrollmentFlags{ReplaceCertificate: true}

	result, err := runEnrollCore(ctx, 1, "host", "host:443", "", flags, core)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	findStep(t, result, "replace-certificate", true, "")
	if result.PinSPKISHA256 != certSPKISHA256(newCert) {
		t.Errorf("PinSPKISHA256 = %q, want SPKI of new cert", result.PinSPKISHA256)
	}
	if len(result.NewCertPEM) == 0 {
		t.Error("NewCertPEM should be populated after cert replacement")
	}
}

func TestRunEnrollCore_StepReplaceCertificate_IssuerError(t *testing.T) {
	ctx := context.Background()
	core := minimalCore(t)
	wantErr := errors.New("CA unavailable")
	core.certIssuer = func(_ context.Context) (*x509.Certificate, []byte, []byte, error) {
		return nil, nil, nil, wantErr
	}
	flags := enrollmentFlags{ReplaceCertificate: true}

	_, err := runEnrollCore(ctx, 1, "host", "host:443", "", flags, core)
	if err == nil {
		t.Fatal("expected error from certIssuer")
	}
	var enrollErr ErrBMCEnrollFactoryCert
	if !errors.As(err, &enrollErr) {
		t.Errorf("err type = %T, want ErrBMCEnrollFactoryCert", err)
	}
}

func TestRunEnrollCore_StepReplaceCertificate_PinUpdater_NonFatal(t *testing.T) {
	ctx := context.Background()
	core := minimalCore(t)
	newCert := testIssuedCertificate()
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCert.Raw})
	core.certIssuer = func(_ context.Context) (*x509.Certificate, []byte, []byte, error) {
		return newCert, leafPEM, nil, nil
	}
	core.pinUpdater = func(_ context.Context, _ string, _ int, _, _ string) error {
		return errors.New("pin store write failed")
	}
	flags := enrollmentFlags{ReplaceCertificate: true}

	// Pin update error must be non-fatal.
	result, err := runEnrollCore(ctx, 1, "host", "host:443", "", flags, core)
	if err != nil {
		t.Fatalf("pin update error should be non-fatal, got: %v", err)
	}
	step := findStep(t, result, "replace-certificate", true, "")
	if step.Detail == "" {
		t.Error("replace-certificate detail should describe the non-fatal pin failure")
	}
}

func TestRunEnrollCore_StepDNSRegister_Skipped_Flag(t *testing.T) {
	ctx := context.Background()
	core := minimalCore(t)

	result, err := runDefault(ctx, core)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	findStep(t, result, "dns-register", true, "skipped")
}

func TestRunEnrollCore_StepDNSRegister_NoZone_Fatal(t *testing.T) {
	ctx := context.Background()
	core := minimalCore(t)
	core.dnsRegister = func(_ context.Context, _, _, _ string) (string, error) {
		return "lab-node-1-bmc.internal.", nil
	}
	flags := enrollmentFlags{DNSRegister: true}

	// No internalZone supplied → must fail with ErrBMCEnrollNoInternalZone.
	_, err := runEnrollCore(ctx, 1, "host", "host:443", "" /* empty zone */, flags, core)
	if err == nil {
		t.Fatal("expected error when zone is empty")
	}
	var zoneErr ErrBMCEnrollNoInternalZone
	if !errors.As(err, &zoneErr) {
		t.Errorf("err type = %T, want ErrBMCEnrollNoInternalZone", err)
	}
}

func TestRunEnrollCore_StepDNSRegister_Success(t *testing.T) {
	ctx := context.Background()
	core := minimalCore(t)
	const wantDNS = "lab-node-1-bmc.internal."
	core.dnsRegister = func(_ context.Context, _, _, _ string) (string, error) {
		return wantDNS, nil
	}
	flags := enrollmentFlags{DNSRegister: true}

	result, err := runEnrollCore(ctx, 1, "host", "host:443", "internal.", flags, core)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	findStep(t, result, "dns-register", true, "A record")
	if result.DNSName != wantDNS {
		t.Errorf("DNSName = %q, want %q", result.DNSName, wantDNS)
	}
}

func TestRunEnrollCore_StepDNSRegister_Error(t *testing.T) {
	ctx := context.Background()
	core := minimalCore(t)
	core.dnsRegister = func(_ context.Context, _, _, _ string) (string, error) {
		return "", errors.New("DNS write failed")
	}
	flags := enrollmentFlags{DNSRegister: true}

	_, err := runEnrollCore(ctx, 1, "host", "host:443", "internal.", flags, core)
	if err == nil {
		t.Fatal("expected error from dnsRegister")
	}
	// Error wraps as ErrBMCEnrollCredStore (dns-register uses same typed wrapper).
	var credErr ErrBMCEnrollCredStore
	if !errors.As(err, &credErr) {
		t.Errorf("err type = %T, want ErrBMCEnrollCredStore", err)
	}
}

func TestRunEnrollCore_StepDANEPublish_Skipped_NoPlatformCert(t *testing.T) {
	ctx := context.Background()
	core := minimalCore(t)
	core.danePublish = func(_ context.Context, _, _ *x509.Certificate, _ string, _ uint16, _ string) error {
		return &MessageError{Msg: "should not be called"}
	}
	// DANEPublish=true but no new cert → step skipped.
	flags := enrollmentFlags{DANEPublish: true}

	result, err := runEnrollCore(ctx, 1, "host", "host:443", "internal.", flags, core)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	findStep(t, result, "dane-publish", true, "skipped")
}

func TestRunEnrollCore_StepDANEPublish_Success(t *testing.T) {
	ctx := context.Background()
	core := minimalCore(t)
	newCert := testIssuedCertificate()
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCert.Raw})

	daneCalled := false
	core.certIssuer = func(_ context.Context) (*x509.Certificate, []byte, []byte, error) {
		return newCert, leafPEM, nil, nil
	}
	core.danePublish = func(_ context.Context, _, _ *x509.Certificate, _ string, _ uint16, _ string) error {
		daneCalled = true
		return nil
	}
	flags := enrollmentFlags{ReplaceCertificate: true, DANEPublish: true}

	result, err := runEnrollCore(ctx, 1, "host", "host:443", "internal.", flags, core)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !daneCalled {
		t.Error("danePublish should have been called")
	}
	findStep(t, result, "dane-publish", true, "TLSA")
}

func TestRunEnrollCore_StepDANEPublish_NonFatal(t *testing.T) {
	ctx := context.Background()
	core := minimalCore(t)
	newCert := testIssuedCertificate()
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCert.Raw})
	core.certIssuer = func(_ context.Context) (*x509.Certificate, []byte, []byte, error) {
		return newCert, leafPEM, nil, nil
	}
	core.danePublish = func(_ context.Context, _, _ *x509.Certificate, _ string, _ uint16, _ string) error {
		return errors.New("DNS write error")
	}
	flags := enrollmentFlags{ReplaceCertificate: true, DANEPublish: true}

	// DANE errors are non-fatal per spec.
	result, err := runEnrollCore(ctx, 1, "host", "host:443", "internal.", flags, core)
	if err != nil {
		t.Fatalf("DANE error should be non-fatal, got: %v", err)
	}
	// The DANE step should be OK=false but the ceremony continues.
	s := findStep(t, result, "dane-publish", false, "")
	if s.OK {
		t.Error("dane-publish step OK should be false when publish fails")
	}
}

func TestRunEnrollCore_StepDeviceStamp_Success(t *testing.T) {
	ctx := context.Background()
	dev := &entities.Device{ID: 42, State: entities.DeviceStateActivated}
	var savedDev *entities.Device
	core := &enrollCore{
		resolver: &fakeResolver{},
		deviceLoader: func(_ context.Context, _ uint64) (*entities.Device, error) {
			return dev, nil
		},
		deviceSaver: func(_ context.Context, d *entities.Device) error {
			savedDev = d
			return nil
		},
	}

	result, err := runEnrollCore(ctx, 42, "host", "host:443", "internal.", enrollmentFlags{}, core)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	findStep(t, result, "device-stamp", true, "")
	if savedDev == nil {
		t.Fatal("deviceSaver was not called")
	}
	if savedDev.BMCEnrollment == nil {
		t.Fatal("BMCEnrollment should be set on saved device")
	}
	if savedDev.BMCEnrollment.EnrolledAt.IsZero() {
		t.Error("EnrolledAt should be set")
	}
}

func TestRunEnrollCore_StepDeviceStamp_LoadError(t *testing.T) {
	ctx := context.Background()
	wantErr := errors.New("not found")
	core := &enrollCore{
		resolver: &fakeResolver{},
		deviceLoader: func(_ context.Context, _ uint64) (*entities.Device, error) {
			return nil, wantErr
		},
		deviceSaver: func(_ context.Context, _ *entities.Device) error {
			return nil
		},
	}

	_, err := runEnrollCore(ctx, 1, "host", "host:443", "", enrollmentFlags{}, core)
	if err == nil {
		t.Fatal("expected error")
	}
	var stampErr ErrBMCEnrollDeviceLoad
	if !errors.As(err, &stampErr) {
		t.Errorf("err type = %T, want ErrBMCEnrollDeviceLoad", err)
	}
}

func TestRunEnrollCore_StepDeviceStamp_SaveError(t *testing.T) {
	ctx := context.Background()
	dev := &entities.Device{ID: 1}
	wantErr := errors.New("save failed")
	core := &enrollCore{
		resolver: &fakeResolver{},
		deviceLoader: func(_ context.Context, _ uint64) (*entities.Device, error) {
			return dev, nil
		},
		deviceSaver: func(_ context.Context, _ *entities.Device) error {
			return wantErr
		},
	}

	_, err := runEnrollCore(ctx, 1, "host", "host:443", "", enrollmentFlags{}, core)
	if err == nil {
		t.Fatal("expected error")
	}
	var stampErr ErrBMCEnrollDeviceSave
	if !errors.As(err, &stampErr) {
		t.Errorf("err type = %T, want ErrBMCEnrollDeviceSave", err)
	}
}

func TestRunEnrollCore_FullCeremony_HappyPath(t *testing.T) {
	ctx := context.Background()
	factoryCert := testIssuedCertificate()
	newCert := testIssuedCertificate()
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCert.Raw})

	var pinHost string
	var dnsRegistered string
	var daneCalled bool
	dev := &entities.Device{ID: 7, State: entities.DeviceStateActivated}

	core := &enrollCore{
		resolver:    &fakeResolver{},
		certFetcher: &fakeCertFetcher{cert: factoryCert},
		credStore:   newFakeCredStore(),
		certIssuer: func(_ context.Context) (*x509.Certificate, []byte, []byte, error) {
			return newCert, leafPEM, nil, nil
		},
		pinUpdater: func(_ context.Context, host string, _ int, _, _ string) error {
			pinHost = host
			return nil
		},
		dnsRegister: func(_ context.Context, hostname, _, _ string) (string, error) {
			dnsRegistered = hostname + "-bmc.internal."
			return dnsRegistered, nil
		},
		danePublish: func(_ context.Context, _, _ *x509.Certificate, _ string, _ uint16, _ string) error {
			daneCalled = true
			return nil
		},
		deviceLoader: func(_ context.Context, _ uint64) (*entities.Device, error) {
			return dev, nil
		},
		deviceSaver: func(_ context.Context, _ *entities.Device) error {
			return nil
		},
	}

	flags := enrollmentFlags{
		ReplaceCertificate: true,
		DNSRegister:        true,
		DANEPublish:        true,
	}

	result, err := runEnrollCore(ctx, 7, "lab-node-1", "lab-node-1:443", "internal.", flags, core)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify all 7 steps ran.
	wantSteps := []string{
		"trust", "factory-cert", "credentials", "replace-certificate",
		"dns-register", "dane-publish", "device-stamp",
	}
	if len(result.Steps) != len(wantSteps) {
		t.Errorf("len(Steps) = %d, want %d", len(result.Steps), len(wantSteps))
	}
	for i, name := range wantSteps {
		if i >= len(result.Steps) {
			break
		}
		if result.Steps[i].Name != name {
			t.Errorf("Steps[%d].Name = %q, want %q", i, result.Steps[i].Name, name)
		}
		if !result.Steps[i].OK {
			t.Errorf("Steps[%d].OK = false, want true", i)
		}
	}

	// Verify side-effects.
	if pinHost != "lab-node-1" {
		t.Errorf("pinUpdater host = %q, want %q", pinHost, "lab-node-1")
	}
	if dnsRegistered == "" {
		t.Error("dnsRegister was not called")
	}
	if !daneCalled {
		t.Error("danePublish was not called")
	}
	if result.PinSPKISHA256 != certSPKISHA256(newCert) {
		t.Errorf("PinSPKISHA256 = %q, want new cert SPKI", result.PinSPKISHA256)
	}
}

// ---------------------------------------------------------------------------
// TestEffectiveEnrollmentOpts
// ---------------------------------------------------------------------------

func TestEffectiveEnrollmentOpts_Defaults(t *testing.T) {
	cfg := &bmc.Config{Address: "host"}
	flags := effectiveEnrollmentOpts(cfg, nil)

	def := bmc.DefaultEnrollmentConfig()
	if flags.ReplaceCertificate != def.ReplaceCertificate {
		t.Errorf("ReplaceCertificate = %v, want %v", flags.ReplaceCertificate, def.ReplaceCertificate)
	}
	if flags.DNSRegister != def.DNSRegister {
		t.Errorf("DNSRegister = %v, want %v", flags.DNSRegister, def.DNSRegister)
	}
	if flags.DANEPublish != def.DANEPublish {
		t.Errorf("DANEPublish = %v, want %v", flags.DANEPublish, def.DANEPublish)
	}
}

func TestEffectiveEnrollmentOpts_Override(t *testing.T) {
	cfg := &bmc.Config{Address: "host"}
	f := false
	opts := &BMCEnrollOptions{
		ReplaceCertificate: &f,
		DNSRegister:        &f,
	}
	flags := effectiveEnrollmentOpts(cfg, opts)
	if flags.ReplaceCertificate {
		t.Error("ReplaceCertificate should be overridden to false")
	}
	if flags.DNSRegister {
		t.Error("DNSRegister should be overridden to false")
	}
}

// ---------------------------------------------------------------------------
// TestCertSPKISHA256 / TestCertDERSHA256
// ---------------------------------------------------------------------------

func TestCertSPKISHA256_Deterministic(t *testing.T) {
	cert := testIssuedCertificate()
	pin1 := certSPKISHA256(cert)
	pin2 := certSPKISHA256(cert)
	if pin1 != pin2 {
		t.Errorf("certSPKISHA256 non-deterministic: %q != %q", pin1, pin2)
	}
	if len(pin1) != 64 {
		t.Errorf("SPKI SHA-256 hex len = %d, want 64", len(pin1))
	}
}

func TestCertDERSHA256_DifferentFromSPKI(t *testing.T) {
	cert := testIssuedCertificate()
	spki := certSPKISHA256(cert)
	full := certDERSHA256(cert)
	if spki == full {
		t.Error("SPKI pin should differ from full DER fingerprint (rarely equal)")
	}
}

// ---------------------------------------------------------------------------
// TestParsePEMCert
// ---------------------------------------------------------------------------

func TestParsePEMCert_Valid(t *testing.T) {
	cert := testIssuedCertificate()
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	parsed, err := parsePEMCert(pemData)
	if err != nil {
		t.Fatalf("parsePEMCert: %v", err)
	}
	if parsed.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("serial mismatch after parse")
	}
}

func TestParsePEMCert_InvalidPEM(t *testing.T) {
	_, err := parsePEMCert([]byte("not-a-cert"))
	if err == nil {
		t.Error("expected error for invalid PEM input")
	}
}

func TestParsePEMCert_EmptyInput(t *testing.T) {
	_, err := parsePEMCert(nil)
	if err == nil {
		t.Error("expected error for nil input")
	}
}

// ---------------------------------------------------------------------------
// TestEnrollCredentials
// ---------------------------------------------------------------------------

func TestEnrollCredentials_NoCredentialYet_ReturnsNil(t *testing.T) {
	ctx := context.Background()
	cs := newFakeCredStore()
	core := &enrollCore{credStore: cs}

	// credStore.Get returns error (not found) → enrollCredentials must return nil.
	err := enrollCredentials(ctx, 1, "host", enrollmentFlags{}, core)
	if err != nil {
		t.Errorf("enrollCredentials with absent credential: %v", err)
	}
}

func TestEnrollCredentials_ExistingCredential_ReturnsNil(t *testing.T) {
	ctx := context.Background()
	cs := newFakeCredStore()
	// Seed a credential so Get succeeds.
	creds := bmc.NewCredentialsFromStrings("admin", "password")
	if err := cs.Put(ctx, "host", creds); err != nil {
		t.Fatalf("seed: %v", err)
	}

	core := &enrollCore{credStore: cs}
	err := enrollCredentials(ctx, 1, "host", enrollmentFlags{RotatePassword: true}, core)
	if err != nil {
		t.Errorf("enrollCredentials with existing credential: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestBMCEnrollResult_DeviceStampFields
// ---------------------------------------------------------------------------

func TestRunEnrollCore_DeviceStamp_SetsEnrollmentFields(t *testing.T) {
	ctx := context.Background()
	newCert := testIssuedCertificate()
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCert.Raw})
	const dnsName = "lab-node-1-bmc.internal."

	var savedDev *entities.Device
	dev := &entities.Device{ID: 1}
	core := &enrollCore{
		resolver: &fakeResolver{},
		certIssuer: func(_ context.Context) (*x509.Certificate, []byte, []byte, error) {
			return newCert, leafPEM, nil, nil
		},
		dnsRegister: func(_ context.Context, _, _, _ string) (string, error) {
			return dnsName, nil
		},
		danePublish: func(_ context.Context, _, _ *x509.Certificate, _ string, _ uint16, _ string) error {
			return nil
		},
		deviceLoader: func(_ context.Context, _ uint64) (*entities.Device, error) {
			return dev, nil
		},
		deviceSaver: func(_ context.Context, d *entities.Device) error {
			savedDev = d
			return nil
		},
	}

	flags := enrollmentFlags{
		ReplaceCertificate: true,
		DNSRegister:        true,
		DANEPublish:        true,
	}
	_, err := runEnrollCore(ctx, 1, "host", "host:443", "internal.", flags, core)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if savedDev == nil || savedDev.BMCEnrollment == nil {
		t.Fatal("BMCEnrollment not set on device")
	}
	e := savedDev.BMCEnrollment
	if e.PinSPKISHA256 != certSPKISHA256(newCert) {
		t.Errorf("PinSPKISHA256 = %q, want new cert SPKI", e.PinSPKISHA256)
	}
	if e.DNSName != dnsName {
		t.Errorf("DNSName = %q, want %q", e.DNSName, dnsName)
	}
	if !e.TLSAPublished {
		t.Error("TLSAPublished should be true")
	}
	if e.CertSerial == "" {
		t.Error("CertSerial should be set")
	}
	if e.CertNotAfter.IsZero() {
		t.Error("CertNotAfter should be set")
	}
	if e.EnrolledAt.IsZero() {
		t.Error("EnrolledAt should be set")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// findStep asserts a step with the given name exists and that its OK flag
// matches wantOK. If wantDetailContains is non-empty, it must be a substring
// of the step's Detail. Returns the matched step.
func findStep(t *testing.T, result *BMCEnrollResult, name string, wantOK bool, wantDetailContains string) BMCEnrollStep {
	t.Helper()
	for _, s := range result.Steps {
		if s.Name == name {
			if s.OK != wantOK {
				t.Errorf("step %q: OK = %v, want %v (detail: %q)", name, s.OK, wantOK, s.Detail)
			}
			if wantDetailContains != "" && !containsStr(s.Detail, wantDetailContains) {
				t.Errorf("step %q detail = %q, want substring %q", name, s.Detail, wantDetailContains)
			}
			return s
		}
	}
	t.Errorf("step %q not found in result steps %v", name, stepNames(result))
	return BMCEnrollStep{}
}

func containsStr(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}()))
}

func stepNames(result *BMCEnrollResult) []string {
	names := make([]string, len(result.Steps))
	for i, s := range result.Steps {
		names[i] = s.Name
	}
	return names
}
