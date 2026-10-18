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
	stdtls "crypto/tls"
	"errors"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// Fakes shared across enroll tests
// =============================================================================

// fakeBMCEnroller records calls and returns configured responses.
type fakeBMCEnroller struct {
	enrollResult *app.BMCEnrollResult
	enrollErr    error
	tlsProvider  bmc.TLSProvider
	lastDeviceID uint64
	lastBMCCfg   *bmc.Config
	lastOpts     *app.BMCEnrollOptions
}

func (f *fakeBMCEnroller) EnrollBMC(ctx context.Context, deviceID uint64, bmcCfg *bmc.Config, opts *app.BMCEnrollOptions) (*app.BMCEnrollResult, error) {
	f.lastDeviceID = deviceID
	f.lastBMCCfg = bmcCfg
	f.lastOpts = opts
	return f.enrollResult, f.enrollErr
}

func (f *fakeBMCEnroller) BMCTLSProvider() bmc.TLSProvider {
	return f.tlsProvider
}

// goodEnrollResult returns a minimal non-nil BMCEnrollResult for happy-path tests.
func goodEnrollResult() *app.BMCEnrollResult {
	return &app.BMCEnrollResult{
		DeviceID:      42,
		Endpoint:      "192.168.1.100:443",
		Hostname:      "bmc-01.example.com",
		PinSPKISHA256: "sha256/abc123",
		FactoryCertMeta: app.BMCFactoryCertMeta{
			Subject:      "CN=bmc-01",
			Issuer:       "CN=factory-ca",
			SerialNumber: "deadbeef",
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			SPKISHA256:   "aabbcc",
			SHA256:       "ddeeff",
			CapturedAt:   time.Now(),
		},
		Steps: []app.BMCEnrollStep{
			{Name: "trust", OK: true},
			{Name: "factory_cert", OK: true},
		},
	}
}

// fakeDeviceProfileSvcForEnroll builds a mockProfileService with a single
// profile that has a BMCConfig attached.
func fakeDeviceProfileSvcForEnroll(id uint64, hasBMC bool) *mockProfileService {
	svc := newMockProfileService()
	profile := &entities.DeviceProfile{ID: id}
	if hasBMC {
		profile.BMC = &entities.BMCConfig{
			Address:  "192.168.1.100",
			Port:     443,
			Username: "admin",
			Password: "secret",
			Protocol: entities.BMCProtocolRedfish,
		}
	}
	svc.profiles[id] = profile
	return svc
}

// =============================================================================
// BMCGRPCService.EnrollBMC tests
// =============================================================================

func TestBMCGRPCEnrollBMC_NoEnrollerReturnsFailedPrecondition(t *testing.T) {
	svc := NewBMCGRPCService(&fakeBMCService{}, nil, slog.Default())
	// enroller is not wired — should return FailedPrecondition.
	_, err := svc.EnrollBMC(context.Background(), &platformv1.BMCEnrollRequest{ProfileId: 1})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %s", st.Code())
	}
}

func TestBMCGRPCEnrollBMC_ZeroProfileIDReturnsInvalidArgument(t *testing.T) {
	svc := NewBMCGRPCService(&fakeBMCService{}, nil, slog.Default())
	svc.SetEnroller(&fakeBMCEnroller{}, fakeDeviceProfileSvcForEnroll(1, true))

	_, err := svc.EnrollBMC(context.Background(), &platformv1.BMCEnrollRequest{ProfileId: 0})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %s", st.Code())
	}
}

func TestBMCGRPCEnrollBMC_ProfileNotFoundReturnsNotFound(t *testing.T) {
	svc := NewBMCGRPCService(&fakeBMCService{}, nil, slog.Default())
	// DeviceProfileService has no profile with ID 99.
	svc.SetEnroller(&fakeBMCEnroller{}, fakeDeviceProfileSvcForEnroll(1, true))

	_, err := svc.EnrollBMC(context.Background(), &platformv1.BMCEnrollRequest{ProfileId: 99})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Fatalf("expected NotFound, got %s", st.Code())
	}
}

func TestBMCGRPCEnrollBMC_EnrollerErrorReturnsInternal(t *testing.T) {
	enroller := &fakeBMCEnroller{enrollErr: errors.New("enrollment boom")}
	svc := NewBMCGRPCService(&fakeBMCService{}, nil, slog.Default())
	svc.SetEnroller(enroller, fakeDeviceProfileSvcForEnroll(5, true))

	_, err := svc.EnrollBMC(context.Background(), &platformv1.BMCEnrollRequest{ProfileId: 5})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Fatalf("expected Internal, got %s", st.Code())
	}
}

func TestBMCGRPCEnrollBMC_HappyPath(t *testing.T) {
	want := goodEnrollResult()
	enroller := &fakeBMCEnroller{enrollResult: want}
	svc := NewBMCGRPCService(&fakeBMCService{}, nil, slog.Default())
	svc.SetEnroller(enroller, fakeDeviceProfileSvcForEnroll(7, true))

	resp, err := svc.EnrollBMC(context.Background(), &platformv1.BMCEnrollRequest{ProfileId: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.DeviceId != want.DeviceID {
		t.Errorf("DeviceId: got %d, want %d", resp.DeviceId, want.DeviceID)
	}
	if resp.Endpoint != want.Endpoint {
		t.Errorf("Endpoint: got %q, want %q", resp.Endpoint, want.Endpoint)
	}
	if len(resp.Steps) != len(want.Steps) {
		t.Errorf("Steps len: got %d, want %d", len(resp.Steps), len(want.Steps))
	}
	// Confirm optional overrides were forwarded as nil when absent.
	if enroller.lastOpts.ReplaceCertificate != nil {
		t.Errorf("expected ReplaceCertificate to be nil")
	}
}

func TestBMCGRPCEnrollBMC_OptionalsForwarded(t *testing.T) {
	want := goodEnrollResult()
	enroller := &fakeBMCEnroller{enrollResult: want}
	svc := NewBMCGRPCService(&fakeBMCService{}, nil, slog.Default())
	svc.SetEnroller(enroller, fakeDeviceProfileSvcForEnroll(8, true))

	tval := true
	resp, err := svc.EnrollBMC(context.Background(), &platformv1.BMCEnrollRequest{
		ProfileId:          8,
		ReplaceCertificate: &tval,
		DnsRegister:        &tval,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if enroller.lastOpts.ReplaceCertificate == nil || !*enroller.lastOpts.ReplaceCertificate {
		t.Error("expected ReplaceCertificate=true to be forwarded")
	}
	if enroller.lastOpts.DNSRegister == nil || !*enroller.lastOpts.DNSRegister {
		t.Error("expected DNSRegister=true to be forwarded")
	}
	if enroller.lastOpts.RotatePassword != nil {
		t.Error("expected RotatePassword to remain nil")
	}
}

// =============================================================================
// deviceProfileStore tests
// =============================================================================

func TestDeviceProfileStore_GetProfileNotFound(t *testing.T) {
	svc := newMockProfileService()
	store := newDeviceProfileStore(svc, nil)

	_, err := store.Get(context.Background(), 999)
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
	var notFound bmc.ErrProfileNotFound
	if !errors.As(err, &notFound) {
		t.Errorf("expected ErrProfileNotFound, got %T: %v", err, err)
	}
}

func TestDeviceProfileStore_GetProfileNoBMCConfig(t *testing.T) {
	svc := fakeDeviceProfileSvcForEnroll(1, false)
	store := newDeviceProfileStore(svc, nil)

	_, err := store.Get(context.Background(), 1)
	if err == nil {
		t.Fatal("expected error when BMC config is nil")
	}
	var notFound bmc.ErrProfileNotFound
	if !errors.As(err, &notFound) {
		t.Errorf("expected ErrProfileNotFound, got %T: %v", err, err)
	}
}

func TestDeviceProfileStore_GetHappyPath(t *testing.T) {
	svc := fakeDeviceProfileSvcForEnroll(3, true)
	store := newDeviceProfileStore(svc, nil)

	cfg, err := store.Get(context.Background(), 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Address != "192.168.1.100" {
		t.Errorf("Address: got %q, want %q", cfg.Address, "192.168.1.100")
	}
	if cfg.Port != 443 {
		t.Errorf("Port: got %d, want 443", cfg.Port)
	}
	if cfg.TLS != nil {
		t.Error("expected TLS provider to be nil when none wired")
	}
}

func TestDeviceProfileStore_GetWithTLSProvider(t *testing.T) {
	svc := fakeDeviceProfileSvcForEnroll(4, true)
	fakeTLS := &fakeTLSProvider{}
	store := newDeviceProfileStore(svc, fakeTLS)

	cfg, err := store.Get(context.Background(), 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TLS != fakeTLS {
		t.Error("expected TLS provider to be wired into config")
	}
}

// fakeTLSProvider is a zero-value TLSProvider for testing.
type fakeTLSProvider struct{}

func (f *fakeTLSProvider) TLSConfig(_ context.Context, _ string) (*stdtls.Config, error) {
	return nil, nil
}

// =============================================================================
// enrollResultToProto tests
// =============================================================================

func TestEnrollResultToProto_NilInput(t *testing.T) {
	resp := enrollResultToProto(nil)
	if resp == nil {
		t.Fatal("expected non-nil response for nil input")
	}
}

func TestEnrollResultToProto_FullResult(t *testing.T) {
	src := goodEnrollResult()
	src.FactoryCertPEM = []byte("CERT PEM")
	src.NewCertPEM = []byte("NEW CERT")
	src.CACertPEM = []byte("CA CERT")

	resp := enrollResultToProto(src)

	if resp.DeviceId != src.DeviceID {
		t.Errorf("DeviceId: got %d, want %d", resp.DeviceId, src.DeviceID)
	}
	if string(resp.FactoryCertPem) != "CERT PEM" {
		t.Errorf("FactoryCertPem: got %q", resp.FactoryCertPem)
	}
	if string(resp.NewCertPem) != "NEW CERT" {
		t.Errorf("NewCertPem: got %q", resp.NewCertPem)
	}
	if len(resp.Steps) != 2 {
		t.Errorf("Steps len: got %d, want 2", len(resp.Steps))
	}
	if resp.FactoryCertMeta == nil {
		t.Fatal("FactoryCertMeta should not be nil")
	}
	if resp.FactoryCertMeta.Subject != src.FactoryCertMeta.Subject {
		t.Errorf("Subject: got %q, want %q", resp.FactoryCertMeta.Subject, src.FactoryCertMeta.Subject)
	}
}

// =============================================================================
// QUIC BMC enrollment tests
// =============================================================================

func TestQUICBMCEnrollResult_NilInput(t *testing.T) {
	resp := quicBMCEnrollResultToResponse(nil)
	if resp == nil {
		t.Fatal("expected non-nil response for nil input")
	}
	if resp.Timestamp == 0 {
		t.Error("expected Timestamp to be set")
	}
}

func TestQUICBMCEnrollResult_FullResult(t *testing.T) {
	src := goodEnrollResult()
	resp := quicBMCEnrollResultToResponse(src)

	if resp.DeviceID != src.DeviceID {
		t.Errorf("DeviceID: got %d, want %d", resp.DeviceID, src.DeviceID)
	}
	if resp.Endpoint != src.Endpoint {
		t.Errorf("Endpoint: got %q, want %q", resp.Endpoint, src.Endpoint)
	}
	if resp.FactoryCertMeta.Subject != src.FactoryCertMeta.Subject {
		t.Errorf("FactoryCertMeta.Subject: got %q", resp.FactoryCertMeta.Subject)
	}
	if len(resp.Steps) != len(src.Steps) {
		t.Errorf("Steps len: got %d, want %d", len(resp.Steps), len(src.Steps))
	}
}

// =============================================================================
// REST adapter tests
// =============================================================================

func TestRESTBMCEnrollerAdapter_EnrollBMCHappyPath(t *testing.T) {
	want := goodEnrollResult()
	want.FactoryCertPEM = []byte("CERT")
	want.NewCertPEM = []byte("NEW")
	want.CACertPEM = []byte("CA")
	enroller := &fakeBMCEnroller{enrollResult: want}
	adapter := newRESTBMCEnrollerAdapter(enroller)

	bmcCfg := &bmc.Config{Address: "10.0.0.1", Port: 443}
	result, err := adapter.EnrollBMC(context.Background(), 7, bmcCfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.DeviceID != want.DeviceID {
		t.Errorf("DeviceID: got %d, want %d", result.DeviceID, want.DeviceID)
	}
	if string(result.FactoryCertPEM) != "CERT" {
		t.Errorf("FactoryCertPEM: got %q", result.FactoryCertPEM)
	}
	if string(result.NewCertPEM) != "NEW" {
		t.Errorf("NewCertPEM: got %q", result.NewCertPEM)
	}
}

func TestRESTBMCEnrollerAdapter_EnrollerError(t *testing.T) {
	enroller := &fakeBMCEnroller{enrollErr: errors.New("boom")}
	adapter := newRESTBMCEnrollerAdapter(enroller)

	_, err := adapter.EnrollBMC(context.Background(), 1, &bmc.Config{}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}
