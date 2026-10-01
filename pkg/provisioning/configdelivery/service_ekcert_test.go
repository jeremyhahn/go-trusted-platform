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

package configdelivery

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// boolPtr returns a pointer to b. Used to drive the tri-state RequireEKMatch
// service parameter (nil -> enforce by default).
func boolPtr(b bool) *bool { return &b }

// newSelfSignedEKCert generates an ECDSA self-signed certificate and returns it
// in both forms the resolver consumes: PEM (prestaged on the profile) and
// standard-base64-encoded DER (presented by the device).
func newSelfSignedEKCert(t *testing.T) (pemStr, b64DER string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test-ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	pemStr = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	b64DER = base64.StdEncoding.EncodeToString(der)
	return pemStr, b64DER
}

// newEKService builds a Service whose resolver always returns profile, with EK
// matching enforcement controlled by requireEK.
func newEKService(t *testing.T, profile *entities.DeviceProfile, requireEK bool) *Service {
	t.Helper()
	logger := logging.NewLogger(slog.LevelDebug, nil)
	resolver := &mockProfileResolver{
		findConfigFunc: func(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
			return profile, nil
		},
	}
	svc, err := NewService(ServiceParams{
		ProfileService: resolver,
		EABService:     boundEAB(profile),
		BaseURL:        "https://platform.example.com",
		RequireEKMatch: boolPtr(requireEK),
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("unexpected error creating service: %v", err)
	}
	return svc
}

func ekConfigRequest(t *testing.T, svc *Service, presentedEKCert string) *ConfigRequest {
	t.Helper()
	return &ConfigRequest{
		EKSerial: "ek-123",
		EKCert:   presentedEKCert,
		EABKeyID: "key-1",
		EABHMAC:  validEABHMAC(),
		Nonce:    issueValidNonce(t, svc),
	}
}

// TestService_ResolveConfig_EKCertMatch verifies a matching EK certificate
// public key releases the resolved config (not a pending session).
func TestService_ResolveConfig_EKCertMatch(t *testing.T) {
	certPEM, certB64 := newSelfSignedEKCert(t)
	profile := &entities.DeviceProfile{
		ID:     1,
		EKCert: certPEM,
		Config: map[string]string{"platform": "config"},
	}
	svc := newEKService(t, profile, true)

	configResp, pendingResp, err := svc.ResolveConfig(context.Background(), ekConfigRequest(t, svc, certB64))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pendingResp != nil {
		t.Fatal("expected nil pending response for an EK match")
	}
	if configResp == nil || configResp.Status != "ok" {
		t.Fatalf("expected config response with status ok, got %+v", configResp)
	}
}

// TestService_ResolveConfig_EKCertMismatch verifies a different EK certificate
// is rejected with ErrEKCertMismatch and no config is returned.
func TestService_ResolveConfig_EKCertMismatch(t *testing.T) {
	prestagedPEM, _ := newSelfSignedEKCert(t)
	_, presentedB64 := newSelfSignedEKCert(t) // different key pair
	profile := &entities.DeviceProfile{
		ID:     1,
		EKCert: prestagedPEM,
		Config: map[string]string{"platform": "config"},
	}
	svc := newEKService(t, profile, true)

	configResp, pendingResp, err := svc.ResolveConfig(context.Background(), ekConfigRequest(t, svc, presentedB64))
	if err == nil {
		t.Fatal("expected error for EK certificate mismatch")
	}
	if configResp != nil || pendingResp != nil {
		t.Fatal("expected no config or pending response on mismatch")
	}
	var mismatch ErrEKCertMismatch
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected ErrEKCertMismatch, got %T: %v", err, err)
	}
}

// TestService_ResolveConfig_EKCertMissingPresented verifies a profile bound to
// a prestaged EK certificate rejects a request that presents none.
func TestService_ResolveConfig_EKCertMissingPresented(t *testing.T) {
	prestagedPEM, _ := newSelfSignedEKCert(t)
	profile := &entities.DeviceProfile{
		ID:     1,
		EKCert: prestagedPEM,
		Config: map[string]string{"platform": "config"},
	}
	svc := newEKService(t, profile, true)

	_, _, err := svc.ResolveConfig(context.Background(), ekConfigRequest(t, svc, ""))
	if err == nil {
		t.Fatal("expected error when no EK certificate is presented")
	}
	var required ErrEKCertRequired
	if !errors.As(err, &required) {
		t.Fatalf("expected ErrEKCertRequired, got %T: %v", err, err)
	}
}

// TestService_ResolveConfig_EKCertParseFailed verifies an undecodable presented
// EK certificate is a client error.
func TestService_ResolveConfig_EKCertParseFailed(t *testing.T) {
	prestagedPEM, _ := newSelfSignedEKCert(t)
	profile := &entities.DeviceProfile{
		ID:     1,
		EKCert: prestagedPEM,
		Config: map[string]string{"platform": "config"},
	}
	svc := newEKService(t, profile, true)

	_, _, err := svc.ResolveConfig(context.Background(), ekConfigRequest(t, svc, "!!!not-base64!!!"))
	if err == nil {
		t.Fatal("expected error for unparseable EK certificate")
	}
	var parseErr ErrEKCertParseFailed
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected ErrEKCertParseFailed, got %T: %v", err, err)
	}
}

// TestService_ResolveConfig_RequireEKMatch_NoPrestaged verifies enforcement
// rejects a matched profile that has no prestaged EK certificate.
func TestService_ResolveConfig_RequireEKMatch_NoPrestaged(t *testing.T) {
	profile := &entities.DeviceProfile{
		ID:     1,
		Config: map[string]string{"platform": "config"},
	}
	svc := newEKService(t, profile, true)

	_, _, err := svc.ResolveConfig(context.Background(), ekConfigRequest(t, svc, ""))
	if err == nil {
		t.Fatal("expected error when EK match is required but nothing is prestaged")
	}
	var required ErrEKCertRequired
	if !errors.As(err, &required) {
		t.Fatalf("expected ErrEKCertRequired, got %T: %v", err, err)
	}
}

// TestService_ResolveConfig_RequireEKMatchFalse_Fallback verifies the opt-out
// path returns config via EK-serial/MAC matching when no cert is prestaged.
func TestService_ResolveConfig_RequireEKMatchFalse_Fallback(t *testing.T) {
	profile := &entities.DeviceProfile{
		ID:     1,
		Config: map[string]string{"platform": "config"},
	}
	svc := newEKService(t, profile, false)

	configResp, pendingResp, err := svc.ResolveConfig(context.Background(), ekConfigRequest(t, svc, ""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pendingResp != nil {
		t.Fatal("expected nil pending response on serial/MAC fallback")
	}
	if configResp == nil || configResp.Status != "ok" {
		t.Fatalf("expected config response with status ok, got %+v", configResp)
	}
}

// TestService_ResolveConfig_RequireEKMatchFalse_StillVerifiesPrestaged verifies
// the opt-out does NOT skip verification when a cert is actually prestaged: a
// prestaged cert is still binding even with enforcement off.
func TestService_ResolveConfig_RequireEKMatchFalse_StillVerifiesPrestaged(t *testing.T) {
	prestagedPEM, _ := newSelfSignedEKCert(t)
	_, presentedB64 := newSelfSignedEKCert(t) // mismatching key
	profile := &entities.DeviceProfile{
		ID:     1,
		EKCert: prestagedPEM,
		Config: map[string]string{"platform": "config"},
	}
	svc := newEKService(t, profile, false)

	_, _, err := svc.ResolveConfig(context.Background(), ekConfigRequest(t, svc, presentedB64))
	if err == nil {
		t.Fatal("expected mismatch error even with enforcement disabled when a cert is prestaged")
	}
	var mismatch ErrEKCertMismatch
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected ErrEKCertMismatch, got %T: %v", err, err)
	}
}

// TestService_PendingResponse_ProvisionURL verifies the pending URL uses the
// canonical provisioning route prefix and configured base URL.
func TestService_PendingResponse_ProvisionURL(t *testing.T) {
	profileSvc := &mockProfileResolver{
		findConfigFunc: func(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
			return nil, device.ErrNoMatchingConfig{EKSerial: ekSerial, MAC: mac}
		},
	}
	// No EAB service: a credential names a profile, so an EAB-carrying device
	// without one is refused (TestService_ResolveConfig_EABWithoutProfile).
	svc := testService(t, profileSvc, nil)

	req := &ConfigRequest{
		EKSerial: "ek-unknown",
		EABKeyID: "key-1",
		EABHMAC:  validEABHMAC(),
		Nonce:    issueValidNonce(t, svc),
	}

	_, pendingResp, err := svc.ResolveConfig(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pendingResp == nil {
		t.Fatal("expected pending response for no match")
	}
	want := "https://platform.example.com/api/v1/provisioning/sessions/" + pendingResp.SessionID
	if pendingResp.ProvisionURL != want {
		t.Fatalf("expected provision URL %q, got %q", want, pendingResp.ProvisionURL)
	}
	if strings.Contains(pendingResp.ProvisionURL, "/provision/sessions/") {
		t.Fatalf("provision URL must not use the legacy /provision/ prefix: %q", pendingResp.ProvisionURL)
	}
}

func TestProvisionBaseURL(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
		want string
	}{
		{name: "host and port", host: "cp.example.com", port: 8443, want: "https://cp.example.com:8443"},
		{name: "host only", host: "cp.example.com", port: 0, want: "https://cp.example.com"},
		{name: "empty host", host: "", port: 8443, want: ""},
		{name: "unset fqdn", host: ".", port: 8443, want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ProvisionBaseURL(tc.host, tc.port); got != tc.want {
				t.Fatalf("ProvisionBaseURL(%q,%d)=%q, want %q", tc.host, tc.port, got, tc.want)
			}
		})
	}
}
