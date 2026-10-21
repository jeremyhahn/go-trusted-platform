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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// fakeDBKeySigner is a recording DBKeySigner double. It captures the references
// and digest it is called with so tests can assert both the values forwarded to
// the signer and — critically — that signing is NOT attempted when EAB or EK
// verification fails.
type fakeDBKeySigner struct {
	signCalls   int
	certCalls   int
	lastKeyURI  string
	lastDigest  []byte
	lastCertRef string
	signature   []byte
	certPEM     []byte
	signErr     error
	certErr     error
}

func (f *fakeDBKeySigner) SignDigest(_ context.Context, keyURI string, digest []byte) ([]byte, error) {
	f.signCalls++
	f.lastKeyURI = keyURI
	f.lastDigest = append([]byte(nil), digest...)
	if f.signErr != nil {
		return nil, f.signErr
	}
	return f.signature, nil
}

func (f *fakeDBKeySigner) Certificate(_ context.Context, certRef string) ([]byte, error) {
	f.certCalls++
	f.lastCertRef = certRef
	if f.certErr != nil {
		return nil, f.certErr
	}
	return f.certPEM, nil
}

// remoteSignProfile returns a device profile whose platform config enables
// remote Secure Boot DB signing, optionally bound to a prestaged EK certificate.
func remoteSignProfile(ekCertPEM string) *entities.DeviceProfile {
	return &entities.DeviceProfile{
		ID:     7,
		EKCert: ekCertPEM,
		Config: map[string]interface{}{
			"secure-boot": map[string]interface{}{
				"enabled":     true,
				"resign-mode": "remote",
				"db": map[string]interface{}{
					"cn":       "Trusted Platform Secure Boot DB",
					"store":    "software",
					"key-uri":  "kms://platform/secureboot/db",
					"cert-uri": "kms://platform/secureboot/db-cert",
				},
			},
		},
	}
}

// newSignService builds a Service for sign tests. When profile is nil the
// resolver reports no match.
func newSignService(t *testing.T, profile *entities.DeviceProfile, signer DBKeySigner, eabSvc eab.Service, requireEK bool) *Service {
	t.Helper()
	logger := logging.NewLogger(slog.LevelDebug, nil)
	resolver := &mockProfileResolver{
		findConfigFunc: func(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
			if profile == nil {
				return nil, device.ErrNoMatchingConfig{EKSerial: ekSerial, MAC: mac}
			}
			return profile, nil
		},
	}
	svc, err := NewService(ServiceParams{
		ProfileService: resolver,
		EABService:     eabSvc,
		BaseURL:        "https://platform.example.com",
		RequireEKMatch: boolPtr(requireEK),
		DBKeySigner:    signer,
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("unexpected error creating sign service: %v", err)
	}
	return svc
}

func signRequest(t *testing.T, svc *Service, presentedEKCert string, digest []byte) *SignRequest {
	t.Helper()
	return &SignRequest{
		EKSerial: "ek-123",
		EKCert:   presentedEKCert,
		EABKeyID: "key-1",
		EABHMAC:  validEABHMAC(),
		Nonce:    issueValidNonce(t, svc),
		Digest:   digest,
		KeyRef:   "db",
	}
}

func sha256Digest() []byte { return bytes.Repeat([]byte{0x01}, 32) }

// TestService_SignDigest_HappyPath verifies a fully authenticated request is
// signed with the profile's DB key URI and returns the signature and DB cert.
func TestService_SignDigest_HappyPath(t *testing.T) {
	certPEM, certB64 := newSelfSignedEKCert(t)
	profile := remoteSignProfile(certPEM)
	signer := &fakeDBKeySigner{signature: []byte("sig-bytes"), certPEM: []byte("db-cert-pem")}
	svc := newSignService(t, profile, signer, boundEAB(profile), true)

	digest := sha256Digest()
	resp, err := svc.SignDigest(context.Background(), signRequest(t, svc, certB64, digest))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || string(resp.Signature) != "sig-bytes" {
		t.Fatalf("expected signature %q, got %+v", "sig-bytes", resp)
	}
	if string(resp.CertPEM) != "db-cert-pem" {
		t.Fatalf("expected cert pem %q, got %q", "db-cert-pem", string(resp.CertPEM))
	}
	if signer.signCalls != 1 || signer.certCalls != 1 {
		t.Fatalf("expected 1 sign + 1 cert call, got sign=%d cert=%d", signer.signCalls, signer.certCalls)
	}
	if signer.lastKeyURI != "kms://platform/secureboot/db" {
		t.Fatalf("signer received key uri %q", signer.lastKeyURI)
	}
	if signer.lastCertRef != "Trusted Platform Secure Boot DB" {
		t.Fatalf("signer received cert ref %q", signer.lastCertRef)
	}
	if !bytes.Equal(signer.lastDigest, digest) {
		t.Fatalf("signer received wrong digest: %x", signer.lastDigest)
	}
}

// TestService_SignDigest_BadEABRejectsBeforeSigning verifies a failed EAB
// validation rejects the request and the digest is never signed.
func TestService_SignDigest_BadEABRejectsBeforeSigning(t *testing.T) {
	certPEM, certB64 := newSelfSignedEKCert(t)
	profile := remoteSignProfile(certPEM)
	signer := &fakeDBKeySigner{signature: []byte("sig")}
	eabSvc := &mockEABService{
		validateFunc: func(ctx context.Context, keyID string, hmacKey []byte) (*eab.Credential, error) {
			return nil, errors.New("eab rejected")
		},
	}
	svc := newSignService(t, profile, signer, eabSvc, true)

	_, err := svc.SignDigest(context.Background(), signRequest(t, svc, certB64, sha256Digest()))
	if err == nil {
		t.Fatal("expected error for failed EAB validation")
	}
	var eabFailed ErrEABValidationFailed
	if !errors.As(err, &eabFailed) {
		t.Fatalf("expected ErrEABValidationFailed, got %T: %v", err, err)
	}
	if signer.signCalls != 0 {
		t.Fatalf("signer must not be called when EAB fails (calls=%d)", signer.signCalls)
	}
}

// TestService_SignDigest_EKMismatchRejectsBeforeSigning verifies a mismatched EK
// certificate rejects the request before any signing happens.
func TestService_SignDigest_EKMismatchRejectsBeforeSigning(t *testing.T) {
	prestagedPEM, _ := newSelfSignedEKCert(t)
	_, presentedB64 := newSelfSignedEKCert(t) // different key pair
	profile := remoteSignProfile(prestagedPEM)
	signer := &fakeDBKeySigner{signature: []byte("sig")}
	svc := newSignService(t, profile, signer, boundEAB(profile), true)

	_, err := svc.SignDigest(context.Background(), signRequest(t, svc, presentedB64, sha256Digest()))
	if err == nil {
		t.Fatal("expected error for EK certificate mismatch")
	}
	var mismatch ErrEKCertMismatch
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected ErrEKCertMismatch, got %T: %v", err, err)
	}
	if signer.signCalls != 0 {
		t.Fatalf("signer must not be called when EK verification fails (calls=%d)", signer.signCalls)
	}
}

// TestService_SignDigest_NotConfigured verifies a profile whose resign-mode is
// not "remote" yields ErrRemoteSignNotConfigured without signing.
func TestService_SignDigest_NotConfigured(t *testing.T) {
	profile := &entities.DeviceProfile{
		ID: 8,
		Config: map[string]interface{}{
			"secure-boot": map[string]interface{}{
				"enabled":     true,
				"resign-mode": "local",
				"db": map[string]interface{}{
					"cn":      "Trusted Platform Secure Boot DB",
					"key-uri": "kms://platform/secureboot/db",
				},
			},
		},
	}
	signer := &fakeDBKeySigner{signature: []byte("sig")}
	// EK matching disabled and no prestaged cert: EK binding passes so the
	// not-configured branch is what rejects the request.
	svc := newSignService(t, profile, signer, boundEAB(profile), false)

	_, err := svc.SignDigest(context.Background(), signRequest(t, svc, "", sha256Digest()))
	if err == nil {
		t.Fatal("expected error for non-remote resign mode")
	}
	var notConfigured ErrRemoteSignNotConfigured
	if !errors.As(err, &notConfigured) {
		t.Fatalf("expected ErrRemoteSignNotConfigured, got %T: %v", err, err)
	}
	if signer.signCalls != 0 {
		t.Fatalf("signer must not be called when remote signing is not configured (calls=%d)", signer.signCalls)
	}
}

// TestService_SignDigest_NilSignerUnavailable verifies the endpoint reports a
// typed unavailable error when no DB signer is wired.
func TestService_SignDigest_NilSignerUnavailable(t *testing.T) {
	certPEM, certB64 := newSelfSignedEKCert(t)
	profile := remoteSignProfile(certPEM)
	svc := newSignService(t, profile, nil, boundEAB(profile), true)

	_, err := svc.SignDigest(context.Background(), signRequest(t, svc, certB64, sha256Digest()))
	if err == nil {
		t.Fatal("expected error when no signer is configured")
	}
	var unavailable ErrSignerUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("expected ErrSignerUnavailable, got %T: %v", err, err)
	}
}

// TestService_SignDigest_KMSNotFoundSurfacesAsNotConfigured verifies a signer
// error that is itself ErrRemoteSignNotConfigured (the KMS does not hold the
// configured DB key) remains found through the ErrSignFailed wrapper.
func TestService_SignDigest_KMSNotFoundSurfacesAsNotConfigured(t *testing.T) {
	certPEM, certB64 := newSelfSignedEKCert(t)
	profile := remoteSignProfile(certPEM)
	signer := &fakeDBKeySigner{signErr: ErrRemoteSignNotConfigured{Reason: "db key not provisioned in the KMS"}}
	svc := newSignService(t, profile, signer, boundEAB(profile), true)

	_, err := svc.SignDigest(context.Background(), signRequest(t, svc, certB64, sha256Digest()))
	if err == nil {
		t.Fatal("expected error when the KMS does not hold the db key")
	}
	if !errors.Is(err, ErrRemoteSignNotConfigured{}) {
		t.Fatalf("expected ErrRemoteSignNotConfigured through ErrSignFailed, got %T: %v", err, err)
	}
	var signFailed ErrSignFailed
	if !errors.Is(err, signFailed) {
		t.Fatalf("expected ErrSignFailed wrapping the signer error, got %T: %v", err, err)
	}
}

// TestService_SignDigest_UnrelatedSignerErrorIsNotNotConfigured verifies an
// unrelated signer failure stays a plain ErrSignFailed and is not mistaken
// for ErrRemoteSignNotConfigured.
func TestService_SignDigest_UnrelatedSignerErrorIsNotNotConfigured(t *testing.T) {
	certPEM, certB64 := newSelfSignedEKCert(t)
	profile := remoteSignProfile(certPEM)
	signer := &fakeDBKeySigner{signErr: errors.New("kms unavailable")}
	svc := newSignService(t, profile, signer, boundEAB(profile), true)

	_, err := svc.SignDigest(context.Background(), signRequest(t, svc, certB64, sha256Digest()))
	if err == nil {
		t.Fatal("expected error for an unrelated signer failure")
	}
	if errors.Is(err, ErrRemoteSignNotConfigured{}) {
		t.Fatalf("an unrelated signer error must not be ErrRemoteSignNotConfigured, got: %v", err)
	}
	if !errors.Is(err, ErrSignFailed{}) {
		t.Fatalf("expected ErrSignFailed for an unrelated signer error, got %T: %v", err, err)
	}
}

// TestService_SignDigest_EmptyDigest verifies an empty digest is rejected as a
// bad request before signing.
func TestService_SignDigest_EmptyDigest(t *testing.T) {
	certPEM, certB64 := newSelfSignedEKCert(t)
	profile := remoteSignProfile(certPEM)
	signer := &fakeDBKeySigner{signature: []byte("sig")}
	svc := newSignService(t, profile, signer, boundEAB(profile), true)

	_, err := svc.SignDigest(context.Background(), signRequest(t, svc, certB64, nil))
	if err == nil {
		t.Fatal("expected error for empty digest")
	}
	var invalid ErrInvalidRequest
	if !errors.As(err, &invalid) {
		t.Fatalf("expected ErrInvalidRequest, got %T: %v", err, err)
	}
	if signer.signCalls != 0 {
		t.Fatalf("signer must not be called for an invalid request (calls=%d)", signer.signCalls)
	}
}
