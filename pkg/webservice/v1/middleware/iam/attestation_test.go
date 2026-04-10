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

package iam

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	iampb "github.com/jeremyhahn/go-quicbaas/api/proto/iam"
)

// Certificate option functions for creating test certificates with specific extensions.
// Note: We use ExtraExtensions (not Extensions) when creating certificates because
// Extensions is only populated when parsing a certificate, not when creating one.

// withIDevIDExtension adds the TCG IDevID OID extension to a certificate.
func withIDevIDExtension() func(*x509.Certificate) {
	return func(c *x509.Certificate) {
		c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 23, 133, 5, 4, 2},
			Critical: false,
			Value:    []byte("IDevID"),
		})
	}
}

// withIAKExtension adds the TCG IAK OID extension to a certificate.
func withIAKExtension() func(*x509.Certificate) {
	return func(c *x509.Certificate) {
		c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 23, 133, 5, 4, 1},
			Critical: false,
			Value:    []byte("IAK"),
		})
	}
}

// withTPMManufacturerExtension adds the TCG TPM manufacturer OID extension.
func withTPMManufacturerExtension() func(*x509.Certificate) {
	return func(c *x509.Certificate) {
		c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 23, 133, 2, 1},
			Critical: false,
			Value:    []byte("TPM-Manufacturer"),
		})
	}
}

// withTPMModelExtension adds the TCG TPM model OID extension.
func withTPMModelExtension() func(*x509.Certificate) {
	return func(c *x509.Certificate) {
		c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 23, 133, 2, 2},
			Critical: false,
			Value:    []byte("TPM-Model"),
		})
	}
}

// withTPMVersionExtension adds the TCG TPM version OID extension.
func withTPMVersionExtension() func(*x509.Certificate) {
	return func(c *x509.Certificate) {
		c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 23, 133, 2, 3},
			Critical: false,
			Value:    []byte("TPM-Version"),
		})
	}
}

// withDigitalSignatureOnly sets key usage to Digital Signature only.
func withDigitalSignatureOnly() func(*x509.Certificate) {
	return func(c *x509.Certificate) {
		c.KeyUsage = x509.KeyUsageDigitalSignature
	}
}

// withNoDigitalSignature removes the Digital Signature key usage.
func withNoDigitalSignature() func(*x509.Certificate) {
	return func(c *x509.Certificate) {
		c.KeyUsage = x509.KeyUsageKeyEncipherment
	}
}

// TestNewAttestationVerifier tests the NewAttestationVerifier constructor.
func TestNewAttestationVerifier(t *testing.T) {
	t.Run("creates_verifier_with_defaults", func(t *testing.T) {
		verifier := NewAttestationVerifier()

		if verifier == nil {
			t.Fatal("expected verifier to be non-nil")
		}

		av, ok := verifier.(*attestationVerifier)
		if !ok {
			t.Fatal("expected verifier to be *attestationVerifier")
		}

		if av.config.RequireTPMAttestation {
			t.Error("expected RequireTPMAttestation to be false by default")
		}
		if av.config.ValidateIDevID {
			t.Error("expected ValidateIDevID to be false by default")
		}
		if av.config.ValidateIAK {
			t.Error("expected ValidateIAK to be false by default")
		}
	})

	t.Run("creates_verifier_with_options", func(t *testing.T) {
		verifier := NewAttestationVerifier(
			WithRequireTPMAttestation(true),
			WithValidateIDevID(true),
			WithValidateIAK(true),
		)

		if verifier == nil {
			t.Fatal("expected verifier to be non-nil")
		}

		av, ok := verifier.(*attestationVerifier)
		if !ok {
			t.Fatal("expected verifier to be *attestationVerifier")
		}

		if !av.config.RequireTPMAttestation {
			t.Error("expected RequireTPMAttestation to be true")
		}
		if !av.config.ValidateIDevID {
			t.Error("expected ValidateIDevID to be true")
		}
		if !av.config.ValidateIAK {
			t.Error("expected ValidateIAK to be true")
		}
	})
}

// TestAttestationVerifier_IsIDevIDCertificate tests the IsIDevIDCertificate method.
func TestAttestationVerifier_IsIDevIDCertificate(t *testing.T) {
	verifier := NewAttestationVerifier()

	t.Run("returns_true_for_idevid_cert", func(t *testing.T) {
		cert, _ := createTestCertificate(withIDevIDExtension())

		result := verifier.IsIDevIDCertificate(cert)

		if !result {
			t.Error("expected IsIDevIDCertificate to return true for IDevID certificate")
		}
	})

	t.Run("returns_true_for_cert_with_tpm_info_oids", func(t *testing.T) {
		cert, _ := createTestCertificate(
			withTPMManufacturerExtension(),
			withTPMModelExtension(),
			withTPMVersionExtension(),
		)

		result := verifier.IsIDevIDCertificate(cert)

		if !result {
			t.Error("expected IsIDevIDCertificate to return true for certificate with TPM info OIDs")
		}
	})

	t.Run("returns_false_for_regular_cert", func(t *testing.T) {
		cert, _ := createTestCertificate()

		result := verifier.IsIDevIDCertificate(cert)

		if result {
			t.Error("expected IsIDevIDCertificate to return false for regular certificate")
		}
	})

	t.Run("returns_false_for_nil_cert", func(t *testing.T) {
		result := verifier.IsIDevIDCertificate(nil)

		if result {
			t.Error("expected IsIDevIDCertificate to return false for nil certificate")
		}
	})
}

// TestAttestationVerifier_IsIAKCertificate tests the IsIAKCertificate method.
func TestAttestationVerifier_IsIAKCertificate(t *testing.T) {
	verifier := NewAttestationVerifier()

	t.Run("returns_true_for_iak_cert", func(t *testing.T) {
		cert, _ := createTestCertificate(withIAKExtension())

		result := verifier.IsIAKCertificate(cert)

		if !result {
			t.Error("expected IsIAKCertificate to return true for IAK certificate")
		}
	})

	t.Run("returns_true_for_cert_with_tpm_manufacturer_oid", func(t *testing.T) {
		cert, _ := createTestCertificate(withTPMManufacturerExtension())

		result := verifier.IsIAKCertificate(cert)

		if !result {
			t.Error("expected IsIAKCertificate to return true for certificate with TPM manufacturer OID")
		}
	})

	t.Run("returns_false_for_regular_cert", func(t *testing.T) {
		cert, _ := createTestCertificate()

		result := verifier.IsIAKCertificate(cert)

		if result {
			t.Error("expected IsIAKCertificate to return false for regular certificate")
		}
	})

	t.Run("returns_false_for_nil_cert", func(t *testing.T) {
		result := verifier.IsIAKCertificate(nil)

		if result {
			t.Error("expected IsIAKCertificate to return false for nil certificate")
		}
	})
}

// TestAttestationVerifier_VerifyIDevID tests the VerifyIDevID method.
func TestAttestationVerifier_VerifyIDevID(t *testing.T) {
	ctx := context.Background()

	t.Run("succeeds_for_valid_idevid", func(t *testing.T) {
		verifier := NewAttestationVerifier(WithValidateIDevID(true))
		cert, _ := createTestCertificate(
			withIDevIDExtension(),
			withDigitalSignatureOnly(),
		)

		err := verifier.VerifyIDevID(ctx, cert)

		if err != nil {
			t.Errorf("expected no error for valid IDevID certificate, got: %v", err)
		}
	})

	t.Run("succeeds_when_validation_disabled", func(t *testing.T) {
		verifier := NewAttestationVerifier(
			WithValidateIDevID(false),
			WithRequireTPMAttestation(false),
		)
		cert, _ := createTestCertificate(withNoDigitalSignature())

		err := verifier.VerifyIDevID(ctx, cert)

		if err != nil {
			t.Errorf("expected no error when validation disabled, got: %v", err)
		}
	})

	t.Run("fails_for_missing_digital_signature", func(t *testing.T) {
		verifier := NewAttestationVerifier(WithValidateIDevID(true))
		cert, _ := createTestCertificate(
			withIDevIDExtension(),
			withNoDigitalSignature(),
		)

		err := verifier.VerifyIDevID(ctx, cert)

		if err == nil {
			t.Error("expected error for certificate without Digital Signature key usage")
		}
		if _, ok := err.(ErrCertificateInvalid); !ok {
			t.Errorf("expected ErrCertificateInvalid, got %T: %v", err, err)
		}
	})

	t.Run("fails_for_nil_cert", func(t *testing.T) {
		verifier := NewAttestationVerifier(WithValidateIDevID(true))

		err := verifier.VerifyIDevID(ctx, nil)

		if err == nil {
			t.Error("expected error for nil certificate")
		}
		if _, ok := err.(ErrCertificateInvalid); !ok {
			t.Errorf("expected ErrCertificateInvalid, got %T: %v", err, err)
		}
	})

	t.Run("fails_for_cert_without_idevid_oid", func(t *testing.T) {
		verifier := NewAttestationVerifier(WithValidateIDevID(true))
		cert, _ := createTestCertificate(withDigitalSignatureOnly())

		err := verifier.VerifyIDevID(ctx, cert)

		if err == nil {
			t.Error("expected error for certificate without IDevID OID")
		}
	})
}

// TestAttestationVerifier_VerifyIAK tests the VerifyIAK method.
func TestAttestationVerifier_VerifyIAK(t *testing.T) {
	ctx := context.Background()

	t.Run("succeeds_for_valid_iak", func(t *testing.T) {
		verifier := NewAttestationVerifier(WithValidateIAK(true))
		cert, _ := createTestCertificate(
			withIAKExtension(),
			withDigitalSignatureOnly(),
		)

		err := verifier.VerifyIAK(ctx, cert)

		if err != nil {
			t.Errorf("expected no error for valid IAK certificate, got: %v", err)
		}
	})

	t.Run("succeeds_when_validation_disabled", func(t *testing.T) {
		verifier := NewAttestationVerifier(
			WithValidateIAK(false),
			WithRequireTPMAttestation(false),
		)
		cert, _ := createTestCertificate(withNoDigitalSignature())

		err := verifier.VerifyIAK(ctx, cert)

		if err != nil {
			t.Errorf("expected no error when validation disabled, got: %v", err)
		}
	})

	t.Run("fails_for_nil_cert", func(t *testing.T) {
		verifier := NewAttestationVerifier(WithValidateIAK(true))

		err := verifier.VerifyIAK(ctx, nil)

		if err == nil {
			t.Error("expected error for nil certificate")
		}
		if _, ok := err.(ErrCertificateInvalid); !ok {
			t.Errorf("expected ErrCertificateInvalid, got %T: %v", err, err)
		}
	})

	t.Run("fails_for_missing_digital_signature", func(t *testing.T) {
		verifier := NewAttestationVerifier(WithValidateIAK(true))
		cert, _ := createTestCertificate(
			withIAKExtension(),
			withNoDigitalSignature(),
		)

		err := verifier.VerifyIAK(ctx, cert)

		if err == nil {
			t.Error("expected error for certificate without Digital Signature key usage")
		}
		if _, ok := err.(ErrCertificateInvalid); !ok {
			t.Errorf("expected ErrCertificateInvalid, got %T: %v", err, err)
		}
	})

	t.Run("fails_for_cert_without_iak_oid", func(t *testing.T) {
		verifier := NewAttestationVerifier(WithValidateIAK(true))
		cert, _ := createTestCertificate(withDigitalSignatureOnly())

		err := verifier.VerifyIAK(ctx, cert)

		if err == nil {
			t.Error("expected error for certificate without IAK OID")
		}
	})
}

// TestAuthMiddleware_RequireTPMAttestation tests the RequireTPMAttestation middleware.
func TestAuthMiddleware_RequireTPMAttestation(t *testing.T) {
	logger := createTestLogger()
	iamService := newMockIAMServiceClient()

	t.Run("allows_request_with_verified_attestation", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		config := AuthConfig{}
		middleware, err := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)
		if err != nil {
			t.Fatalf("failed to create middleware: %v", err)
		}

		session := NewIAMSessionWithAttestation(
			&iampb.User{
				Id:       "user-123",
				TenantId: "tenant-456",
			},
			false,
			time.Time{},
			true,
			time.Now(),
			"device-001",
		)

		called := false
		handler := middleware.RequireTPMAttestation()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if !called {
			t.Error("expected handler to be called for request with verified attestation")
		}
	})

	t.Run("blocks_request_without_attestation", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		config := AuthConfig{}
		middleware, err := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)
		if err != nil {
			t.Fatalf("failed to create middleware: %v", err)
		}

		session := NewIAMSessionWithAttestation(
			&iampb.User{
				Id:       "user-123",
				TenantId: "tenant-456",
			},
			false,
			time.Time{},
			false, // attestation not verified
			time.Time{},
			"",
		)

		called := false
		handler := middleware.RequireTPMAttestation()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if called {
			t.Error("expected handler not to be called for request without verified attestation")
		}
		if httpWriter.getError403Count() != 1 {
			t.Error("expected Error403 to be called for unverified attestation")
		}
	})

	t.Run("returns_401_without_session", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		config := AuthConfig{}
		middleware, err := NewAuthMiddleware(logger, httpWriter, config, iamService, nil, nil, nil)
		if err != nil {
			t.Fatalf("failed to create middleware: %v", err)
		}

		called := false
		handler := middleware.RequireTPMAttestation()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if called {
			t.Error("expected handler not to be called without session")
		}
		if httpWriter.getError401Count() != 1 {
			t.Error("expected Error401 to be called when session is missing")
		}
	})
}

// TestIAMSession_AttestationMethods tests the attestation-related methods on IAMSession.
func TestIAMSession_AttestationMethods(t *testing.T) {
	t.Run("attestation_verified_returns_correct_value", func(t *testing.T) {
		// Test with attestation verified
		sessionVerified := NewIAMSessionWithAttestation(
			&iampb.User{
				Id:       "user-123",
				TenantId: "tenant-456",
			},
			false,
			time.Time{},
			true,
			time.Now(),
			"device-001",
		)

		if !sessionVerified.IsAttestationVerified() {
			t.Error("expected IsAttestationVerified to return true for verified session")
		}

		// Test with attestation not verified
		sessionNotVerified := NewIAMSessionWithAttestation(
			&iampb.User{
				Id:       "user-123",
				TenantId: "tenant-456",
			},
			false,
			time.Time{},
			false,
			time.Time{},
			"",
		)

		if sessionNotVerified.IsAttestationVerified() {
			t.Error("expected IsAttestationVerified to return false for unverified session")
		}
	})

	t.Run("attestation_time_returns_correct_value", func(t *testing.T) {
		attestationTime := time.Now().Add(-1 * time.Hour)
		session := NewIAMSessionWithAttestation(
			&iampb.User{
				Id:       "user-123",
				TenantId: "tenant-456",
			},
			false,
			time.Time{},
			true,
			attestationTime,
			"device-001",
		)

		result := session.AttestationTime()

		if !result.Equal(attestationTime) {
			t.Errorf("expected AttestationTime to return %v, got %v", attestationTime, result)
		}
	})

	t.Run("device_id_returns_correct_value", func(t *testing.T) {
		expectedDeviceID := "device-abc-123"
		session := NewIAMSessionWithAttestation(
			&iampb.User{
				Id:       "user-123",
				TenantId: "tenant-456",
			},
			false,
			time.Time{},
			true,
			time.Now(),
			expectedDeviceID,
		)

		result := session.DeviceID()

		if result != expectedDeviceID {
			t.Errorf("expected DeviceID to return %q, got %q", expectedDeviceID, result)
		}
	})

	t.Run("regular_session_has_no_attestation", func(t *testing.T) {
		session := NewIAMSession(&iampb.User{
			Id:       "user-123",
			TenantId: "tenant-456",
		})

		if session.IsAttestationVerified() {
			t.Error("expected regular session to have IsAttestationVerified return false")
		}
		if !session.AttestationTime().IsZero() {
			t.Error("expected regular session to have zero AttestationTime")
		}
		if session.DeviceID() != "" {
			t.Error("expected regular session to have empty DeviceID")
		}
	})
}

// TestAttestationConfig_Options tests the attestation configuration options.
func TestAttestationConfig_Options(t *testing.T) {
	t.Run("with_require_tpm_attestation", func(t *testing.T) {
		config := &AttestationConfig{}
		opt := WithRequireTPMAttestation(true)
		opt(config)

		if !config.RequireTPMAttestation {
			t.Error("expected RequireTPMAttestation to be true")
		}
	})

	t.Run("with_validate_idevid", func(t *testing.T) {
		config := &AttestationConfig{}
		opt := WithValidateIDevID(true)
		opt(config)

		if !config.ValidateIDevID {
			t.Error("expected ValidateIDevID to be true")
		}
	})

	t.Run("with_validate_iak", func(t *testing.T) {
		config := &AttestationConfig{}
		opt := WithValidateIAK(true)
		opt(config)

		if !config.ValidateIAK {
			t.Error("expected ValidateIAK to be true")
		}
	})
}

// TestAttestationVerifier_WrapAttestationError tests error wrapping functionality.
func TestAttestationVerifier_WrapAttestationError(t *testing.T) {
	// Note: wrapAttestationError is not exported, so we test it indirectly
	// through the VerifyIDevID and VerifyIAK methods

	t.Run("wraps_nil_certificate_error", func(t *testing.T) {
		verifier := NewAttestationVerifier(WithValidateIDevID(true))
		ctx := context.Background()

		err := verifier.VerifyIDevID(ctx, nil)

		if err == nil {
			t.Fatal("expected error for nil certificate")
		}
		certErr, ok := err.(ErrCertificateInvalid)
		if !ok {
			t.Errorf("expected ErrCertificateInvalid, got %T", err)
		}
		if certErr.Reason != "nil certificate provided" {
			t.Errorf("unexpected error reason: %s", certErr.Reason)
		}
	})

	t.Run("wraps_invalid_key_usage_error", func(t *testing.T) {
		verifier := NewAttestationVerifier(WithValidateIDevID(true))
		ctx := context.Background()

		cert, _ := createTestCertificate(
			withIDevIDExtension(),
			withNoDigitalSignature(),
		)

		err := verifier.VerifyIDevID(ctx, cert)

		if err == nil {
			t.Fatal("expected error for invalid key usage")
		}
		if _, ok := err.(ErrCertificateInvalid); !ok {
			t.Errorf("expected ErrCertificateInvalid, got %T", err)
		}
	})
}

// TestOIDConstants tests the OID constant definitions.
func TestOIDConstants(t *testing.T) {
	t.Run("idevid_oid_is_correct", func(t *testing.T) {
		expected := asn1.ObjectIdentifier{2, 23, 133, 5, 4, 2}
		if !OIDTCGIDevID.Equal(expected) {
			t.Errorf("expected OIDTCGIDevID to be %v, got %v", expected, OIDTCGIDevID)
		}
	})

	t.Run("iak_oid_is_correct", func(t *testing.T) {
		expected := asn1.ObjectIdentifier{2, 23, 133, 5, 4, 1}
		if !OIDTCGIAK.Equal(expected) {
			t.Errorf("expected OIDTCGIAK to be %v, got %v", expected, OIDTCGIAK)
		}
	})

	t.Run("manufacturer_oid_is_correct", func(t *testing.T) {
		expected := asn1.ObjectIdentifier{2, 23, 133, 2, 1}
		if !OIDTCGManufacturer.Equal(expected) {
			t.Errorf("expected OIDTCGManufacturer to be %v, got %v", expected, OIDTCGManufacturer)
		}
	})

	t.Run("model_oid_is_correct", func(t *testing.T) {
		expected := asn1.ObjectIdentifier{2, 23, 133, 2, 2}
		if !OIDTCGModel.Equal(expected) {
			t.Errorf("expected OIDTCGModel to be %v, got %v", expected, OIDTCGModel)
		}
	})

	t.Run("version_oid_is_correct", func(t *testing.T) {
		expected := asn1.ObjectIdentifier{2, 23, 133, 2, 3}
		if !OIDTCGVersion.Equal(expected) {
			t.Errorf("expected OIDTCGVersion to be %v, got %v", expected, OIDTCGVersion)
		}
	})
}

// TestAttestationVerifier_MultipleExtensions tests certificates with multiple TCG extensions.
func TestAttestationVerifier_MultipleExtensions(t *testing.T) {
	verifier := NewAttestationVerifier()

	t.Run("detects_idevid_with_all_tpm_extensions", func(t *testing.T) {
		cert, _ := createTestCertificate(
			withIDevIDExtension(),
			withTPMManufacturerExtension(),
			withTPMModelExtension(),
			withTPMVersionExtension(),
		)

		if !verifier.IsIDevIDCertificate(cert) {
			t.Error("expected IsIDevIDCertificate to return true")
		}
	})

	t.Run("detects_iak_with_manufacturer_extension", func(t *testing.T) {
		cert, _ := createTestCertificate(
			withIAKExtension(),
			withTPMManufacturerExtension(),
		)

		if !verifier.IsIAKCertificate(cert) {
			t.Error("expected IsIAKCertificate to return true")
		}
	})

	t.Run("cert_with_both_idevid_and_iak_detected_as_idevid", func(t *testing.T) {
		cert, _ := createTestCertificate(
			withIDevIDExtension(),
			withIAKExtension(),
		)

		if !verifier.IsIDevIDCertificate(cert) {
			t.Error("expected IsIDevIDCertificate to return true")
		}
		if !verifier.IsIAKCertificate(cert) {
			t.Error("expected IsIAKCertificate to return true")
		}
	})
}
