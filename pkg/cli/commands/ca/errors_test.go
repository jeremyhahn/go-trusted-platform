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

package ca

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestErrDaemonConnectionRequired verifies the error message format.
func TestErrDaemonConnectionRequired(t *testing.T) {
	err := ErrDaemonConnectionRequired{}

	assert.Equal(t, "daemon connection required: this command requires connection to the platform daemon", err.Error())
	assert.True(t, errors.As(err, &ErrDaemonConnectionRequired{}))
}

// TestErrCANotInitialized verifies the error message format.
func TestErrCANotInitialized(t *testing.T) {
	err := ErrCANotInitialized{}

	assert.Equal(t, "certificate authority not initialized", err.Error())
	assert.True(t, errors.As(err, &ErrCANotInitialized{}))
}

// TestErrCANotConfigured verifies the error message format.
func TestErrCANotConfigured(t *testing.T) {
	err := ErrCANotConfigured{}

	assert.Equal(t, "certificate authority not configured", err.Error())
	assert.True(t, errors.As(err, &ErrCANotConfigured{}))
}

// TestErrCertificateNotFound verifies the error message format with serial.
func TestErrCertificateNotFound(t *testing.T) {
	testCases := []struct {
		serial   string
		expected string
	}{
		{
			serial:   "example.com",
			expected: "certificate not found: example.com",
		},
		{
			serial:   "123456789",
			expected: "certificate not found: 123456789",
		},
		{
			serial:   "CN=Test Certificate",
			expected: "certificate not found: CN=Test Certificate",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.serial, func(t *testing.T) {
			err := ErrCertificateNotFound{Serial: tc.serial}
			assert.Equal(t, tc.expected, err.Error())
		})
	}
}

// TestErrInvalidCertificatePath verifies the error message format with path and reason.
func TestErrInvalidCertificatePath(t *testing.T) {
	testCases := []struct {
		path     string
		reason   string
		expected string
	}{
		{
			path:     "/path/to/cert.pem",
			reason:   "file not found",
			expected: "invalid certificate path /path/to/cert.pem: file not found",
		},
		{
			path:     "",
			reason:   "path is empty",
			expected: "invalid certificate path : path is empty",
		},
		{
			path:     "/etc/ssl/cert.der",
			reason:   "unsupported format",
			expected: "invalid certificate path /etc/ssl/cert.der: unsupported format",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.path+"_"+tc.reason, func(t *testing.T) {
			err := ErrInvalidCertificatePath{Path: tc.path, Reason: tc.reason}
			assert.Equal(t, tc.expected, err.Error())
		})
	}
}

// TestErrCertificateExpired verifies the error message format.
func TestErrCertificateExpired(t *testing.T) {
	err := ErrCertificateExpired{
		Subject:   "CN=example.com",
		ExpiredAt: "2024-01-01T00:00:00Z",
	}

	assert.Equal(t, "certificate CN=example.com expired at 2024-01-01T00:00:00Z", err.Error())
}

// TestErrCertificateRevoked verifies the error message format.
func TestErrCertificateRevoked(t *testing.T) {
	err := ErrCertificateRevoked{
		Subject: "CN=example.com",
		Serial:  "123456789",
	}

	assert.Equal(t, "certificate CN=example.com (serial: 123456789) is revoked", err.Error())
}

// TestErrCertificateVerificationFailed verifies the error message format.
func TestErrCertificateVerificationFailed(t *testing.T) {
	testCases := []struct {
		subject  string
		reason   string
		expected string
	}{
		{
			subject:  "CN=example.com",
			reason:   "signature invalid",
			expected: "certificate verification failed for CN=example.com: signature invalid",
		},
		{
			subject:  "CN=test.local",
			reason:   "chain incomplete",
			expected: "certificate verification failed for CN=test.local: chain incomplete",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.subject, func(t *testing.T) {
			err := ErrCertificateVerificationFailed{Subject: tc.subject, Reason: tc.reason}
			assert.Equal(t, tc.expected, err.Error())
		})
	}
}

// TestErrCertificateNotExpiring verifies the error message format.
func TestErrCertificateNotExpiring(t *testing.T) {
	err := ErrCertificateNotExpiring{
		Subject:   "CN=example.com",
		ExpiresIn: "300 days",
	}

	assert.Equal(t, "certificate CN=example.com not expiring soon (expires in 300 days), use --force to renew", err.Error())
}

// TestErrCRLNotFound verifies the error message format.
func TestErrCRLNotFound(t *testing.T) {
	err := ErrCRLNotFound{Issuer: "CN=My CA"}

	assert.Equal(t, "CRL not found for issuer: CN=My CA", err.Error())
}

// TestErrCRLGenerationFailed verifies the error message format.
func TestErrCRLGenerationFailed(t *testing.T) {
	err := ErrCRLGenerationFailed{Reason: "signing key unavailable"}

	assert.Equal(t, "CRL generation failed: signing key unavailable", err.Error())
}

// TestErrCRLExportFailed verifies the error message format.
func TestErrCRLExportFailed(t *testing.T) {
	err := ErrCRLExportFailed{
		Reason: "permission denied",
	}

	assert.Equal(t, "CRL export failed: permission denied", err.Error())
}

// TestErrInvalidOutputFormat verifies the error message format.
func TestErrInvalidOutputFormat(t *testing.T) {
	err := ErrInvalidOutputFormat{Format: "xml"}

	assert.Equal(t, "invalid output format: xml (valid: table, json, yaml)", err.Error())
}

// TestErrInvalidStatus verifies the error message format.
func TestErrInvalidStatus(t *testing.T) {
	err := ErrInvalidStatus{Status: "invalid"}

	assert.Equal(t, "invalid status filter: invalid (valid: valid, revoked, expired, all)", err.Error())
}

// TestErrMissingArgument verifies the error message format.
func TestErrMissingArgument(t *testing.T) {
	testCases := []struct {
		argument string
		expected string
	}{
		{
			argument: "common-name",
			expected: "missing required argument: common-name",
		},
		{
			argument: "serial",
			expected: "missing required argument: serial",
		},
		{
			argument: "certificate-path",
			expected: "missing required argument: certificate-path",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.argument, func(t *testing.T) {
			err := ErrMissingArgument{Argument: tc.argument}
			assert.Equal(t, tc.expected, err.Error())
		})
	}
}

// TestErrInvalidSerial verifies the error message format.
func TestErrInvalidSerial(t *testing.T) {
	testCases := []struct {
		serial   string
		expected string
	}{
		{
			serial:   "abc",
			expected: "invalid serial number: abc",
		},
		{
			serial:   "-1",
			expected: "invalid serial number: -1",
		},
		{
			serial:   "",
			expected: "invalid serial number: ",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.serial, func(t *testing.T) {
			err := ErrInvalidSerial{Serial: tc.serial}
			assert.Equal(t, tc.expected, err.Error())
		})
	}
}

// TestErrInvalidStoreType verifies the error message format.
func TestErrInvalidStoreType(t *testing.T) {
	testCases := []struct {
		store    string
		expected string
	}{
		{
			store:    "invalid",
			expected: "invalid store type: invalid",
		},
		{
			store:    "pkcs12",
			expected: "invalid store type: pkcs12",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.store, func(t *testing.T) {
			err := ErrInvalidStoreType{Store: tc.store}
			assert.Equal(t, tc.expected, err.Error())
		})
	}
}

// TestErrInvalidKeyAlgorithm verifies the error message format.
func TestErrInvalidKeyAlgorithm(t *testing.T) {
	testCases := []struct {
		algorithm string
		expected  string
	}{
		{
			algorithm: "DSA",
			expected:  "invalid key algorithm: DSA",
		},
		{
			algorithm: "RSA-512",
			expected:  "invalid key algorithm: RSA-512",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.algorithm, func(t *testing.T) {
			err := ErrInvalidKeyAlgorithm{Algorithm: tc.algorithm}
			assert.Equal(t, tc.expected, err.Error())
		})
	}
}

// TestErrIssueCertificateFailed verifies the error message format.
func TestErrIssueCertificateFailed(t *testing.T) {
	err := ErrIssueCertificateFailed{Reason: "key generation failed"}

	assert.Equal(t, "failed to issue certificate: key generation failed", err.Error())
}

// TestErrRevokeCertificateFailed verifies the error message format.
func TestErrRevokeCertificateFailed(t *testing.T) {
	err := ErrRevokeCertificateFailed{Reason: "certificate already revoked"}

	assert.Equal(t, "failed to revoke certificate: certificate already revoked", err.Error())
}

// TestErrRenewCertificateFailed verifies the error message format.
func TestErrRenewCertificateFailed(t *testing.T) {
	err := ErrRenewCertificateFailed{Reason: "original certificate not found"}

	assert.Equal(t, "failed to renew certificate: original certificate not found", err.Error())
}

// TestErrCABundleFailed verifies the error message format.
func TestErrCABundleFailed(t *testing.T) {
	err := ErrCABundleFailed{Reason: "CA not initialized"}

	assert.Equal(t, "CA bundle operation failed: CA not initialized", err.Error())
}

// TestErrInitCAFailed verifies the error message format.
func TestErrInitCAFailed(t *testing.T) {
	err := ErrInitCAFailed{Reason: "configuration invalid"}

	assert.Equal(t, "failed to initialize CA: configuration invalid", err.Error())
}

// TestErrGetCAInfoFailed verifies the error message format.
func TestErrGetCAInfoFailed(t *testing.T) {
	err := ErrGetCAInfoFailed{Reason: "CA not accessible"}

	assert.Equal(t, "failed to get CA info: CA not accessible", err.Error())
}

// TestErrInstallCertificatesFailed verifies the error message format.
func TestErrInstallCertificatesFailed(t *testing.T) {
	err := ErrInstallCertificatesFailed{Reason: "insufficient permissions"}

	assert.Equal(t, "failed to install CA certificates: insufficient permissions", err.Error())
}

// TestErrUninstallCertificatesFailed verifies the error message format.
func TestErrUninstallCertificatesFailed(t *testing.T) {
	err := ErrUninstallCertificatesFailed{Reason: "certificates not found in trust store"}

	assert.Equal(t, "failed to uninstall CA certificates: certificates not found in trust store", err.Error())
}

// TestErrCRLEmpty verifies the error message format.
func TestErrCRLEmpty(t *testing.T) {
	err := ErrCRLEmpty{}

	assert.Equal(t, "CRL is empty", err.Error())
}

// TestErrGetCRLFailed verifies the error message format.
func TestErrGetCRLFailed(t *testing.T) {
	err := ErrGetCRLFailed{Reason: "network error"}

	assert.Equal(t, "failed to get CRL: network error", err.Error())
}

// TestErrBundleEmpty verifies the error message format.
func TestErrBundleEmpty(t *testing.T) {
	err := ErrBundleEmpty{}

	assert.Equal(t, "CA bundle is empty", err.Error())
}

// TestErrGetCertificateFailed verifies the error message format.
func TestErrGetCertificateFailed(t *testing.T) {
	err := ErrGetCertificateFailed{Reason: "certificate not found"}

	assert.Equal(t, "failed to get certificate: certificate not found", err.Error())
}

// TestErrVerifyCertificateFailed verifies the error message format.
func TestErrVerifyCertificateFailed(t *testing.T) {
	err := ErrVerifyCertificateFailed{Reason: "chain verification failed"}

	assert.Equal(t, "failed to verify certificate: chain verification failed", err.Error())
}

// TestErrInvalidRevocationReason verifies the error message format.
func TestErrInvalidRevocationReason(t *testing.T) {
	err := ErrInvalidRevocationReason{Reason: "bad-reason"}

	assert.Equal(t, "invalid revocation reason: bad-reason", err.Error())
}

func TestErrReadCSRFailed(t *testing.T) {
	err := ErrReadCSRFailed{Path: "/tmp/fleet.csr", Reason: "no such file or directory"}

	assert.Equal(t, "failed to read certificate signing request /tmp/fleet.csr: no such file or directory", err.Error())
}

func TestErrNoCertificateIssued(t *testing.T) {
	assert.Equal(t, "the CA returned no certificate", ErrNoCertificateIssued{}.Error())
}

func TestErrWriteCertificateFailed(t *testing.T) {
	err := ErrWriteCertificateFailed{Path: "/tmp/leaf.pem", Reason: "permission denied"}

	assert.Equal(t, "failed to write certificate to /tmp/leaf.pem: permission denied", err.Error())
}

func TestWrappedError(t *testing.T) {
	cause := ErrCRLEmpty{}
	err := &WrappedError{Msg: "failed to list certificates", Err: cause}

	assert.Equal(t, "failed to list certificates: "+cause.Error(), err.Error())
	assert.Equal(t, cause, err.Unwrap())
	assert.ErrorIs(t, err, cause)
}

// TestErrNotImplemented verifies the error message format.
func TestErrNotImplemented(t *testing.T) {
	err := ErrNotImplemented{Operation: "dual-mode"}

	assert.Equal(t, "operation not implemented: dual-mode", err.Error())
}

// TestErrorsAreErrors verifies all error types implement the error interface.
func TestErrorsAreErrors(t *testing.T) {
	errs := []error{
		ErrDaemonConnectionRequired{},
		ErrCANotInitialized{},
		ErrCANotConfigured{},
		ErrCertificateNotFound{Serial: "test"},
		ErrInvalidCertificatePath{Path: "/path", Reason: "reason"},
		ErrCertificateExpired{Subject: "test", ExpiredAt: "time"},
		ErrCertificateRevoked{Subject: "test", Serial: "123"},
		ErrCertificateVerificationFailed{Subject: "test", Reason: "reason"},
		ErrCertificateNotExpiring{Subject: "test", ExpiresIn: "days"},
		ErrCRLNotFound{Issuer: "test"},
		ErrCRLGenerationFailed{Reason: "reason"},
		ErrCRLExportFailed{Reason: "reason"},
		ErrCRLEmpty{},
		ErrGetCRLFailed{Reason: "reason"},
		ErrInvalidOutputFormat{Format: "test"},
		ErrInvalidStatus{Status: "test"},
		ErrMissingArgument{Argument: "test"},
		ErrInvalidSerial{Serial: "test"},
		ErrInvalidStoreType{Store: "test"},
		ErrInvalidKeyAlgorithm{Algorithm: "test"},
		ErrInvalidRevocationReason{Reason: "test"},
		ErrIssueCertificateFailed{Reason: "reason"},
		ErrGetCertificateFailed{Reason: "reason"},
		ErrRevokeCertificateFailed{Reason: "reason"},
		ErrRenewCertificateFailed{Reason: "reason"},
		ErrVerifyCertificateFailed{Reason: "reason"},
		ErrCABundleFailed{Reason: "reason"},
		ErrBundleEmpty{},
		ErrInitCAFailed{Reason: "reason"},
		ErrGetCAInfoFailed{Reason: "reason"},
		ErrInstallCertificatesFailed{Reason: "reason"},
		ErrUninstallCertificatesFailed{Reason: "reason"},
		ErrNotImplemented{Operation: "test"},
	}

	for _, err := range errs {
		errStr := err.Error()
		minLen := 20
		if len(errStr) < 20 {
			minLen = len(errStr)
		}
		t.Run(errStr[:minLen], func(t *testing.T) {
			// Verify it implements error interface
			e := err
			assert.NotNil(t, e)
			assert.NotEmpty(t, e.Error())
		})
	}
}

// TestErrorsWithErrorsAs verifies all errors can be detected with errors.As.
func TestErrorsWithErrorsAs(t *testing.T) {
	t.Run("ErrDaemonConnectionRequired", func(t *testing.T) {
		var err error = ErrDaemonConnectionRequired{}
		var target ErrDaemonConnectionRequired
		assert.True(t, errors.As(err, &target))
	})

	t.Run("ErrCANotInitialized", func(t *testing.T) {
		var err error = ErrCANotInitialized{}
		var target ErrCANotInitialized
		assert.True(t, errors.As(err, &target))
	})

	t.Run("ErrCANotConfigured", func(t *testing.T) {
		var err error = ErrCANotConfigured{}
		var target ErrCANotConfigured
		assert.True(t, errors.As(err, &target))
	})

	t.Run("ErrCertificateNotFound", func(t *testing.T) {
		var err error = ErrCertificateNotFound{Serial: "test.com"}
		var target ErrCertificateNotFound
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "test.com", target.Serial)
	})

	t.Run("ErrInvalidCertificatePath", func(t *testing.T) {
		var err error = ErrInvalidCertificatePath{Path: "/test", Reason: "invalid"}
		var target ErrInvalidCertificatePath
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "/test", target.Path)
		assert.Equal(t, "invalid", target.Reason)
	})

	t.Run("ErrCertificateExpired", func(t *testing.T) {
		var err error = ErrCertificateExpired{Subject: "CN=test", ExpiredAt: "2024-01-01"}
		var target ErrCertificateExpired
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "CN=test", target.Subject)
		assert.Equal(t, "2024-01-01", target.ExpiredAt)
	})

	t.Run("ErrCertificateRevoked", func(t *testing.T) {
		var err error = ErrCertificateRevoked{Subject: "CN=test", Serial: "123"}
		var target ErrCertificateRevoked
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "CN=test", target.Subject)
		assert.Equal(t, "123", target.Serial)
	})

	t.Run("ErrCertificateVerificationFailed", func(t *testing.T) {
		var err error = ErrCertificateVerificationFailed{Subject: "CN=test", Reason: "failed"}
		var target ErrCertificateVerificationFailed
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "CN=test", target.Subject)
		assert.Equal(t, "failed", target.Reason)
	})

	t.Run("ErrCertificateNotExpiring", func(t *testing.T) {
		var err error = ErrCertificateNotExpiring{Subject: "CN=test", ExpiresIn: "30 days"}
		var target ErrCertificateNotExpiring
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "CN=test", target.Subject)
		assert.Equal(t, "30 days", target.ExpiresIn)
	})

	t.Run("ErrCRLNotFound", func(t *testing.T) {
		var err error = ErrCRLNotFound{Issuer: "CN=CA"}
		var target ErrCRLNotFound
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "CN=CA", target.Issuer)
	})

	t.Run("ErrCRLGenerationFailed", func(t *testing.T) {
		var err error = ErrCRLGenerationFailed{Reason: "key missing"}
		var target ErrCRLGenerationFailed
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "key missing", target.Reason)
	})

	t.Run("ErrCRLExportFailed", func(t *testing.T) {
		var err error = ErrCRLExportFailed{Reason: "denied"}
		var target ErrCRLExportFailed
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "denied", target.Reason)
	})

	t.Run("ErrCRLEmpty", func(t *testing.T) {
		var err error = ErrCRLEmpty{}
		var target ErrCRLEmpty
		assert.True(t, errors.As(err, &target))
	})

	t.Run("ErrGetCRLFailed", func(t *testing.T) {
		var err error = ErrGetCRLFailed{Reason: "network error"}
		var target ErrGetCRLFailed
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "network error", target.Reason)
	})

	t.Run("ErrInvalidOutputFormat", func(t *testing.T) {
		var err error = ErrInvalidOutputFormat{Format: "xml"}
		var target ErrInvalidOutputFormat
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "xml", target.Format)
	})

	t.Run("ErrInvalidStatus", func(t *testing.T) {
		var err error = ErrInvalidStatus{Status: "bad"}
		var target ErrInvalidStatus
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "bad", target.Status)
	})

	t.Run("ErrMissingArgument", func(t *testing.T) {
		var err error = ErrMissingArgument{Argument: "cn"}
		var target ErrMissingArgument
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "cn", target.Argument)
	})

	t.Run("ErrInvalidSerial", func(t *testing.T) {
		var err error = ErrInvalidSerial{Serial: "bad"}
		var target ErrInvalidSerial
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "bad", target.Serial)
	})

	t.Run("ErrInvalidStoreType", func(t *testing.T) {
		var err error = ErrInvalidStoreType{Store: "bad"}
		var target ErrInvalidStoreType
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "bad", target.Store)
	})

	t.Run("ErrInvalidKeyAlgorithm", func(t *testing.T) {
		var err error = ErrInvalidKeyAlgorithm{Algorithm: "bad"}
		var target ErrInvalidKeyAlgorithm
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "bad", target.Algorithm)
	})

	t.Run("ErrInvalidRevocationReason", func(t *testing.T) {
		var err error = ErrInvalidRevocationReason{Reason: "bad"}
		var target ErrInvalidRevocationReason
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "bad", target.Reason)
	})

	t.Run("ErrIssueCertificateFailed", func(t *testing.T) {
		var err error = ErrIssueCertificateFailed{Reason: "failed"}
		var target ErrIssueCertificateFailed
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "failed", target.Reason)
	})

	t.Run("ErrGetCertificateFailed", func(t *testing.T) {
		var err error = ErrGetCertificateFailed{Reason: "failed"}
		var target ErrGetCertificateFailed
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "failed", target.Reason)
	})

	t.Run("ErrRevokeCertificateFailed", func(t *testing.T) {
		var err error = ErrRevokeCertificateFailed{Reason: "failed"}
		var target ErrRevokeCertificateFailed
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "failed", target.Reason)
	})

	t.Run("ErrRenewCertificateFailed", func(t *testing.T) {
		var err error = ErrRenewCertificateFailed{Reason: "failed"}
		var target ErrRenewCertificateFailed
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "failed", target.Reason)
	})

	t.Run("ErrVerifyCertificateFailed", func(t *testing.T) {
		var err error = ErrVerifyCertificateFailed{Reason: "failed"}
		var target ErrVerifyCertificateFailed
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "failed", target.Reason)
	})

	t.Run("ErrCABundleFailed", func(t *testing.T) {
		var err error = ErrCABundleFailed{Reason: "failed"}
		var target ErrCABundleFailed
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "failed", target.Reason)
	})

	t.Run("ErrBundleEmpty", func(t *testing.T) {
		var err error = ErrBundleEmpty{}
		var target ErrBundleEmpty
		assert.True(t, errors.As(err, &target))
	})

	t.Run("ErrInitCAFailed", func(t *testing.T) {
		var err error = ErrInitCAFailed{Reason: "failed"}
		var target ErrInitCAFailed
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "failed", target.Reason)
	})

	t.Run("ErrGetCAInfoFailed", func(t *testing.T) {
		var err error = ErrGetCAInfoFailed{Reason: "failed"}
		var target ErrGetCAInfoFailed
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "failed", target.Reason)
	})

	t.Run("ErrInstallCertificatesFailed", func(t *testing.T) {
		var err error = ErrInstallCertificatesFailed{Reason: "failed"}
		var target ErrInstallCertificatesFailed
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "failed", target.Reason)
	})

	t.Run("ErrUninstallCertificatesFailed", func(t *testing.T) {
		var err error = ErrUninstallCertificatesFailed{Reason: "failed"}
		var target ErrUninstallCertificatesFailed
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "failed", target.Reason)
	})

	t.Run("ErrNotImplemented", func(t *testing.T) {
		var err error = ErrNotImplemented{Operation: "test"}
		var target ErrNotImplemented
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "test", target.Operation)
	})
}
