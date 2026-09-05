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

package entities

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ErrEKCertNotPEM indicates a prestaged EK certificate value that does not
// contain a decodable PEM block.
type ErrEKCertNotPEM struct{}

// Error implements the error interface.
func (e ErrEKCertNotPEM) Error() string {
	return "device: ek certificate is not PEM encoded"
}

// ErrEKCertInvalid indicates a prestaged EK certificate PEM block whose
// contents do not parse as an X.509 certificate.
type ErrEKCertInvalid struct {
	Cause error
}

// Error implements the error interface.
func (e ErrEKCertInvalid) Error() string {
	return fmt.Sprintf("device: ek certificate is not a valid x509 certificate: %v", e.Cause)
}

// Unwrap returns the underlying parse error.
func (e ErrEKCertInvalid) Unwrap() error {
	return e.Cause
}

// ParseEKCertPEM parses a PEM-encoded EK certificate and returns the decoded
// X.509 certificate. It is the single write-side validator for the
// DeviceProfile.EKCert prestage field, shared by every transport DTO seam
// (gRPC, REST, QUIC, MCP, CLI) so a malformed certificate is rejected with
// the same typed error everywhere. Callers that only need validation may
// discard the returned certificate.
func ParseEKCertPEM(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, ErrEKCertNotPEM{}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrEKCertInvalid{Cause: err}
	}
	return cert, nil
}

// EKSerialFromCertPEM derives the platform's EK-serial identity from a
// PEM-encoded EK certificate: the decimal form of the X.509 serial number,
// the same convention DeviceProfile.EKSerial and the boot-time resolver use.
// It is the single place that derivation lives, so the profile resolver, the
// assign-by-device path and every transport agree on what "the device's EK
// serial" is; clients never parse certificates themselves.
func EKSerialFromCertPEM(pemData string) (string, error) {
	cert, err := ParseEKCertPEM(pemData)
	if err != nil {
		return "", err
	}
	return cert.SerialNumber.String(), nil
}

// ValidateEKCertPEM validates an optional prestaged EK certificate value.
// An empty value is valid (no certificate prestaged); a non-empty value must
// parse as a PEM-encoded X.509 certificate.
func ValidateEKCertPEM(pemData string) error {
	if pemData == "" {
		return nil
	}
	_, err := ParseEKCertPEM(pemData)
	return err
}
