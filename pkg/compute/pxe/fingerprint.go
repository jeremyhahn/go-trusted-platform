// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package pxe

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
)

// CertificateFingerprintOf returns the SHA-256 of the certificate's DER
// encoding in lowercase hex: the form DeviceInfo.CertificateFingerprint is
// stored in, and the form `openssl x509 -fingerprint -sha256` prints once its
// colons are dropped.
func CertificateFingerprintOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// NormalizeCertificateFingerprint returns an operator-supplied SHA-256
// certificate fingerprint in the stored form: colon separators removed,
// lowercase. Anything that is not 32 bytes of hex, the empty string
// included, is an error.
func NormalizeCertificateFingerprint(fingerprint string) (string, error) {
	if fingerprint == "" {
		return "", ErrInvalidCertificateFingerprint{Fingerprint: fingerprint, Reason: "required"}
	}
	normalized := strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
	raw, err := hex.DecodeString(normalized)
	if err != nil {
		return "", ErrInvalidCertificateFingerprint{Fingerprint: fingerprint, Reason: "not hex"}
	}
	if len(raw) != sha256.Size {
		return "", ErrInvalidCertificateFingerprint{Fingerprint: fingerprint, Reason: "not a SHA-256 digest (32 bytes)"}
	}
	return normalized, nil
}
