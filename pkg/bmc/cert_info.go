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

package bmc

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"time"
)

// CertificateInfo represents the JSON-friendly metadata of a BMC web
// server certificate. It mirrors the SDK and proto representations so
// REST, gRPC, and SDK clients all observe an identical shape.
//
// The zero value is not meaningful; instances are produced via
// NewCertificateInfo against an *x509.Certificate returned from a
// CertificateManager.
type CertificateInfo struct {
	// Subject is the certificate subject distinguished name.
	Subject string `json:"subject" yaml:"subject"`
	// Issuer is the certificate issuer distinguished name.
	Issuer string `json:"issuer" yaml:"issuer"`
	// SerialNumber is the certificate serial number in uppercase hex.
	SerialNumber string `json:"serial_number" yaml:"serial_number"`
	// NotBefore is the certificate validity start time.
	NotBefore time.Time `json:"not_before" yaml:"not_before"`
	// NotAfter is the certificate validity end time.
	NotAfter time.Time `json:"not_after" yaml:"not_after"`
	// DaysRemaining is the number of whole days until the certificate
	// expires. Negative when the certificate has already expired.
	DaysRemaining int32 `json:"days_remaining" yaml:"days_remaining"`
	// SubjectAlternativeNames contains the DNS and IP SANs encoded as
	// strings (IPs are formatted via net.IP.String()).
	SubjectAlternativeNames []string `json:"subject_alternative_names,omitempty" yaml:"subject_alternative_names,omitempty"`
	// Fingerprint is the lowercase hex SHA-256 fingerprint of the
	// certificate DER bytes.
	Fingerprint string `json:"fingerprint" yaml:"fingerprint"`
}

// NewCertificateInfo builds a CertificateInfo from an *x509.Certificate.
// Returns nil when cert is nil so callers can use it in a single
// expression. now is used to compute DaysRemaining; tests pass a fixed
// clock and production code passes time.Now().UTC().
func NewCertificateInfo(cert *x509.Certificate, now time.Time) *CertificateInfo {
	if cert == nil {
		return nil
	}

	sans := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	if len(sans) == 0 {
		sans = nil
	}

	sum := sha256.Sum256(cert.Raw)

	serial := ""
	if cert.SerialNumber != nil {
		serial = strings.ToUpper(cert.SerialNumber.Text(16))
	}

	return &CertificateInfo{
		Subject:                 cert.Subject.String(),
		Issuer:                  cert.Issuer.String(),
		SerialNumber:            serial,
		NotBefore:               cert.NotBefore,
		NotAfter:                cert.NotAfter,
		DaysRemaining:           daysRemaining(cert.NotAfter, now),
		SubjectAlternativeNames: sans,
		Fingerprint:             hex.EncodeToString(sum[:]),
	}
}

// daysRemaining returns the number of whole days between now and
// notAfter. Result is negative when notAfter is in the past.
func daysRemaining(notAfter, now time.Time) int32 {
	delta := notAfter.Sub(now)
	return int32(delta / (24 * time.Hour))
}
