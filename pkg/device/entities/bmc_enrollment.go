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

import "time"

// BMCEnrollment records the outcome of a BMC enrollment ceremony. It is
// stamped onto the Device entity after a successful EnrollBMC call and is
// updated on every subsequent re-enrollment. All fields are safe for
// long-term storage; no secret material is included.
type BMCEnrollment struct {
	// EnrolledAt is the timestamp of the most recent successful enrollment.
	EnrolledAt time.Time `yaml:"enrolled_at" json:"enrolled_at"`

	// Host is the BMC address (host only, no port) the enrollment ceremony
	// ran against. It is the join key used to match a platform node's BMC
	// config to its device record (e.g. at cert-renewal time), since the
	// Device entity itself carries no BMC address.
	Host string `yaml:"host" json:"host"`

	// PinSPKISHA256 is the hex-encoded SHA-256 of the SubjectPublicKeyInfo
	// of the BMC's current TLS leaf certificate (platform-issued if
	// ReplaceCertificate was true, factory otherwise). This matches the
	// format used by the trust resolver's TOFU and SPKI strategies so
	// callers can construct a pinned *tls.Config directly from this value.
	PinSPKISHA256 string `yaml:"pin_spki_sha256" json:"pin_spki_sha256"`

	// CertSerial is the serial number of the platform-issued certificate,
	// encoded as a decimal string. Empty when certificate replacement was
	// skipped.
	CertSerial string `yaml:"cert_serial" json:"cert_serial"`

	// CertNotAfter is the expiry of the platform-issued certificate. Zero
	// when certificate replacement was skipped.
	CertNotAfter time.Time `yaml:"cert_not_after" json:"cert_not_after"`

	// DNSName is the fully qualified DNS name registered for this BMC during
	// enrollment (e.g. "lab-node-1-bmc.internal."). Empty when DNS registration
	// was skipped or unavailable.
	DNSName string `yaml:"dns_name" json:"dns_name"`

	// TLSAPublished indicates whether DANE TLSA records were successfully
	// published for this BMC during enrollment.
	TLSAPublished bool `yaml:"tlsa_published" json:"tlsa_published"`

	// FactoryCertSHA256 is the hex-encoded SHA-256 fingerprint of the BMC's
	// factory TLS certificate as it existed at enrollment time. Used for
	// audit and to detect accidental factory resets.
	FactoryCertSHA256 string `yaml:"factory_cert_sha256" json:"factory_cert_sha256"`
}
