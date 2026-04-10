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

package dns

import "errors"

// Sentinel errors for DNSSEC operations.
// DNSSEC key management is exclusively handled by QuicBaaS KMS.
var (
	// ErrDNSSECConfigNil is returned when the DNSSEC configuration is nil.
	ErrDNSSECConfigNil = errors.New("dnssec: configuration is nil")

	// ErrLoggerNil is returned when the logger is nil.
	ErrLoggerNil = errors.New("dnssec: logger is nil")

	// ErrZoneNameEmpty is returned when the zone name is empty.
	ErrZoneNameEmpty = errors.New("dnssec: zone name is empty")

	// ErrZoneNil is returned when the zone is nil.
	ErrZoneNil = errors.New("dnssec: zone is nil")

	// ErrKeyNotFound is returned when a DNSSEC key cannot be found.
	ErrKeyNotFound = errors.New("dnssec: key not found")

	// ErrInvalidDNSKEY is returned when parsing a DNSKEY record fails.
	ErrInvalidDNSKEY = errors.New("dnssec: invalid DNSKEY record")

	// ErrPrivateKeySerialize is returned when serializing a private key fails.
	ErrPrivateKeySerialize = errors.New("dnssec: failed to serialize private key")

	// ErrEmptyRRSet is returned when attempting to sign an empty RRset.
	ErrEmptyRRSet = errors.New("dnssec: cannot sign empty RRset")

	// ErrInvalidKeyType is returned when an invalid key type is specified.
	ErrInvalidKeyType = errors.New("dnssec: invalid key type, must be 'ksk' or 'zsk'")

	// ErrSigningFailed is returned when zone signing fails.
	ErrSigningFailed = errors.New("dnssec: zone signing failed")

	// ErrInvalidAlgorithm is returned when an unsupported algorithm is specified.
	ErrInvalidAlgorithm = errors.New("dnssec: invalid or unsupported algorithm")

	// ErrKeyGenerationFailed is returned when key generation fails.
	ErrKeyGenerationFailed = errors.New("dnssec: key generation failed")

	// ErrNSECChainFailed is returned when NSEC chain generation fails.
	ErrNSECChainFailed = errors.New("dnssec: NSEC chain generation failed")

	// ErrNSEC3ChainFailed is returned when NSEC3 chain generation fails.
	ErrNSEC3ChainFailed = errors.New("dnssec: NSEC3 chain generation failed")

	// ErrKMSNil is returned when the KMS service is nil.
	ErrKMSNil = errors.New("dnssec: KMS service is nil")

	// ErrKMSKeyGeneration is returned when key generation via KMS fails.
	ErrKMSKeyGeneration = errors.New("dnssec: KMS key generation failed")

	// ErrKMSKeyNotFound is returned when a key cannot be found in KMS.
	ErrKMSKeyNotFound = errors.New("dnssec: key not found in KMS")

	// ErrKMSSigningFailed is returned when signing via KMS fails.
	ErrKMSSigningFailed = errors.New("dnssec: KMS signing failed")

	// ErrKMSKeyDisabled is returned when the requested key is disabled in KMS.
	ErrKMSKeyDisabled = errors.New("dnssec: KMS key is disabled")

	// ErrUnsupportedAlgorithm is returned when a DNSSEC algorithm is not supported by the KMS backend.
	ErrUnsupportedAlgorithm = errors.New("dnssec: algorithm not supported by KMS backend")

	// ErrInvalidKeyStore is returned when an invalid key store type is specified.
	ErrInvalidKeyStore = errors.New("dnssec: invalid key store type")

	// ErrKeyStoreNil is returned when the key store is nil.
	ErrKeyStoreNil = errors.New("dnssec: key store is nil")
)

// DNSSECError provides detailed error information for DNSSEC operations.
type DNSSECError struct {
	// Op is the operation that failed.
	Op string
	// Zone is the zone name associated with the error.
	Zone string
	// Err is the underlying error.
	Err error
}

// Error implements the error interface.
func (e *DNSSECError) Error() string {
	if e.Zone != "" {
		return "dnssec: " + e.Op + " [" + e.Zone + "]: " + e.Err.Error()
	}
	return "dnssec: " + e.Op + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *DNSSECError) Unwrap() error {
	return e.Err
}

// Is implements errors.Is support.
func (e *DNSSECError) Is(target error) bool {
	if target == nil {
		return false
	}
	return errors.Is(e.Err, target)
}
