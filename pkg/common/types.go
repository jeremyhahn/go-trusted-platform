package common

import (
	"encoding/asn1"
	"errors"
)

var (
	ErrPasswordsDontMatch = errors.New("trusted-platform: passwords don't match")
	ErrPasswordComplexity = errors.New("trusted-platform: password doesn't meet complexity requirements")
	ErrCorruptWrite       = errors.New("trusted-platform: corrupt write: bytes written don't match source length")
	ErrCorruptCopy        = errors.New("trusted-platform: corrupt copy: destination bytes don't match source length")

	// TCG OIDs:
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-OID-Registry-Version-1.00-Revision-0.74_10July24.pdf
	OIDTCGHWModule               = asn1.ObjectIdentifier{2, 23, 133, 1, 1}
	OIDTCGHWType                 = asn1.ObjectIdentifier{2, 23, 133, 1, 2}
	OIDTCGTPMManufacturer        = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	OIDTCGTPMModel               = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	OIDTCGTPMVersion             = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	OIDTCGSpecification          = asn1.ObjectIdentifier{2, 23, 133, 2, 16}
	OIDTCGVerifiedTPMResidency   = asn1.ObjectIdentifier{2, 23, 133, 11, 1, 1}
	OIDTCGVerifiedTPMFixed       = asn1.ObjectIdentifier{2, 23, 133, 11, 1, 2}
	OIDTCGVerifiedTPMRestricted  = asn1.ObjectIdentifier{2, 23, 133, 11, 1, 3}
	OIDTCGPermanentIdentifier    = asn1.ObjectIdentifier{2, 23, 133, 12, 1}
	OIDTCGPlatformManufacturer   = asn1.ObjectIdentifier{2, 23, 133, 5, 1, 1}
	OIDTCGPlatformManufacturerID = asn1.ObjectIdentifier{2, 23, 133, 5, 1, 2}
	OIDTCGPlatformConfigURL      = asn1.ObjectIdentifier{2, 23, 133, 5, 1, 3}
	OIDTCGPlatformModel          = asn1.ObjectIdentifier{2, 23, 133, 5, 1, 4}
	OIDTCGPlatformVersion        = asn1.ObjectIdentifier{2, 23, 133, 5, 1, 5}
	OIDTCGPlatformSerial         = asn1.ObjectIdentifier{2, 23, 133, 5, 1, 6}
	OIDTCGPlatformConfiguration  = asn1.ObjectIdentifier{2, 23, 133, 5, 1, 7}
	OIDTCGEKCertificate          = asn1.ObjectIdentifier{2, 23, 133, 8, 1}
	OIDTCGPlatformCertificate    = asn1.ObjectIdentifier{2, 23, 133, 8, 2}
	OIDTCGAIKCertificate         = asn1.ObjectIdentifier{2, 23, 133, 8, 3}
	OIDTCGPlatformKeyCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 4}

	OIDTCGTPMFirmwareVersion = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 21911, 1, 1, 3, 1, 1, 5}

	// Trusted Platform OIDs
	OIDTPIssuerKeyStore = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 1}
	OIDTPKeyStore       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 2}
	OIDTPFIPS140        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 3}

	OIDQuantumAlgorithm = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 10}
	OIDQuantumSignature = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 11}

	ROLE_SO    = "so"
	ROLE_ADMIN = "admin"

	AUTH_TYPE_LOCAL  = 0
	AUTH_TYPE_GOOGLE = 1
)
