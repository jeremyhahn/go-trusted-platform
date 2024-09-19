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

	// TCG OIDs
	OIDTCGHWModule               = asn1.ObjectIdentifier{2, 23, 133, 1, 1}
	OIDTCGHWType                 = asn1.ObjectIdentifier{2, 23, 133, 1, 2}
	OIDTCGManufacturer           = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	OIDTCGModel                  = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	OIDTCGVersion                = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
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
	OIDTCGPlatformKeyCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 4}

	// Trusted Platform OIDs
	OIDTPIssuerKeyStore = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 1}
	OIDTPKeyStore       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 2}

	ROLE_SO    = "so"
	ROLE_ADMIN = "admin"

	AUTH_TYPE_LOCAL  = 0
	AUTH_TYPE_GOOGLE = 1
)
