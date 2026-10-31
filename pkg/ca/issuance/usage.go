package issuance

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
)

// keyUsageNames maps each accepted key usage name, upper-cased, to its bit
// (RFC 5280 §4.2.1.3). Every transport parses through this one table.
var keyUsageNames = map[string]x509.KeyUsage{
	"DIGITALSIGNATURE":   x509.KeyUsageDigitalSignature,
	"DIGITAL_SIGNATURE":  x509.KeyUsageDigitalSignature,
	"CONTENTCOMMITMENT":  x509.KeyUsageContentCommitment,
	"CONTENT_COMMITMENT": x509.KeyUsageContentCommitment,
	"KEYENCIPHERMENT":    x509.KeyUsageKeyEncipherment,
	"KEY_ENCIPHERMENT":   x509.KeyUsageKeyEncipherment,
	"DATAENCIPHERMENT":   x509.KeyUsageDataEncipherment,
	"DATA_ENCIPHERMENT":  x509.KeyUsageDataEncipherment,
	"KEYAGREEMENT":       x509.KeyUsageKeyAgreement,
	"KEY_AGREEMENT":      x509.KeyUsageKeyAgreement,
	"CERTSIGN":           x509.KeyUsageCertSign,
	"CERT_SIGN":          x509.KeyUsageCertSign,
	"CRLSIGN":            x509.KeyUsageCRLSign,
	"CRL_SIGN":           x509.KeyUsageCRLSign,
	"ENCIPHERONLY":       x509.KeyUsageEncipherOnly,
	"ENCIPHER_ONLY":      x509.KeyUsageEncipherOnly,
	"DECIPHERONLY":       x509.KeyUsageDecipherOnly,
	"DECIPHER_ONLY":      x509.KeyUsageDecipherOnly,
}

// extKeyUsageNames maps each accepted extended key usage name, upper-cased,
// to its value (RFC 5280 §4.2.1.12).
var extKeyUsageNames = map[string]x509.ExtKeyUsage{
	"ANY":              x509.ExtKeyUsageAny,
	"SERVERAUTH":       x509.ExtKeyUsageServerAuth,
	"SERVER_AUTH":      x509.ExtKeyUsageServerAuth,
	"CLIENTAUTH":       x509.ExtKeyUsageClientAuth,
	"CLIENT_AUTH":      x509.ExtKeyUsageClientAuth,
	"CODESIGNING":      x509.ExtKeyUsageCodeSigning,
	"CODE_SIGNING":     x509.ExtKeyUsageCodeSigning,
	"EMAILPROTECTION":  x509.ExtKeyUsageEmailProtection,
	"EMAIL_PROTECTION": x509.ExtKeyUsageEmailProtection,
	"TIMESTAMPING":     x509.ExtKeyUsageTimeStamping,
	"TIME_STAMPING":    x509.ExtKeyUsageTimeStamping,
	"OCSPSIGNING":      x509.ExtKeyUsageOCSPSigning,
	"OCSP_SIGNING":     x509.ExtKeyUsageOCSPSigning,
}

// ParseKeyUsages converts key usage names, case-insensitively, into a key
// usage mask. An unrecognized name is refused rather than dropped: a dropped
// name on an isCA request would leave a zero mask, which selects the CA
// profile's full authority.
func ParseKeyUsages(names []string) (x509.KeyUsage, error) {
	var usage x509.KeyUsage
	for _, name := range names {
		bit, ok := keyUsageNames[strings.ToUpper(name)]
		if !ok {
			return 0, ErrUnsupportedUsage{Name: name}
		}
		usage |= bit
	}
	return usage, nil
}

// ParseExtKeyUsages converts extended key usage names, case-insensitively.
// An unrecognized name is refused rather than dropped, so a restriction the
// caller asked for is never silently lifted.
func ParseExtKeyUsages(names []string) ([]x509.ExtKeyUsage, error) {
	var usages []x509.ExtKeyUsage
	for _, name := range names {
		usage, ok := extKeyUsageNames[strings.ToUpper(name)]
		if !ok {
			return nil, ErrUnsupportedUsage{Name: name}
		}
		usages = append(usages, usage)
	}
	return usages, nil
}

// installerUsageNames are the names that ask for an installer certificate:
// the critical tp-pxeInstaller extended key usage extension
// (InstallerMarkerExtension), which carries id-kp-clientAuth beside the
// marker. An x509.ExtKeyUsage cannot name a private OID, so these names are
// held apart from extKeyUsageNames.
var installerUsageNames = map[string]bool{
	"PXEINSTALLER":  true,
	"PXE_INSTALLER": true,
}

// ParseRequestUsages converts an issue request's usage names. An isCA request
// carrying any extended key usage name is refused before conversion with
// ErrCAExtKeyUsageUnsupported: the SDK's CA profile drops the restriction,
// whatever the name (Codex 8662). A leaf request naming PXE_INSTALLER gets
// the installer marker extension, returned for the request's ExtraExtensions,
// and may name no extended key usage beside it but CLIENT_AUTH, which the
// extension already carries (ErrInstallerExtKeyUsage).
func ParseRequestUsages(isCA bool, keyUsages, extKeyUsages []string) (x509.KeyUsage, []x509.ExtKeyUsage, []pkix.Extension, error) {
	if isCA && len(extKeyUsages) > 0 {
		return 0, nil, nil, ErrCAExtKeyUsageUnsupported{}
	}
	keyUsage, err := ParseKeyUsages(keyUsages)
	if err != nil {
		return 0, nil, nil, err
	}
	installer := false
	standard := make([]string, 0, len(extKeyUsages))
	for _, name := range extKeyUsages {
		if installerUsageNames[strings.ToUpper(name)] {
			installer = true
			continue
		}
		standard = append(standard, name)
	}
	extKeyUsage, err := ParseExtKeyUsages(standard)
	if err != nil {
		return 0, nil, nil, err
	}
	if !installer {
		return keyUsage, extKeyUsage, nil, nil
	}
	for i, usage := range extKeyUsage {
		if usage != x509.ExtKeyUsageClientAuth {
			return 0, nil, nil, ErrInstallerExtKeyUsage{Name: standard[i]}
		}
	}
	marker, err := InstallerMarkerExtension()
	if err != nil {
		return 0, nil, nil, err
	}
	return keyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, []pkix.Extension{marker}, nil
}
