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

package issuance

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// OIDPXEInstaller is tp-pxeInstaller, the private extended key usage that
// marks a certificate as a PXE installer's (RFC 5280 §4.2.1.12, issue #1362).
// The mTLS peer authenticators read it from the certificate itself, so an
// installer stays restricted to pxe:complete on a daemon that has restarted,
// or on another instance, without the PXE binding history.
var OIDPXEInstaller = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 22}

// oidExtensionExtKeyUsage is the extended key usage extension (RFC 5280
// §4.2.1.12).
var oidExtensionExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

// oidExtKeyUsageClientAuth is id-kp-clientAuth (RFC 5280 §4.2.1.12).
var oidExtKeyUsageClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}

// InstallerMarkerExtension is the extended key usage extension an installer
// certificate is signed with: critical, carrying id-kp-clientAuth, so TLS
// client verification still accepts the certificate, and tp-pxeInstaller.
// Being critical, a relying party that does not know the marker rejects the
// certificate rather than treating it as an unrestricted client.
func InstallerMarkerExtension() (pkix.Extension, error) {
	value, err := asn1.Marshal([]asn1.ObjectIdentifier{oidExtKeyUsageClientAuth, OIDPXEInstaller})
	if err != nil {
		return pkix.Extension{}, &InstallerMarkerEncodeError{Err: err}
	}
	return pkix.Extension{Id: oidExtensionExtKeyUsage, Critical: true, Value: value}, nil
}

// HasInstallerMarker reports whether cert's extended key usage carries
// tp-pxeInstaller. Every caller that classifies or admits an installer uses it.
func HasInstallerMarker(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(OIDPXEInstaller) {
			return true
		}
	}
	return false
}
