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

package common

import (
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
)

// Identity describes an ACME-managed TLS certificate identity. It is
// reusable across any platform component that issues certs through
// the ACME client (webservice TLS, BMC web-server TLS, future
// identities). Lives in pkg/common so infrastructure packages can
// consume it without pulling in application-layer dependencies.
type Identity struct {
	ACME    *ACMEIdentityConfig                  `yaml:"acme" json:"acme" mapstructure:"acme"`
	SANS    *trustedca.CASubjectAlternativeNames `yaml:"sans" json:"sans" mapstructure:"sans"`
	Subject trustedca.CASubject                  `yaml:"subject" json:"subject" mapstructure:"subject"`
	Valid   int                                  `yaml:"valid" json:"valid" mapstructure:"valid"`
}

// ACMEIdentityConfig defines ACME-related configuration for an Identity.
//
// Schema matches the reference implementation (legacy go-trusted-platform)
// exactly so existing YAML continues to deserialize:
//
//	certificate:
//	  acme:
//	    challenge: http-01
//	    authz-type: dns
//	    authz-value: gw.example.com
//	    renew: 15
//	    cross-sign:
//	      directory: https://acme-staging-v02.api.letsencrypt.org/directory
//	      challenge: http-01
//
// All ACME fields live directly under `acme:` at the top level (Challenge,
// AuthzType, AuthzValue, Renew), and cross-signing uses the `cross-sign:`
// block with `directory:` and `challenge:` keys.
type ACMEIdentityConfig struct {
	// Challenge is the ACME challenge type used when issuing this identity's
	// certificate from the platform ACME client's primary directory.
	// Valid: http-01, dns-01, tls-alpn-01, device-attest-01, enroll-01,
	// endorse-01.
	Challenge string `yaml:"challenge" json:"challenge" mapstructure:"challenge"`

	// AuthzType is the ACME authorization type (dns, ip, permanent-identifier).
	// Defaults to "dns" at runtime when empty.
	AuthzType string `yaml:"authz-type,omitempty" json:"authz_type,omitempty" mapstructure:"authz-type"`

	// AuthzValue is the authorization value (e.g. FQDN for dns, IP for ip).
	// Defaults to the Subject CN at runtime when empty.
	AuthzValue string `yaml:"authz-value,omitempty" json:"authz_value,omitempty" mapstructure:"authz-value"`

	// Renew is the number of days before expiry at which the cert should be
	// renewed by the platform scheduler.
	Renew int `yaml:"renew,omitempty" json:"renew,omitempty" mapstructure:"renew"`

	// CrossSign holds cross-signing configuration. When present, after the
	// initial cert is issued (via Challenge above), the same CSR is submitted
	// to a second ACME directory specified by CrossSign.DirectoryURL using
	// CrossSign.ChallengeType so both the internal and cross-signed chains
	// validate at the TLS handshake.
	CrossSign *trustedca.ACMECrossSignConfig `yaml:"cross-sign,omitempty" json:"cross_sign,omitempty" mapstructure:"cross-sign"`
}
