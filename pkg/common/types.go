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
	"encoding/asn1"
	"errors"
)

var (
	ErrPasswordsDontMatch = errors.New("trusted-platform: passwords don't match")
	ErrPasswordComplexity = errors.New("trusted-platform: password doesn't meet complexity requirements")
	ErrCorruptWrite       = errors.New("trusted-platform: corrupt write: bytes written don't match source length")
	ErrCorruptCopy        = errors.New("trusted-platform: corrupt copy: destination bytes don't match source length")

	// TCG OIDs are not defined here. The tcg-cap-verifiedTPM*
	// certificate-policy arcs (2.23.133.11.1.1-.3) and tcg-kp-AIKCertificate
	// are reached through the SDK re-export
	// github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca, so the arc a relying
	// party checks has one definition in the stack.

	// Trusted Platform OIDs
	OIDTPIssuerKeyStore = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 1}
	OIDTPKeyStore       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 2}
	OIDTPFIPS140        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 3}

	// tp-networkZone (1.3.6.1.4.1.29377.101.21) is
	// quicbaasca.OIDTPNetworkZone in the same re-export.

	OIDQuantumAlgorithm = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 10}
	OIDQuantumSignature = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 11}

	ROLE_SO    = "so"
	ROLE_ADMIN = "admin"

	// AdminUsername is the username qrdb firstboot gives the system
	// tenant's administrator. It is the subject of the certificate bundle
	// every node comes up with (<quicbaas data-dir>/admin/admin.crt) and
	// the identity the admin-claim ceremony binds an authenticator to.
	AdminUsername = "admin"

	AUTH_TYPE_LOCAL  = 0
	AUTH_TYPE_GOOGLE = 1
)
