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

package app

import (
	"bytes"
	"crypto/x509"
	"errors"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// interimIAKCN is the name go-xkms stores an IAK certificate under when the
// IAK has no configured CN: the name every node provisioned during the #74
// interim holds its certificate under.
const interimIAKCN = "default-device-id"

// iakAttributer is the TPM surface the migration reads: the IAK's settled
// attributes, whose CN is the name the certificate is expected under and
// whose public key is what proves a stored certificate is this IAK's.
type iakAttributer interface {
	IAKAttributes() (*xkmssdk.KeyAttributes, error)
}

// migrateInterimIAKCertificate carries a node provisioned under the #74
// interim across the #78 rename. Such a node holds its IAK certificate in
// the certificate store under interimIAKCN; after the rename the TPM
// module looks it up under `<hostname>-iak`, does not find it, and the
// identity-completeness check would then re-issue an identity the node
// already has. The migration copies the entry to its new name once,
// after proving the certificate's public key is the resident IAK's, so an
// unrelated certificate that happens to sit under the interim name is
// never adopted. The interim entry is left in place: it is inert once the
// new name resolves, and removing it buys nothing a rollback would not
// then miss.
//
// It reports whether a certificate was migrated. A node with no IAK handle
// (never provisioned), with the certificate already under its new name, or
// with nothing under the interim name is not an error: there is nothing to
// migrate.
func migrateInterimIAKCertificate(tpm iakAttributer, store xkmssdk.TPMCertificateStorer, logger *logging.Logger) (bool, error) {
	if tpm == nil || store == nil {
		return false, nil
	}
	iakAttrs, err := tpm.IAKAttributes()
	if err != nil || iakAttrs == nil || iakAttrs.CN == "" || iakAttrs.CN == interimIAKCN {
		return false, nil
	}
	if _, err := store.Get(iakAttrs); err == nil {
		return false, nil
	}

	interim := *iakAttrs
	interim.CN = interimIAKCN
	cert, err := store.Get(&interim)
	if err != nil {
		if errors.Is(err, xkmssdk.ErrTPMStoreCertNotFound) {
			return false, nil
		}
		return false, &WrappedError{Msg: "reading the IAK certificate stored under the interim name", Err: err}
	}

	if !certificateMatchesKey(cert, iakAttrs) {
		logger.Warn("The certificate stored under the interim IAK name is not the resident IAK's; leaving it alone",
			"interim_cn", interimIAKCN, "iak_cn", iakAttrs.CN)
		return false, nil
	}

	if err := store.Save(iakAttrs, cert); err != nil {
		return false, &WrappedError{Msg: "storing the IAK certificate under " + iakAttrs.CN, Err: err}
	}
	logger.Info("Migrated the IAK certificate from the interim name (#78)",
		"from", interimIAKCN, "to", iakAttrs.CN)
	return true, nil
}

// certificateMatchesKey reports whether cert carries the public key the
// TPM attributes describe. The attributes hold the key as PKIX DER
// (TPMAttributes.PublicKeyBytes), the same encoding
// x509.MarshalPKIXPublicKey produces from the certificate.
func certificateMatchesKey(cert *x509.Certificate, attrs *xkmssdk.KeyAttributes) bool {
	if cert == nil || attrs == nil || attrs.TPMAttributes == nil || len(attrs.TPMAttributes.PublicKeyBytes) == 0 {
		return false
	}
	certPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return false
	}
	return bytes.Equal(certPub, attrs.TPMAttributes.PublicKeyBytes)
}
