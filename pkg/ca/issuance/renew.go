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
	"context"
	"crypto/x509"
	"errors"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmsbackend "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/backend"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/certstore"
	caquicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/ca/quicbaas"
)

// RenewalCA is the part of the CA a renewal changes before it re-issues.
type RenewalCA interface {
	TrustedRoot() (*x509.Certificate, error)
	TrustedIntermediate() (*x509.Certificate, error)
	KeyStore() xkmsbackend.Backend
	CertStore() certstore.CertStore
	RevokeCert(ctx context.Context, cert *x509.Certificate, opts quicbaasca.RevokeOptions) error
}

// SupersedeForRenewal readies the CA to issue a renewal of existing, the
// step every CA transport takes before it calls IssueCertificate with
// keyAttrs. It rotates the leaf key, so the renewal certifies fresh key
// material, then revokes the old certificate and removes it from the
// certificate store, which the CA checks before it issues under the same
// common name.
//
// The key is rotated, not deleted and regenerated. The SDK KMS keeps a
// deleted key's name reserved — go-quicbaas pkg/service/kms.go GenerateKey
// refuses any name it has stored and DeleteKey never releases it — so
// regenerating under the leaf's CN-namespaced key name fails with
// already_exists. Rotation gives that name a new key version, which the CA
// signs when it issues. A leaf whose key the CA keystore does not hold, one
// certified from a caller's CSR, has nothing to rotate: the CA generates its
// key at issuance.
//
// The CA's own root and intermediate certificates are refused: their key is
// the CA signing key, and renewing it here would orphan every certificate
// the CA has issued.
func SupersedeForRenewal(ctx context.Context, ca RenewalCA, existing *x509.Certificate, keyAttrs *xkmssdk.KeyAttributes) error {
	cn := existing.Subject.CommonName
	if isCAOwnCertificate(ca, existing) {
		return &RenewCAOwnCertificateError{CommonName: cn}
	}

	keyStore := ca.KeyStore()
	if keyStore == nil {
		return &RenewStoreUnavailableError{CommonName: cn, Store: "keystore"}
	}
	certStore := ca.CertStore()
	if certStore == nil {
		return &RenewStoreUnavailableError{CommonName: cn, Store: "certificate store"}
	}

	var keyNotFound caquicbaas.ErrKeyNotFound
	_, lookupErr := keyStore.Signer(ctx, keyAttrs)
	switch {
	case lookupErr == nil:
		if _, err := keyStore.RotateKey(ctx, keyAttrs); err != nil {
			return &RenewKeyRotationError{CommonName: cn, Err: err}
		}
	case !errors.As(lookupErr, &keyNotFound):
		return &RenewKeyRotationError{CommonName: cn, Err: lookupErr}
	}

	if err := ca.RevokeCert(ctx, existing, quicbaasca.RevokeOptions{}); err != nil {
		return &RenewSupersedeError{CommonName: cn, Err: err}
	}
	if err := certStore.DeleteCertificate(cn); err != nil {
		return &RenewSupersedeError{CommonName: cn, Err: err}
	}
	return nil
}

// isCAOwnCertificate reports whether cert is the CA's root or intermediate
// certificate.
func isCAOwnCertificate(ca RenewalCA, cert *x509.Certificate) bool {
	if root, err := ca.TrustedRoot(); err == nil && root != nil && root.Equal(cert) {
		return true
	}
	if inter, err := ca.TrustedIntermediate(); err == nil && inter != nil && inter.Equal(cert) {
		return true
	}
	return false
}
