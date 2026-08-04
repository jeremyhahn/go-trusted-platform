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

package secureboot

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// CertFetcher fetches a public certificate for a KMS-resident key. It is the
// minimal slice of the go-quicbaas xkms transport client that the remote signer
// needs: the production *xkmssdk.Client satisfies it structurally, and tests
// inject a fake. Accepting a small interface here keeps remote signing testable
// without standing up a full KMS transport.
type CertFetcher interface {
	// GetCertificate returns the stored certificate for keyID on backend.
	GetCertificate(ctx context.Context, backend, keyID string) (*xkmssdk.GetCertificateResponse, error)
}

// NewRemoteSigner returns a Secure Boot DB signer that performs remote
// hash-signing: the private key stays in the KMS and only the message digest is
// round-tripped over the wire. The returned signer's Sign(rand, digest, opts)
// delegates to the KMS via the global XKMS service (ServiceKey), so the key
// never leaves the server. The companion public certificate is fetched from the
// KMS through client.
//
// client MUST be non-nil: a nil client means no KMS is reachable, which is an
// error so callers (the installer's resolveSecureBootSigner branch (b)) fall
// back to on-node generation. In remote mode no private key is ever exported —
// XKMSConfig.ResignMode == ResignModeRemote forces ExportKeys false.
//
// This is the seam consumed POST-install by the Phase 5a kernel-update path and,
// when an SDK client is reachable, optionally at install time.
func NewRemoteSigner(
	ctx context.Context,
	attrs *xkmssdk.KeyAttributes,
	client CertFetcher,
) (crypto.Signer, *x509.Certificate, error) {

	if attrs == nil {
		return nil, nil, ErrNilKeyAttributes
	}
	if client == nil {
		return nil, nil, ErrNilSDKClient
	}

	// Resolve the signing key from the global XKMS service. For a service wired
	// to a remote backend this returns a signer that round-trips only the digest.
	key, err := xkmssdk.ServiceKey(ctx, attrs)
	if err != nil {
		return nil, nil, &SentinelCauseError{Sentinel: ErrRemoteSignerUnavailable, Cause: &MessageError{Msg: fmt.Sprintf("%v", err)}}
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, &SentinelCauseError{Sentinel: ErrRemoteSignerUnavailable, Cause: &MessageError{Msg: fmt.Sprintf("key %q does not implement crypto.Signer", attrs.CN)}}
	}

	cert, err := fetchRemoteCertificate(ctx, attrs, client)
	if err != nil {
		return nil, nil, err
	}
	return signer, cert, nil
}

// fetchRemoteCertificate retrieves and parses the public certificate for attrs
// from the KMS via client. The certificate is keyed by the backend (StoreType)
// and the canonical key identifier (KeyAttributes.KeyID).
func fetchRemoteCertificate(
	ctx context.Context,
	attrs *xkmssdk.KeyAttributes,
	client CertFetcher,
) (*x509.Certificate, error) {

	resp, err := client.GetCertificate(ctx, string(attrs.StoreType), attrs.KeyID())
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrRemoteCertUnavailable, Cause: &MessageError{Msg: fmt.Sprintf("%v", err)}}
	}
	if resp == nil || resp.CertificatePEM == "" {
		return nil, &SentinelCauseError{Sentinel: ErrRemoteCertUnavailable, Cause: &MessageError{Msg: fmt.Sprintf("empty certificate for %q", attrs.KeyID())}}
	}
	block, _ := pem.Decode([]byte(resp.CertificatePEM))
	if block == nil {
		return nil, &SentinelCauseError{Sentinel: ErrRemoteCertUnavailable, Cause: &MessageError{Msg: fmt.Sprintf("certificate PEM for %q did not decode", attrs.KeyID())}}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrRemoteCertUnavailable, Cause: &MessageError{Msg: fmt.Sprintf("%v", err)}}
	}
	return cert, nil
}
