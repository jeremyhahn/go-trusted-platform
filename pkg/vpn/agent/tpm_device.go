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

package agent

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	attestationservice "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/service"
)

// TPMDeviceConfig is what a TPM-backed Device is built from.
type TPMDeviceConfig struct {
	// ID is the registry device id the gateway knows the peer by. It may
	// be empty for an agent that only disconnects or renews: those use
	// the id recorded with the lease.
	ID string
	// TPM produces the quotes, signed by the attestation key.
	TPM attestationservice.HostQuoter
	// Chain is the IDevID certificate chain, leaf first. The leaf is the
	// TLS client certificate presented to the gateway.
	Chain []*x509.Certificate
	// Signer is the IDevID key. On a host it is the TPM-resident key
	// behind platform.TPMSigner.
	Signer crypto.Signer
	// PCRs selects the quoted PCRs; nil quotes the manifest default.
	PCRs []int
}

// TPMDevice is the client's device identity: the IDevID certificate and
// key it authenticates with, and the TPM that quotes for it. Quotes are
// produced by the platform's attestation service, the same code platformd
// answers attestation challenges with.
type TPMDevice struct {
	id     string
	quoter *attestationservice.Service
	chain  []*x509.Certificate
	signer crypto.Signer
	quote  *daemon.QuoteConfig
}

// NewTPMDevice returns a Device over cfg. The signer must hold the key of
// the chain's leaf when it reports a public key.
func NewTPMDevice(cfg TPMDeviceConfig) (*TPMDevice, error) {
	if cfg.TPM == nil {
		return nil, &ErrInvalidOptions{Field: "tpm", Reason: "required"}
	}
	if len(cfg.Chain) == 0 || cfg.Chain[0] == nil {
		return nil, &ErrInvalidOptions{Field: "IDevID certificate", Reason: "required"}
	}
	if cfg.Signer == nil {
		return nil, &ErrInvalidOptions{Field: "IDevID signer", Reason: "required"}
	}
	if !signerHoldsLeaf(cfg.Signer, cfg.Chain[0]) {
		return nil, &ErrInvalidOptions{Field: "IDevID signer", Reason: "does not hold the IDevID certificate's key"}
	}
	var quote *daemon.QuoteConfig
	if cfg.PCRs != nil {
		quote = &daemon.QuoteConfig{PCRIndices: cfg.PCRs}
	}
	return &TPMDevice{
		id:     cfg.ID,
		quoter: attestationservice.NewService(nil, attestationservice.WithTPM(cfg.TPM)),
		chain:  cfg.Chain,
		signer: cfg.Signer,
		quote:  quote,
	}, nil
}

// signerHoldsLeaf reports whether signer's public key is the leaf's. A
// TPM signer may report no public key; the certificate's key stands in
// for it then (see leafSigner).
func signerHoldsLeaf(signer crypto.Signer, leaf *x509.Certificate) bool {
	pub := signer.Public()
	if pub == nil {
		return true
	}
	key, ok := pub.(interface{ Equal(crypto.PublicKey) bool })
	return ok && key.Equal(leaf.PublicKey)
}

// ID returns the registry device id.
func (d *TPMDevice) ID() string { return d.id }

// Certificate returns the IDevID chain with the TPM-resident key.
func (d *TPMDevice) Certificate() (tls.Certificate, error) {
	raw := make([][]byte, 0, len(d.chain))
	for _, cert := range d.chain {
		raw = append(raw, cert.Raw)
	}
	return tls.Certificate{
		Certificate: raw,
		PrivateKey:  leafSigner{Signer: d.signer, pub: d.chain[0].PublicKey},
		Leaf:        d.chain[0],
	}, nil
}

// Quote returns a TPM quote over nonce, carrying the IDevID certificate
// so the gateway can tie the quote to the device it admits.
func (d *TPMDevice) Quote(ctx context.Context, nonce []byte) (*manifest.HostAttestation, error) {
	att, err := d.quoter.CollectHostAttestation(ctx, d.quote, nonce)
	if err != nil {
		return nil, err
	}
	att.IDevIDCertificate = d.chain[0].Raw
	return att, nil
}

// leafSigner reports the certificate's public key. platform.TPMSigner
// returns nil when the key attributes carry no public bytes, and a nil
// Public makes crypto/tls send no client certificate at all.
type leafSigner struct {
	crypto.Signer
	pub crypto.PublicKey
}

// Public returns the certificate's public key.
func (s leafSigner) Public() crypto.PublicKey { return s.pub }
