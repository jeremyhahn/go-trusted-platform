// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// tpm_diskless_boot.go is a provisioned diskless node's per-boot recovery of
// its identity certificates (#690). The TPM keeps the keys; the certificates
// lived on a tmpfs that is gone. The node fetches them back from the control
// plane over an mTLS connection authenticated by its TPM-resident IDevID and
// answers a quote bound to that connection. The control plane hands over the
// material only after the quote verifies against the device's baseline.

package app

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/hostquote"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
)

// disklessBootTimeout bounds each of the two boot requests.
const disklessBootTimeout = 30 * time.Second

// ErrDisklessBootUnconfigured is returned when the configuration does not
// say where the control plane is or which identity to recover.
type ErrDisklessBootUnconfigured struct {
	// Setting names the missing configuration.
	Setting string
}

// Error implements the error interface.
func (e ErrDisklessBootUnconfigured) Error() string {
	return "diskless boot: " + e.Setting + " is not configured"
}

// ErrDisklessBootMaterialInvalid is returned when what the control plane
// delivered does not belong to this node's TPM-resident identity.
type ErrDisklessBootMaterialInvalid struct {
	Reason string
	Cause  error
}

// Error implements the error interface.
func (e ErrDisklessBootMaterialInvalid) Error() string {
	msg := "diskless boot: delivered material refused: " + e.Reason
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the underlying error.
func (e ErrDisklessBootMaterialInvalid) Unwrap() error { return e.Cause }

// disklessBootTarget is where a diskless node recovers its identity from,
// and under which name.
type disklessBootTarget struct {
	serverURL string
	identity  string
}

// disklessIdentity is the material a boot delivery installs, parsed and
// checked against the TPM before anything is stored.
type disklessIdentity struct {
	idevid  []*x509.Certificate
	iak     *x509.Certificate
	issuers []*x509.Certificate
}

// recoverDisklessIdentity is InitTPM's identity completion on a diskless
// node whose TPM already holds its identity. Every failure is an
// ErrDisklessIdentityUnavailable naming the step that refused.
func (app *App) recoverDisklessIdentity(
	ctx context.Context,
	soPIN, userPIN xkmssdk.Password,
	initParams *AppInitParams) error {

	target, err := app.disklessBootTarget()
	if err != nil {
		return ErrDisklessIdentityUnavailable{Reason: "no control plane to recover from", Cause: err}
	}
	roots, err := app.disklessServerRoots()
	if err != nil {
		return ErrDisklessIdentityUnavailable{Reason: "no trust anchor for the control plane", Cause: err}
	}

	// The CA first, as on the disk path's completion: its key store is the
	// IDevID signer's backend, and its certificate store is where the
	// issuing chain must land for the platform anchor to resolve.
	if _, err := app.InitCA(ctx, soPIN, userPIN, initParams); err != nil {
		return ErrDisklessIdentityUnavailable{Reason: "platform CA did not initialize", Cause: err}
	}

	app.Logger.Info("Diskless node: recovering identity certificates from the control plane",
		slog.String("server", target.serverURL),
		slog.String("identity", target.identity))
	delivery, err := app.fetchDisklessIdentity(ctx, target, roots)
	if err != nil {
		return ErrDisklessIdentityUnavailable{Reason: "attested boot delivery failed", Cause: err}
	}
	identity, err := app.checkDisklessIdentity(delivery)
	if err != nil {
		return ErrDisklessIdentityUnavailable{Reason: "delivered identity does not match the TPM", Cause: err}
	}
	if err := app.installDisklessIdentity(ctx, identity); err != nil {
		return ErrDisklessIdentityUnavailable{Reason: "delivered identity could not be stored", Cause: err}
	}

	// A trust-on-first-use acceptance is worth seeing in the log: the quote
	// then proved freshness, not that the boot state is the expected one.
	app.Logger.Info("Diskless node: identity recovered",
		slog.String("serial", delivery.Serial),
		slog.String("pcr_baseline_source", delivery.PCRBaselineSource),
		slog.Bool("pcr_baseline_captured", delivery.PCRBaselineCaptured),
		slog.Int("admitted_vlan", int(delivery.Profile.AdmittedNetwork.VLAN)))
	return nil
}

// disklessBootTarget resolves the control plane from the ACME directory —
// the provisioning API is served beside it, as for FetchProfileAndActivate —
// and the identity from the node's EK (applyDisklessNodeIdentity), the name
// it enrolled its IDevID under. The hostname is the image's, shared by every
// node built from it, and plays no part.
func (app *App) disklessBootTarget() (disklessBootTarget, error) {
	if app.ACMEConfig == nil || app.ACMEConfig.Client == nil || app.ACMEConfig.Client.DirectoryURL == "" {
		return disklessBootTarget{}, ErrDisklessBootUnconfigured{Setting: "acme.client.directory-url"}
	}
	if app.nodeIdentity == "" {
		return disklessBootTarget{}, ErrDisklessIdentityUnavailable{
			Reason: "the node identity has not been derived from the TPM's EK"}
	}
	serverURL, err := util.ExtractBaseURL(app.ACMEConfig.Client.DirectoryURL)
	if err != nil {
		return disklessBootTarget{}, err
	}
	return disklessBootTarget{serverURL: serverURL, identity: app.nodeIdentity}, nil
}

// disklessServerRoots is what the node verifies the control plane against
// before it has a certificate store: the OS trust store plus the CA bundle
// the image carries. Both come from the verified, read-only root image.
func (app *App) disklessServerRoots() (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, &WrappedError{Msg: "diskless boot: OS trust store unavailable", Err: err}
	}
	if bundlePath, bundleData, ok := app.readWellKnownCABundle(); ok {
		if !pool.AppendCertsFromPEM(bundleData) {
			return nil, ErrDisklessBootMaterialInvalid{Reason: "image CA bundle " + bundlePath + " holds no certificate"}
		}
		app.Logger.Info("Diskless node: trusting the image CA bundle for the control plane",
			slog.String("path", bundlePath))
	}
	return pool, nil
}

// fetchDisklessIdentity fetches the recorded IDevID chain, proving with the
// TPM-resident IDevID key that it is this node's, then presents the chain
// with the same key and quotes over the connection. The key's public half is
// read from its persistent handle: the chain that would carry it is what the
// node is about to fetch.
func (app *App) fetchDisklessIdentity(
	ctx context.Context,
	target disklessBootTarget,
	roots *x509.CertPool) (*provisioning.BootDeliveryResponse, error) {

	if app.TPMConfig.IDevID == nil {
		return nil, ErrDisklessIdentityUnavailable{Reason: "the TPM configuration has no IDevID section"}
	}
	idevidPub, err := residentPublicKey(app.TPM, app.TPMConfig.IDevID.Handle)
	if err != nil {
		return nil, ErrDisklessIdentityUnavailable{Reason: "the IDevID key cannot be read", Cause: err}
	}
	signer, err := app.idevidSigner(idevidPub)
	if err != nil {
		return nil, err
	}
	recorded, err := provisioning.FetchBootCertificate(ctx, target.serverURL, roots, target.identity, signer, disklessBootTimeout)
	if err != nil {
		return nil, err
	}
	chain, err := provisioning.ParseCertificateChain([]byte(recorded.IDevIDChain))
	if err != nil {
		return nil, err
	}
	client, err := provisioning.NewClient(&provisioning.ClientConfig{
		ServerURL:      target.serverURL,
		Certificate:    chain[0],
		PrivateKey:     signer,
		CACertPool:     roots,
		TLSCertificate: presentedChain(chain, signer),
		Timeout:        disklessBootTimeout,
	}, app.Logger)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.BootDelivery(ctx, app.disklessBootQuote)
}

// presentedChain is the TLS client certificate: the IDevID leaf with its
// intermediates, so the control plane can chain it without holding them.
func presentedChain(chain []*x509.Certificate, signer crypto.Signer) *tls.Certificate {
	cert := &tls.Certificate{PrivateKey: signer, Leaf: chain[0]}
	for _, c := range chain {
		cert.Certificate = append(cert.Certificate, c.Raw)
	}
	return cert
}

// disklessBootQuote quotes the connection's nonce with the IAK over the
// default PCR selection, in the evidence shape the verifier reads.
func (app *App) disklessBootQuote(ctx context.Context, nonce []byte) ([]byte, error) {
	result, err := hostquote.Collect(ctx, app.TPM, nil, "", nonce)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result.Evidence(nonce))
}

// checkDisklessIdentity parses the delivery and refuses certificates that do
// not certify the keys this TPM holds. The control plane is authenticated,
// but nothing it says is stored beside the node's keys unchecked.
func (app *App) checkDisklessIdentity(delivery *provisioning.BootDeliveryResponse) (*disklessIdentity, error) {
	idevid, err := provisioning.ParseCertificateChain([]byte(delivery.IDevIDChain))
	if err != nil {
		return nil, ErrDisklessBootMaterialInvalid{Reason: "IDevID chain does not parse", Cause: err}
	}
	bundle, err := provisioning.ParseCertificateChain([]byte(delivery.CABundle))
	if err != nil {
		return nil, ErrDisklessBootMaterialInvalid{Reason: "CA bundle does not parse", Cause: err}
	}
	if delivery.AttestCert == "" {
		return nil, ErrDisklessBootMaterialInvalid{Reason: "the control plane holds no IAK certificate for this node"}
	}
	iak, err := provisioning.ParseCertificateChain([]byte(delivery.AttestCert))
	if err != nil {
		return nil, ErrDisklessBootMaterialInvalid{Reason: "IAK certificate does not parse", Cause: err}
	}

	iakPub, err := app.TPM.IAK()
	if err != nil {
		return nil, ErrDisklessBootMaterialInvalid{Reason: "TPM-resident IAK public key unavailable", Cause: err}
	}
	if !samePublicKey(iak[0].PublicKey, iakPub) {
		return nil, ErrDisklessBootMaterialInvalid{Reason: "IAK certificate does not certify the TPM-resident IAK"}
	}

	return &disklessIdentity{
		idevid:  idevid,
		iak:     iak[0],
		issuers: distinctCertificates(append(idevid[1:], bundle...)),
	}, nil
}

// installDisklessIdentity stores the recovered identity where a disk node's
// enrollment stores it: the issuing chain in the CA's certificate store, the
// leaves there and in the TPM certificate store, whose IAK and IDevID
// entries are what mark the platform identity complete.
func (app *App) installDisklessIdentity(ctx context.Context, identity *disklessIdentity) error {
	// Issuers first, so the leaves' issuer resolves the moment they land.
	// As on enrollment, a certificate the store refuses is logged rather
	// than fatal: the TPM certificate store below is what completes the
	// identity, and an anchor gap surfaces where it is diagnosable.
	for _, issuer := range identity.issuers {
		if err := app.CA.ImportCertificate(ctx, issuer); err != nil {
			app.Logger.Error(err, slog.String("context", "Failed to import issuing chain certificate"),
				slog.String("subject", issuer.Subject.CommonName))
		}
	}
	for _, leaf := range []*x509.Certificate{identity.iak, identity.idevid[0]} {
		if err := app.CA.ImportCertificate(ctx, leaf); err != nil {
			app.Logger.Error(err, slog.String("context", "Failed to import identity certificate"),
				slog.String("subject", leaf.Subject.CommonName))
		}
	}
	if err := app.TPM.ProvisionIAKCert(identity.iak); err != nil {
		return &WrappedError{Msg: "failed to store IAK certificate in the TPM certificate store", Err: err}
	}
	if err := app.TPM.ProvisionIDevIDCert(identity.idevid[0]); err != nil {
		return &WrappedError{Msg: "failed to store IDevID certificate in the TPM certificate store", Err: err}
	}
	return nil
}

// samePublicKey reports whether two public keys are the same key.
func samePublicKey(a, b crypto.PublicKey) bool {
	comparable, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && comparable.Equal(b)
}

// distinctCertificates drops repeats, keeping first occurrences in order: an
// intermediate is typically in both the IDevID chain and the CA bundle.
func distinctCertificates(certs []*x509.Certificate) []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(certs))
	for _, cert := range certs {
		seen := false
		for _, kept := range out {
			if bytes.Equal(kept.Raw, cert.Raw) {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, cert)
		}
	}
	return out
}
