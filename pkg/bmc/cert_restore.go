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

package bmc

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
)

// FactoryCertRestorer is an optional capability interface for CertificateManager
// implementations that can instruct the BMC to regenerate its default
// self-signed HTTPS certificate, discarding any previously installed
// platform-issued certificate.
//
// Implementations must:
//   - Issue the vendor-specific command that causes the BMC to regenerate
//     its built-in/default SSL certificate.
//   - Restart the BMC web server so the new self-signed cert is active.
//   - Wait for the BMC HTTPS port to come back online (using the same
//     waitForReady mechanics as ReplaceWebCertificate).
//   - Compare the pre- and post-restore certificate DER SHA-256 to confirm
//     the certificate actually changed, returning ErrFactoryRestoreUnchanged
//     when the fingerprint is identical.
type FactoryCertRestorer interface {
	// RestoreFactoryCertificate instructs the BMC to regenerate its default
	// self-signed HTTPS certificate and waits for the web server to restart.
	// Returns the new self-signed certificate, or an error if the operation
	// fails or the certificate does not change after the restart.
	RestoreFactoryCertificate(ctx context.Context) (*x509.Certificate, error)
}

// ErrFactoryRestoreUnchanged is returned by RestoreFactoryCertificate when
// the BMC's certificate fingerprint is identical before and after the restore
// operation, indicating the BMC did not actually regenerate its certificate.
type ErrFactoryRestoreUnchanged struct {
	// DERFingerprint is the hex-encoded SHA-256 of the certificate DER that
	// was observed both before and after the attempted restore.
	DERFingerprint string
}

// Error implements error.
func (e ErrFactoryRestoreUnchanged) Error() string {
	return fmt.Sprintf("bmc: factory cert restore: certificate unchanged after restart (fingerprint=%s); BMC may not support default-cert regeneration via this path", e.DERFingerprint)
}

// ErrFactoryRestoreUnsupported is returned by AutoCertManager when the
// resolved backend does not implement FactoryCertRestorer.
type ErrFactoryRestoreUnsupported struct {
	// Backend is the CertBackend that was resolved but does not support restore.
	Backend CertBackend
}

// Error implements error.
func (e ErrFactoryRestoreUnsupported) Error() string {
	return fmt.Sprintf("bmc: factory cert restore: backend %q does not support RestoreFactoryCertificate", e.Backend)
}

// certDERSHA256Hex returns the hex-encoded SHA-256 of a certificate's DER bytes.
func certDERSHA256Hex(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", sum)
}

// RestoreFactoryCertificate implements FactoryCertRestorer on AutoCertManager.
// It delegates to the resolved backend when that backend implements
// FactoryCertRestorer; otherwise it returns ErrFactoryRestoreUnsupported.
func (m *AutoCertManager) RestoreFactoryCertificate(ctx context.Context) (*x509.Certificate, error) {
	primary, _, err := m.resolveBackends(ctx)
	if err != nil {
		return nil, err
	}
	restorer, ok := primary.(FactoryCertRestorer)
	if !ok {
		return nil, ErrFactoryRestoreUnsupported{Backend: primary.Backend()}
	}
	return restorer.RestoreFactoryCertificate(ctx)
}

// compile-time check: AutoCertManager implements FactoryCertRestorer.
var _ FactoryCertRestorer = (*AutoCertManager)(nil)

// RestoreFactoryCertificate implements FactoryCertRestorer on redfishCertManager.
//
// Redfish restore flow:
//  1. Capture the SHA-256 fingerprint of the current HTTPS certificate via a
//     live TLS handshake so we can detect whether the restart produced a new
//     cert.
//  2. Discover the Manager resource (same path as ReplaceWebCertificate).
//  3. DELETE the active HTTPS certificate resource at
//     <managerPath>/NetworkProtocol/HTTPS/Certificates/1.
//     Per DMTF Redfish specification §Certificates, deleting the active HTTPS
//     cert causes the manager to fall back to generating a self-signed
//     default certificate on the next web-server restart. Implementations that
//     do not support DELETE return 405 or 501, which surfaces as an error to
//     the caller rather than a silent no-op.
//  4. POST Manager.Reset (GracefulRestart) to activate the new default cert.
//  5. Wait for the BMC HTTPS port to become available again (waitForReady).
//  6. Re-capture the certificate fingerprint and verify it differs from the
//     pre-restore fingerprint. Return ErrFactoryRestoreUnchanged when equal.
func (m *redfishCertManager) RestoreFactoryCertificate(ctx context.Context) (*x509.Certificate, error) {
	// Step 1: capture current cert fingerprint.
	preCert, err := m.GetWebCertificate(ctx)
	if err != nil {
		return nil, ErrConnectionFailed{Address: m.cfg.Address, Cause: err}
	}
	preFingerprint := certDERSHA256Hex(preCert)

	// Step 2: discover manager + cert URI.
	mgr, mgrPath, err := m.discoverManager(ctx)
	if err != nil {
		return nil, err
	}
	certURI := mgrPath + redfishHTTPSCertSuffix

	// Step 3: DELETE the active HTTPS certificate resource. doJSON already
	// returns ErrRedfishRequest on non-2xx; that propagates unchanged to the
	// caller so the status code is visible without double-wrapping.
	if _, err := m.transport.doJSON(ctx, "DELETE", certURI, nil, nil); err != nil {
		return nil, err
	}

	// Step 4: restart the manager web server so the new default cert is loaded.
	resetTarget := mgr.Actions.Reset.Target
	if resetTarget == "" {
		resetTarget = mgrPath + "/Actions/Manager.Reset"
	}
	if err := m.resetManager(ctx, resetTarget); err != nil {
		return nil, err
	}

	// Step 5: wait for the BMC HTTPS port to come back online.
	if err := m.waitForReady(ctx); err != nil {
		return nil, err
	}

	// Step 6: re-capture the new certificate and verify it changed.
	postCert, err := m.GetWebCertificate(ctx)
	if err != nil {
		return nil, ErrConnectionFailed{
			Address: m.cfg.Address,
			Cause:   errors.New("BMC restarted but new cert could not be read: " + err.Error()),
		}
	}
	if certDERSHA256Hex(postCert) == preFingerprint {
		return nil, ErrFactoryRestoreUnchanged{DERFingerprint: preFingerprint}
	}
	return postCert, nil
}

// compile-time check: redfishCertManager implements FactoryCertRestorer.
var _ FactoryCertRestorer = (*redfishCertManager)(nil)
