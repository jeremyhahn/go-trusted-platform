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
	"crypto/x509"
	"errors"
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// Redfish CertificateService paths and known certificate URIs.
const (
	redfishCertServicePath       = "/redfish/v1/CertificateService"
	redfishCertReplaceActionPath = "/redfish/v1/CertificateService/Actions/CertificateService.ReplaceCertificate"
)

// httpsCertContext identifies the standard URI prefix where a Redfish BMC
// publishes its HTTPS server certificate. The full path is the prefix
// joined with the manager ID and the certificate index, e.g.:
//
//	/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates/1
//
// We discover the manager ID from the resolved manager path returned by
// the existing redfishClient discovery flow.
const (
	redfishHTTPSCertSuffix = "/NetworkProtocol/HTTPS/Certificates/1"
	redfishCertTypePEM     = "PEM"
)

// redfishReplaceCertBody is the request body for ReplaceCertificate.
type redfishReplaceCertBody struct {
	CertificateString string     `json:"CertificateString"`
	CertificateType   string     `json:"CertificateType"`
	CertificateURI    redfishRef `json:"CertificateUri"`
}

// redfishManagerResetBody is the body for Manager.Reset to apply a new
// HTTPS certificate. GracefulRestart preserves session state where the
// firmware supports it; ForceRestart is an alternative for stricter BMCs.
type redfishManagerResetBody struct {
	ResetType string `json:"ResetType"`
}

// redfishManagerActions captures the Manager resource's Actions block,
// just the Reset target we need to invoke after a cert replace.
type redfishManagerActions struct {
	Reset struct {
		Target string `json:"target"`
	} `json:"#Manager.Reset"`
}

type redfishManagerResource struct {
	ODataID string                `json:"@odata.id"`
	ID      string                `json:"Id"`
	Actions redfishManagerActions `json:"Actions"`
}

// redfishCertManager implements CertificateManager via the Redfish 1.6+
// CertificateService.
//
// Workflow on ReplaceWebCertificate:
//  1. Discover the Manager ID and its Reset action target.
//  2. POST the new cert+key to CertificateService.ReplaceCertificate with
//     CertificateUri pointing at the HTTPS server cert.
//  3. POST a Manager.Reset (GracefulRestart) so the BMC starts serving the
//     new certificate.
//  4. Wait until the BMC's HTTPS port responds again, or until ctx ends.
type redfishCertManager struct {
	transport      *redfishTransport
	cfg            *Config
	logger         *slog.Logger
	resetWaitCheck time.Duration // poll cadence for post-reset readiness
	resetMaxWait   time.Duration // total timeout for post-reset readiness
}

// Compile-time interface check.
var _ CertificateManager = (*redfishCertManager)(nil)

// ManagedCertificateManager is a CertificateManager that owns lifecycle
// resources. Production constructors return ManagedCertificateManager so
// callers can release the underlying HTTP transport via Close.
type ManagedCertificateManager interface {
	CertificateManager
	Close() error
}

var _ ManagedCertificateManager = (*redfishCertManager)(nil)

// NewRedfishCertManager builds a CertificateManager backed by the
// Redfish CertificateService. Suitable for X11+, iDRAC9+, iLO5+
// generation hardware.
func NewRedfishCertManager(cfg *Config, logger *slog.Logger) (ManagedCertificateManager, error) {
	t, err := newRedfishTransport(context.Background(), cfg, logger)
	if err != nil {
		return nil, err
	}
	return &redfishCertManager{
		transport:      t,
		cfg:            cfg,
		logger:         logger,
		resetWaitCheck: 2 * time.Second,
		resetMaxWait:   5 * time.Minute,
	}, nil
}

// Close releases the transport's resources.
func (m *redfishCertManager) Close() error {
	return m.transport.Close()
}

// Backend reports the backend in use.
func (m *redfishCertManager) Backend() CertBackend {
	return CertBackendRedfish
}

// GetWebCertificate reads the certificate the BMC currently presents on
// its HTTPS port. Implementation reads the leaf cert from the live TLS
// handshake — this works on every BMC regardless of CertificateService
// support, so it can be called even before TLS provisioning.
func (m *redfishCertManager) GetWebCertificate(ctx context.Context) (*x509.Certificate, error) {
	tlsCfg, err := BuildTLSConfig(ctx, m.cfg)
	if err != nil {
		return nil, err
	}
	state, err := peerCertificate(ctx, m.cfg.Address, m.cfg.Port, tlsCfg)
	if err != nil {
		return nil, err
	}
	if len(state.PeerCertificates) == 0 {
		return nil, ErrConnectionFailed{
			Address: m.cfg.Address,
			Cause:   errors.New("BMC presented no peer certificates"),
		}
	}
	return state.PeerCertificates[0], nil
}

// ReplaceWebCertificate uploads a new HTTPS server certificate via the
// Redfish CertificateService and resets the BMC to activate it.
//
// certPEM is the leaf certificate (optionally followed by intermediates)
// in PEM format. keyPEM is the private key in PEM format, held in
// locked memory. Both are sent as a single CertificateString field per
// the Redfish schema, with the key first then the cert chain.
func (m *redfishCertManager) ReplaceWebCertificate(ctx context.Context, certPEM []byte, keyPEM *memguard.Secret) error {
	if len(certPEM) == 0 {
		return ErrInvalidConfig{Field: "certPEM", Reason: "certificate PEM is empty"}
	}
	if keyPEM == nil || keyPEM.Size() == 0 {
		return ErrInvalidConfig{Field: "keyPEM", Reason: "private key is required"}
	}

	mgr, mgrPath, err := m.discoverManager(ctx)
	if err != nil {
		return err
	}
	certURI := mgrPath + redfishHTTPSCertSuffix

	if err := m.postReplace(ctx, certPEM, keyPEM, certURI); err != nil {
		return err
	}

	resetTarget := mgr.Actions.Reset.Target
	if resetTarget == "" {
		resetTarget = mgrPath + "/Actions/Manager.Reset"
	}
	if err := m.resetManager(ctx, resetTarget); err != nil {
		return err
	}

	return m.waitForReady(ctx)
}

// discoverManager returns the first Manager resource and the path that
// resolved it (the OData identifier of the Manager resource), used to
// build the HTTPS-cert URI and the Manager.Reset fallback.
func (m *redfishCertManager) discoverManager(ctx context.Context) (*redfishManagerResource, string, error) {
	var root redfishServiceRoot
	if _, err := m.transport.doJSON(ctx, "GET", "/redfish/v1/", nil, &root); err != nil {
		return nil, "", ErrRedfishDiscovery{Resource: "service root", Cause: err}
	}
	if root.Managers.ODataID == "" {
		return nil, "", ErrRedfishDiscovery{Resource: "managers", Cause: errors.New("Managers link missing from service root")}
	}
	var coll redfishCollection
	if _, err := m.transport.doJSON(ctx, "GET", root.Managers.ODataID, nil, &coll); err != nil {
		return nil, "", ErrRedfishDiscovery{Resource: "managers collection", Cause: err}
	}
	if len(coll.Members) == 0 {
		return nil, "", ErrRedfishDiscovery{Resource: "managers collection", Cause: errors.New("no manager resources")}
	}
	mgrPath := coll.Members[0].ODataID
	var mgr redfishManagerResource
	if _, err := m.transport.doJSON(ctx, "GET", mgrPath, nil, &mgr); err != nil {
		return nil, "", ErrRedfishDiscovery{Resource: "manager", Cause: err}
	}
	if mgr.ODataID != "" {
		mgrPath = mgr.ODataID
	}
	return &mgr, mgrPath, nil
}

// postReplace sends the ReplaceCertificate action.
func (m *redfishCertManager) postReplace(ctx context.Context, certPEM []byte, keyPEM *memguard.Secret, certURI string) error {
	return keyPEM.WithBytes(func(key []byte) error {
		// Per Redfish CertificateService schema, CertificateString carries
		// the PEM bundle. Order: private key first, then certificate chain.
		bundle := make([]byte, 0, len(key)+len(certPEM)+1)
		bundle = append(bundle, key...)
		if len(key) > 0 && key[len(key)-1] != '\n' {
			bundle = append(bundle, '\n')
		}
		bundle = append(bundle, certPEM...)

		body := redfishReplaceCertBody{
			CertificateString: string(bundle),
			CertificateType:   redfishCertTypePEM,
			CertificateURI:    redfishRef{ODataID: certURI},
		}
		_, err := m.transport.doJSON(ctx, "POST", redfishCertReplaceActionPath, body, nil)
		zero(bundle)
		return err
	})
}

// resetManager invokes Manager.Reset to apply the new HTTPS certificate.
func (m *redfishCertManager) resetManager(ctx context.Context, target string) error {
	body := redfishManagerResetBody{ResetType: "GracefulRestart"}
	_, err := m.transport.doJSON(ctx, "POST", target, body, nil)
	return err
}

// waitForReady polls the BMC HTTPS port until a TLS handshake succeeds
// or the context expires. The cert is now signed by the new platform
// CA, so we re-validate against the configured trust store on each
// attempt.
func (m *redfishCertManager) waitForReady(ctx context.Context) error {
	tlsCfg, err := BuildTLSConfig(ctx, m.cfg)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(m.resetMaxWait)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	timer := time.NewTimer(m.resetWaitCheck)
	defer timer.Stop()
	for {
		_, err := peerCertificate(ctx, m.cfg.Address, m.cfg.Port, tlsCfg)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return ErrBMCResetTimeout{Cause: err}
		}
		timer.Reset(m.resetWaitCheck)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

