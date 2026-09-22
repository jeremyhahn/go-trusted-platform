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
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"os"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
)

// HeartbeatConfig is the `heartbeat:` configuration section. When
// enabled on an ACME-enrolled client node, platformd periodically
// reports liveness to the control plane's POST /api/v1/device/heartbeat
// route using the node's TPM-backed IDevID identity over mTLS — the
// same identity FetchProfileAndActivate authenticates with.
type HeartbeatConfig struct {
	// Enabled turns the periodic reporter on. Following the platform's
	// explicit-configuration convention, an absent or disabled section
	// is a no-op.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// Interval is the duration between liveness reports. Zero selects
	// DefaultHeartbeatInterval.
	Interval time.Duration `yaml:"interval,omitempty" json:"interval,omitempty" mapstructure:"interval"`

	// CertFile / KeyFile optionally select a file-based mTLS client
	// identity, taking precedence over the TPM-backed IDevID. This
	// mirrors the gatewayd control-plane reporter's contract and exists
	// because a RESTRICTED IDevID signing key cannot produce a TLS
	// CertificateVerify signature (the TPM ticket-hashes the digest), so
	// fleets whose IDevID keys are restricted enroll a dedicated client
	// certificate instead.
	CertFile string `yaml:"cert-file,omitempty" json:"cert_file,omitempty" mapstructure:"cert-file"`
	KeyFile  string `yaml:"key-file,omitempty" json:"key_file,omitempty" mapstructure:"key-file"`

	// CAFile optionally anchors control-plane server verification to an
	// explicit bundle; when empty the platform CA store is tried first,
	// then the operating-system trust store. Verification is never
	// skipped.
	CAFile string `yaml:"ca-file,omitempty" json:"ca_file,omitempty" mapstructure:"ca-file"`
}

// Active reports whether the section is present and enabled.
func (c *HeartbeatConfig) Active() bool {
	return c != nil && c.Enabled
}

// DefaultHeartbeatInterval is the reporting cadence when the section
// does not set one. The WebUI treats a device as online when its last
// heartbeat is under five minutes old, so one minute leaves several
// missed reports of headroom before a node reads as offline.
const DefaultHeartbeatInterval = time.Minute

// MinHeartbeatInterval is the lowest interval StartDeviceHeartbeat
// accepts. It exists to catch unitless YAML values (`interval: 30`
// decodes to 30 nanoseconds) before they become a request hot loop
// against the control plane.
const MinHeartbeatInterval = 10 * time.Second

// StartDeviceHeartbeat launches the periodic liveness reporter. It is a
// no-op when the section is absent/disabled or when the node has no
// ACME client configuration (the control plane does not report to
// itself). The reporter is deliberately fail-soft at runtime: a missing
// IDevID certificate or an unreachable control plane logs and retries
// on the next tick, because liveness reporting must never take a
// working node down. The goroutine exits when ctx is cancelled.
func (app *App) StartDeviceHeartbeat(ctx context.Context) error {
	// Idempotent across repeated Init attempts and config reloads: any
	// running reporter is stopped FIRST — including when the section was
	// removed or disabled, so turning heartbeat off actually turns it
	// off — and at most one loop ever exists.
	app.StopDeviceHeartbeat()
	if !app.HeartbeatConfig.Active() {
		return nil
	}
	if app.ACMEConfig == nil || app.ACMEConfig.Client == nil || app.ACMEConfig.Client.DirectoryURL == "" {
		app.Logger.Info("heartbeat: no ACME client configuration; reporter not started")
		return nil
	}
	interval := app.HeartbeatConfig.Interval
	if interval == 0 {
		interval = DefaultHeartbeatInterval
	}
	if interval < MinHeartbeatInterval {
		return ErrHeartbeatIntervalTooShort{Interval: interval}
	}
	// A half-configured file identity is an operator configuration bug:
	// refuse startup now, exactly as the section contract promises,
	// instead of leaving the loop to log the same failure every tick.
	if (app.HeartbeatConfig.CertFile == "") != (app.HeartbeatConfig.KeyFile == "") {
		return ErrHeartbeatIdentityIncomplete{
			CertFile: app.HeartbeatConfig.CertFile,
			KeyFile:  app.HeartbeatConfig.KeyFile,
		}
	}
	serverURL, err := util.ExtractBaseURL(app.ACMEConfig.Client.DirectoryURL)
	if err != nil {
		return &WrappedError{Msg: "heartbeat: failed to extract server URL from ACME directory", Err: err}
	}
	runCtx, cancel := context.WithCancel(ctx)
	app.heartbeatCancel = cancel
	app.Logger.Info("device heartbeat reporter started",
		slog.String("server", serverURL),
		slog.Duration("interval", interval))
	go app.runDeviceHeartbeat(runCtx, serverURL, interval)
	return nil
}

// StopDeviceHeartbeat cancels the running reporter, if any.
func (app *App) StopDeviceHeartbeat() {
	if app.heartbeatCancel != nil {
		app.heartbeatCancel()
		app.heartbeatCancel = nil
	}
}

// runDeviceHeartbeat is the reporter loop. The provisioning client is
// built lazily on the first tick where the IDevID identity is available
// and then reused; a failed report drops the client so the next tick
// rebuilds it (certificates rotate).
func (app *App) runDeviceHeartbeat(ctx context.Context, serverURL string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var client *provisioning.Client
	for {
		select {
		case <-ctx.Done():
			if client != nil {
				_ = client.Close()
			}
			return
		case <-ticker.C:
			if client == nil {
				var err error
				client, err = app.newHeartbeatClient(serverURL)
				if err != nil {
					app.Logger.Debugf("heartbeat: client not ready: %v", err)
					continue
				}
			}
			tickCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			resp, err := client.Heartbeat(tickCtx)
			cancel()
			if err != nil {
				app.Logger.Warnf("heartbeat: report failed: %v", err)
				_ = client.Close()
				client = nil
				continue
			}
			app.Logger.Debug("heartbeat: reported",
				slog.String("serial", resp.Serial),
				slog.Time("received_at", resp.ReceivedAt))
		}
	}
}

// certSigner pairs a TPM-backed signing operation with the public key
// taken from the presented certificate, so crypto/tls can negotiate
// signature schemes even when the TPM attributes carry no public bytes.
type certSigner struct {
	crypto.Signer
	pub crypto.PublicKey
}

// Public returns the certificate's public key.
func (s certSigner) Public() crypto.PublicKey {
	return s.pub
}

// heartbeatServerPool resolves the CA pool for verifying the control
// plane's server certificate: the local platform CA store when it can
// chain the node's IDevID issuer, otherwise the operating-system trust
// store — the installer bakes the control plane's root there so the
// first ACME connection can verify TLS, and the gatewayd control-plane
// reporter documents the same fallback order. Verification itself is
// never skipped.
func (app *App) heartbeatServerPool(clientCert *x509.Certificate) (*x509.CertPool, error) {
	if app.CA != nil {
		if rootCert, err := app.CA.RootCertificate(clientCert); err == nil {
			if caPool, poolErr := app.CA.TrustedRootCertPool(rootCert); poolErr == nil {
				return caPool, nil
			}
		}
	}
	caPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, &WrappedError{Msg: "heartbeat: no CA pool available for server verification", Err: err}
	}
	app.Logger.Debug("heartbeat: platform CA store cannot chain the IDevID issuer; using the OS trust store")
	return caPool, nil
}

// newHeartbeatClient assembles the mTLS provisioning client: a
// file-based identity when the section configures one, otherwise the
// node's TPM-backed IDevID, mirroring FetchProfileAndActivate.
func (app *App) newHeartbeatClient(serverURL string) (*provisioning.Client, error) {
	if app.HeartbeatConfig.CertFile != "" || app.HeartbeatConfig.KeyFile != "" {
		return app.newFileHeartbeatClient(serverURL)
	}
	if app.TPM == nil || app.CA == nil || app.PlatformKS == nil {
		return nil, provisioning.ErrMissingCertificate
	}
	idevidCert, err := app.TPM.IDevIDCertificate()
	if err != nil {
		return nil, &WrappedError{Msg: "heartbeat: IDevID certificate unavailable", Err: err}
	}
	// Build the IDevID key attributes from the platform configuration —
	// the same constructor the enrollment flow signs with. The TPM's
	// steady-state IDevIDAttributes() accessor rebuilds attributes from
	// the persistent handle alone and cannot sign (observed live:
	// "invalid parent key attributes", then a blob lookup for a
	// TPM-persistent key).
	if app.TPMConfig.IDevID == nil {
		return nil, provisioning.ErrMissingCertificate
	}
	// Retained as a precondition though the digest is no longer passed to
	// the attribute builder (go-xkms #355): a TPM that cannot produce it
	// cannot satisfy the IDevID key's policy either.
	if _, policyErr := app.TPM.PlatformPolicyDigest(); policyErr != nil {
		return nil, &WrappedError{Msg: "heartbeat: platform policy digest unavailable", Err: policyErr}
	}
	idevidAttrs, err := xkmssdk.IDevIDAttributesFromConfig(*app.TPMConfig.IDevID)
	if err != nil {
		return nil, &WrappedError{Msg: "heartbeat: IDevID key attributes unavailable", Err: err}
	}
	// The TLS client cert's signer MUST report the certificate's public
	// key: TPMSigner resolves its key from TPMAttributes and returns nil
	// when those bytes are absent (the steady-state shape on enrolled
	// nodes), and a nil Public() makes crypto/tls silently present NO
	// client certificate — observed live as 401 "client certificate
	// required" from the control plane. The IDevID certificate itself is
	// the authoritative source for the public half.
	tpmSigner := certSigner{
		Signer: platform.NewTPMSigner(app.TPM, idevidAttrs, app.PlatformKS.Backend()),
		pub:    idevidCert.PublicKey,
	}
	caPool, err := app.heartbeatServerPool(idevidCert)
	if err != nil {
		return nil, err
	}
	return provisioning.NewClient(&provisioning.ClientConfig{
		ServerURL:   serverURL,
		Certificate: idevidCert,
		PrivateKey:  tpmSigner,
		CACertPool:  caPool,
		Timeout:     30 * time.Second,
	}, app.Logger)
}

// newFileHeartbeatClient builds the reporter's mTLS client from the
// configured certificate/key files. Both must be set — a half-configured
// identity fails closed rather than silently falling back to the TPM.
func (app *App) newFileHeartbeatClient(serverURL string) (*provisioning.Client, error) {
	cfg := app.HeartbeatConfig
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, ErrHeartbeatIdentityIncomplete{CertFile: cfg.CertFile, KeyFile: cfg.KeyFile}
	}
	keyPair, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, &WrappedError{Msg: "heartbeat: failed to load client identity", Err: err}
	}
	leaf, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, &WrappedError{Msg: "heartbeat: failed to parse client certificate", Err: err}
	}
	var caPool *x509.CertPool
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, &WrappedError{Msg: "heartbeat: failed to read CA bundle", Err: err}
		}
		caPool = x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(pem) {
			return nil, ErrHeartbeatCABundleInvalid{Path: cfg.CAFile}
		}
	} else {
		// Documented resolution order: ca-file → platform CA store → OS
		// trust store. heartbeatServerPool implements the latter two.
		var poolErr error
		caPool, poolErr = app.heartbeatServerPool(leaf)
		if poolErr != nil {
			return nil, poolErr
		}
	}
	return provisioning.NewClient(&provisioning.ClientConfig{
		ServerURL:      serverURL,
		Certificate:    leaf,
		PrivateKey:     keyPair.PrivateKey,
		CACertPool:     caPool,
		TLSCertificate: &keyPair,
		Timeout:        30 * time.Second,
	}, app.Logger)
}
