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
	"fmt"
	"log/slog"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// bmcCertInitOptions bundles every dependency that
// initBMCCertManagement needs from the surrounding platformd boot
// context. Callers populate from their *App without this function
// having to reach into App's internals — keeps the orchestrator
// testable with in-process fakes.
type bmcCertInitOptions struct {
	// BMCConfig is the BMC identity platformd manages. Expected to
	// come from app.BMCConfig. A nil BMCConfig or a BMCConfig with
	// no Certificate block means "TLS management disabled for this
	// node" — initBMCCertManagement returns nil without error, so
	// callers can call it unconditionally at boot.
	BMCConfig *bmc.Config

	// NodeID is the platformd node's stable identifier. It is used
	// as the device ID in the CertTarget name ("bmc.<nodeID>"), as
	// the ACME identifier when the cert has no explicit CN SANs,
	// and as the scheduler NodeAffinity so the cert-renewal job
	// fires on this node only.
	NodeID string

	// ACMEIssuer is the low-level go-trusted-ca ACME client wrapped
	// into the narrow ACMEIssuer interface. Pass nil to force the
	// local CA fallback path. Production callers typically pass
	// app.ACMEClient.
	ACMEIssuer ACMEIssuer

	// LocalCAIssuer is the platform CA for the local fallback path.
	// Required even when ACMEIssuer is set — issueBMCCertificateCore
	// validates this up front so callers catch configuration
	// mistakes at boot, not on first renewal. Production callers
	// typically pass app.CA.
	LocalCAIssuer LocalCAIssuer

	// DNSUpdater is the platform DNS service used to write dns-01
	// challenge TXT records. Required when ACMEIssuer is non-nil.
	// Production callers typically pass app.DNSService.
	DNSUpdater dnsUpdater

	// Hostmaster is the operator contact email folded into SANs
	// when Certificate.SANS is absent. Production callers typically
	// pass app.Hostmaster.
	Hostmaster string

	// Scheduler is the embedded quicbaas scheduler engine — wired
	// to the platform's own cluster-aware scheduler. See pkg/bmc
	// and P1 scheduler clustering fix for semantics.
	Scheduler SchedulerService

	// Registry holds the managed cert targets. Typically created
	// once per platformd boot via NewCertTargetRegistry and shared
	// with other cert-managed services (webservice TLS, etc.) so
	// the renewal handler iterates all of them in one sweep.
	Registry *CertTargetRegistry

	// Logger receives structured boot/renewal events. May be nil.
	Logger *slog.Logger

	// DNSTTL is the DNS-01 challenge TXT record TTL. Zero falls
	// back to the provider default (60s).
	DNSTTL int
}

// dnsUpdater is the narrow DNS service interface for dns-01 challenge
// TXT record management. The platform's *dns.Service satisfies this.
type dnsUpdater interface {
	AddRecord(ctx context.Context, name, recordType, value string, ttl int) error
	DeleteRecord(ctx context.Context, name, recordType string) error
}

// initBMCCertManagement wires BMC TLS certificate management for a
// platformd node. It:
//
//  1. Short-circuits if BMC TLS management is disabled (BMCConfig
//     nil or BMCConfig.Certificate nil) so callers can call it
//     unconditionally at boot.
//  2. Issues an initial certificate via issueBMCCertificateCore
//     (fresh ECDSA keypair -> CSR -> ACME dns-01 or local CA -> deploy
//     to BMC via AutoCertManager).
//  3. Registers the returned CertTarget in the registry so the
//     renewal handler picks it up.
//  4. Registers the platform.cert-renewal handler + per-node
//     recurring job via RegisterCertRenewal (idempotent -- re-runs
//     of boot leave the job alone).
//
// Called by InitCertManagement; not exported.
func initBMCCertManagement(ctx context.Context, opts bmcCertInitOptions) error {
	if opts.BMCConfig == nil || opts.BMCConfig.Certificate == nil {
		if opts.Logger != nil {
			opts.Logger.Info("bmc-cert-init: no BMC TLS management configured; skipping")
		}
		return nil
	}
	if opts.NodeID == "" {
		return ErrInitBMCCertMissingNodeID
	}
	if opts.Registry == nil {
		return ErrInitBMCCertMissingRegistry
	}
	if opts.Scheduler == nil {
		return ErrInitBMCCertMissingScheduler
	}
	if opts.LocalCAIssuer == nil {
		return ErrMissingLocalCAIssuer
	}

	deviceID := deriveBMCDeviceID(opts.BMCConfig, opts.NodeID)

	// Issue + deploy initial certificate.
	core := issueBMCCertificateOptions{
		ACMEIssuer:    opts.ACMEIssuer,
		LocalCAIssuer: opts.LocalCAIssuer,
		DNSUpdater:    opts.DNSUpdater,
		DNSTTL:        opts.DNSTTL,
		Hostmaster:    opts.Hostmaster,
		Logger:        opts.Logger,
	}
	target, err := issueBMCCertificateCore(ctx, deviceID, opts.BMCConfig, core)
	if err != nil {
		return ErrInitBMCCertIssue{DeviceID: deviceID, Cause: err}
	}

	// Register the target so the renewal sweep picks it up. Use
	// Replace to tolerate re-runs of init at boot (idempotent).
	if err := opts.Registry.Replace(target); err != nil {
		return ErrInitBMCCertRegister{DeviceID: deviceID, Cause: err}
	}

	// Wire the cert-renewal handler + per-node recurring job.
	if err := RegisterCertRenewal(ctx, CertRenewalRegistration{
		Scheduler: opts.Scheduler,
		Registry:  opts.Registry,
		NodeID:    opts.NodeID,
		Logger:    opts.Logger,
	}); err != nil {
		return err
	}

	if opts.Logger != nil {
		opts.Logger.Info("bmc-cert-init: BMC TLS management initialized",
			"device_id", deviceID,
			"node_id", opts.NodeID,
			"backend", opts.BMCConfig.Backend)
	}
	return nil
}

// CertManagementScheduler returns the in-process scheduler engine
// for cert renewal wiring, adapted to the SchedulerService interface
// InitCertManagement expects. Returns nil when the scheduler is not
// enabled on the embedded quicbaas service.
func (app *App) CertManagementScheduler() SchedulerService {
	svc := app.QuicBaaSService()
	if svc == nil {
		return nil
	}
	eng := svc.SchedulerEngine()
	if eng == nil {
		return nil
	}
	return eng
}

// InitCertManagement is the single-call platform-wide cert management
// wiring. It:
//
//  1. Ensures app.CertTargets (the registry) is initialized.
//  2. Registers the platform.cert-renewal scheduler handler + per-node
//     recurring job (idempotent -- re-runs of boot leave jobs alone).
//  3. Optionally initializes BMC TLS management when app.BMCConfig is
//     present (issues the initial cert, registers the target).
//
// Webservice cert targets register themselves during
// issueWebServiceCertificate -- this wrapper does not iterate them.
// Call this AFTER InitWebServer so webservice targets already exist
// in the registry.
//
// scheduler and nodeID must come from the platform's quicbaas
// integration: the embedded SchedulerEngine for scheduler and the
// local node's stable identifier (Raft node ID, hostname, or
// deployment-level tag) for nodeID.
//
// Typical caller shape (in pkg/daemon/commands/serve.go after
// InitWebServer returns):
//
//	if err := App.InitCertManagement(ctx, App.Scheduler, App.NodeID); err != nil {
//	    logger.Error(err, "cert management init failed")
//	    // fatal or non-fatal per deployment policy
//	}
func (app *App) InitCertManagement(ctx context.Context, scheduler SchedulerService, nodeID string) error {
	if scheduler == nil {
		return ErrCertRenewalMissingScheduler
	}
	if nodeID == "" {
		return ErrInitBMCCertMissingNodeID
	}

	// Ensure registry is live so downstream calls have somewhere to
	// register/read.
	reg := app.certTargets()

	// If BMC is configured, run the BMC-specific init which also
	// registers its target into the same registry.
	if app.BMCConfig != nil && app.BMCConfig.Certificate != nil {
		if err := initBMCCertManagement(ctx, bmcCertInitOptions{
			BMCConfig:     app.BMCConfig,
			NodeID:        nodeID,
			ACMEIssuer:    app.ACMEClient,
			LocalCAIssuer: app.CA,
			DNSUpdater:    app.DNSService,
			Hostmaster:    app.Hostmaster,
			Scheduler:     scheduler,
			Registry:      reg,
			Logger:        nil, // see note below on logger adaptation
		}); err != nil {
			return err
		}
		return nil // BMC path internally calls RegisterCertRenewal
	}

	// No BMC configured -- register the renewal handler + job just
	// so webservice targets (or any future target kind) still get
	// swept.
	return RegisterCertRenewal(ctx, CertRenewalRegistration{
		Scheduler: scheduler,
		Registry:  reg,
		NodeID:    nodeID,
	})
}

// deriveBMCDeviceID produces a stable device ID for the CertTarget
// Name. Prefers the BMC's CN (unique, stable) when present; falls
// back to the BMC address with colons/dots escaped; last resort is
// the NodeID itself.
func deriveBMCDeviceID(cfg *bmc.Config, nodeID string) string {
	if cfg == nil {
		return nodeID
	}
	if cfg.Certificate != nil {
		if cn := cfg.Certificate.Subject.CommonName; cn != "" {
			return cn
		}
	}
	if cfg.Address != "" {
		s := strings.NewReplacer(":", "-", ".", "-").Replace(cfg.Address)
		return fmt.Sprintf("%s-%d", s, cfg.Port)
	}
	return nodeID
}
