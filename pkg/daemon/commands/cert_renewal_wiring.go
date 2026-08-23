// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package commands

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// initCertManagement registers the platform-wide certificate renewal sweep.
//
// It is deliberately WARN-AND-CONTINUE rather than fatal, matching the NTP
// startup gate: a node that cannot schedule renewal is degraded, not broken,
// and refusing to boot would take a serving node down over a future problem.
// The warning names the consequence explicitly, because the failure is
// otherwise completely silent — certificates simply stop being renewed and
// nothing says so until something expires.
//
// It is called from BOTH daemon run paths. runDaemonOnly needs it as much as
// runWithWebservices does: a node configured with bmc.certificate but no
// webservices takes the daemon-only path, and BMC certificates need renewing
// whether or not this node happens to serve HTTP.
//
// If deployment policy should instead fail closed, this is the single place to
// change it.
func initCertManagement(ctx context.Context, logger *logging.Logger, a *app.App) {
	if a == nil {
		logger.Warn("certificate renewal NOT scheduled: the platform application " +
			"failed to initialize. Certificates on this node will run to expiry.")
		return
	}

	scheduler := a.CertManagementScheduler()
	if scheduler == nil {
		logger.Warn("certificate renewal NOT scheduled: no scheduler engine available. " +
			"Webservice and BMC certificates will not be renewed on this node and will " +
			"run to expiry. Enable the scheduler on the embedded service to restore renewal.")
		return
	}

	// The node's stable identifier, also used for the IAK and IDevID CNs. It
	// becomes the job's NodeAffinity, so in a multi-node fleet only the owning
	// node renews its own targets.
	nodeID := a.Hostname
	if nodeID == "" {
		logger.Warn("certificate renewal NOT scheduled: node has no hostname, so renewal " +
			"jobs cannot be given a stable NodeAffinity. Certificates will run to expiry.")
		return
	}

	if err := a.InitCertManagement(ctx, scheduler, nodeID); err != nil {
		logger.Error(err, "certificate renewal NOT scheduled: certificates on this node "+
			"will run to expiry")
		return
	}

	logger.Info("certificate renewal scheduled", "node", nodeID)
}

// initACMEClientForCertManagement initializes App.ACMEClient when a BMC
// certificate is configured for ACME issuance and no client exists yet.
//
// Required on BOTH boot paths, not just the daemon-only one. It is tempting to
// think runWithWebservices already has a client, because issueWebServiceCertificate
// initializes one as a side effect — but on an ordinary restart InitWebServer
// finds the certificate already in the CA and jumps to certLoaded, skipping
// issuance entirely. That is the same restart path that left the cert-target
// registry empty before this change; it also leaves App.ACMEClient nil.
//
// With RequireACME set, a nil issuer means BMC provisioning fails. Combined with
// a captured issuer it meant failing forever, which is why the target now
// resolves the issuer lazily.
//
// Failure is warn-and-continue. It must not take the daemon down, and it must
// not be papered over either: with no ACME client, BMC issuance now refuses
// rather than substituting the local CA, so the consequence is one target that
// cannot renew — not a certificate quietly signed by the wrong authority.
func initACMEClientForCertManagement(ctx context.Context, logger *logging.Logger, a *app.App) {
	if a == nil || a.ACMEClient != nil {
		return
	}
	if a.BMCConfig == nil || a.BMCConfig.Certificate == nil {
		return
	}
	if a.BMCConfig.Certificate.ACME == nil || a.BMCConfig.Certificate.ACME.Challenge == "" {
		return
	}
	if a.ACMEConfig == nil || a.ACMEConfig.Client == nil {
		logger.Warn("BMC is configured for ACME issuance but no ACME client is " +
			"configured on this node. Its certificate cannot be issued or renewed; " +
			"the platform will NOT substitute the local CA.")
		return
	}
	err := a.InitACMEClient(ctx, true)
	if err == nil {
		return
	}

	// Retry through BootstrapTrust, exactly as issueWebServiceCertificate does.
	// The CA bundle is usually already in the OS trust store (put there by the
	// ISO installer or platform-initrd), so the first attempt normally succeeds;
	// on a node where it is not, the first attempt fails on TLS and bootstrapping
	// the trust is what fixes it. Omitting this retry would have made "parity
	// with the webservice path" untrue in precisely the case it matters.
	logger.Warn("ACME client init failed, attempting trust bootstrap", "error", err)

	if err := a.BootstrapTrust(ctx); err != nil {
		logger.Error(err, "trust bootstrap failed; the BMC certificate cannot be "+
			"issued or renewed. The platform will NOT substitute the local CA.")
		return
	}
	if err := a.InitACMEClient(ctx, true); err != nil {
		logger.Error(err, "ACME client init failed after trust bootstrap; the BMC "+
			"certificate cannot be issued or renewed until this is resolved. The "+
			"platform will NOT substitute the local CA.")
	}
}
