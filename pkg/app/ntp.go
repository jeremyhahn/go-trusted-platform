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
	"errors"
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ntp"
)

// ErrNTPStartupGate is returned when the startup sync gate expires and the
// configured policy is fail-startup. It wraps the underlying timeout so
// callers can inspect the deadline that was missed.
type ErrNTPStartupGate struct{ Cause error }

// Error implements the error interface.
func (e ErrNTPStartupGate) Error() string {
	return "platform startup aborted: " + e.Cause.Error()
}

// Unwrap returns the underlying timeout.
func (e ErrNTPStartupGate) Unwrap() error { return e.Cause }

// ntpService is the subset of *ntp.Service that platform bring-up drives.
// Declaring it as an interface lets unit tests exercise the startup policy
// without configuring chrony on the host.
type ntpService interface {
	// Apply renders chrony.conf and manages the OpenRC service.
	Apply(ctx context.Context) error

	// RotateNTSMaterial deploys renewed NTS key material into the running
	// chrony under the service's own lock (certificate renewal). The
	// private key travels in a protected-memory enclave owned by the
	// caller; the certificate is public.
	RotateNTSMaterial(ctx context.Context, key *memguard.MemoryEnclave, certPEM []byte) error

	// WaitForSync blocks until the clock converges or the gate expires.
	WaitForSync(ctx context.Context) error

	// CheckServeNames resolves the advertised NTS-KE server names and
	// latches the ones this node's own allow list refuses, so the `ntp`
	// health component reports them. It never fails: an unresolvable name
	// yields no finding.
	CheckServeNames(ctx context.Context, resolver ntp.NameResolver) []ntp.ServeNameFinding
}

// newNTPService builds the platform time service. Tests replace it to keep
// bring-up entirely in memory.
var newNTPService = func(config *ntp.Config, logger *slog.Logger) (ntpService, *ntp.Service, error) {
	service, err := ntp.NewService(config, ntp.WithLogger(logger))
	if err != nil {
		return nil, nil, err
	}
	return service, service, nil
}

// StartNTP brings the node's clock under platform control.
//
// It runs AFTER network bring-up (initSDN) and BEFORE TPM/CA initialization,
// because every downstream trust decision — TPM attestation freshness, ACME
// issuance, DANE/DNSSEC signature windows, JWT exp/nbf — is only meaningful
// against a correct clock. node-02 booted two years slow with no time
// daemon at all; that class of failure is what this gate prevents.
//
// Following the platform's explicit-configuration convention, an absent or
// disabled `ntp:` section is a no-op: platformd never touches chrony.
//
// Failure handling mirrors initSDN and StartDNS: configuration is validated
// at load time (fatal), while runtime failures are logged and the node keeps
// booting with the ntp health component reporting the degraded state. The one
// exception is an expired startup gate with on-timeout: fail-startup, which
// aborts bring-up by contract.
func (app *App) StartNTP(ctx context.Context) error {
	if !app.NTPConfig.Active() {
		return nil
	}

	service, concrete, err := newNTPService(app.NTPConfig, app.Logger.Slog())
	if err != nil {
		// A malformed section is an operator configuration bug, not a
		// transient runtime condition: refuse to start.
		return err
	}
	// NTPService is the API-layer backend; it stays nil when the test seam
	// supplies a substitute so no fake ever reaches a transport. ntpApplier
	// is the deploy path certificate renewal drives to restart chrony with
	// rotated NTS material.
	app.NTPService = concrete
	app.ntpApplier = service

	if applyErr := service.Apply(ctx); applyErr != nil {
		app.Logger.Errorf("NTP: failed to configure chrony: %v", applyErr)
		return nil
	}

	// The allow list chronyd will enforce has just been rendered, so this
	// is the first moment the node can tell whether the NTS-KE names it
	// advertises resolve to an address it is willing to answer. A name
	// that does not is a configuration the operator must reconcile: the
	// handshake succeeds and the time never arrives.
	app.CheckNTSServeNames(ctx)

	if syncErr := service.WaitForSync(ctx); syncErr != nil {
		return app.handleNTPGateTimeout(syncErr)
	}

	return nil
}

// handleNTPGateTimeout applies the configured on-timeout policy. The approved
// default (warn-and-continue) boots the node and leaves it flagged
// time-unsynced in health status so fleet monitoring surfaces it, rather than
// letting a silently-wrong clock corrupt attestation and certificate
// validity.
func (app *App) handleNTPGateTimeout(cause error) error {
	var timeout ntp.ErrSyncTimeout
	if !errors.As(cause, &timeout) {
		app.Logger.Errorf("NTP: startup gate failed: %v", cause)
		return nil
	}

	if app.NTPConfig.TimeoutAction() == ntp.ActionFailStartup {
		return ErrNTPStartupGate{Cause: cause}
	}

	app.Logger.Warnf("NTP: %v — continuing startup with the node flagged time-unsynced; "+
		"attestation freshness, ACME issuance, DANE signature windows and JWT validity "+
		"cannot be trusted until the clock converges", cause)
	return nil
}

// CheckNTSServeNames resolves the advertised NTS-KE server names against the
// rendered allow list and latches any mismatch onto the `ntp` health
// component.
//
// It runs where the served identity is established or replaced — NTP
// bring-up and certificate renewal — because those are the moments the
// advertised set or the allow list can change. It is deliberately
// non-fatal and returns nothing: a mismatch is an operator decision (widen
// the allow list, or publish the name on a segment already allowed) and the
// platform reports it rather than choosing.
func (app *App) CheckNTSServeNames(ctx context.Context) {
	if app.ntpApplier == nil || !app.NTPConfig.NTSServing() {
		return
	}
	findings := app.ntpApplier.CheckServeNames(ctx, app.ntsNameResolver)
	if len(findings) == 0 {
		return
	}
	for _, finding := range findings {
		app.Logger.Warnf("NTP: this node serves an NTS-KE certificate for %s but refuses time to it — %s",
			finding.Name, finding.String())
	}
}
