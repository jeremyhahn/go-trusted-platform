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

package compute

import (
	"context"
	"os"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
)

// Compile-time proof that QEMUOrchestrator provides the VM migration
// capability.
var _ VMMigrator = (*QEMUOrchestrator)(nil)

// mbpsToBytesPerSecond converts a megabits-per-second rate to bytes per second
// (the unit QEMU's migrate max-bandwidth parameter expects): Mbps * 1e6 / 8.
const mbpsToBytesPerSecond = 125000

// migrationStatusPollInterval is the delta window used when polling QEMU for
// migration completion. Polling is ticker-driven (never time.Sleep) and honors
// context cancellation.
var migrationStatusPollInterval = 250 * time.Millisecond

// MigrationSession is the QMP surface a migration drives on the source VM's
// monitor. It composes the vCPU pause/resume controls (for a consistent cold
// transfer), the QMP object-add used to install migration TLS credentials, the
// QEMU migration verbs, and the quit used to retire the source after the guest
// has moved. The real session wraps a *qemu.Monitor and a
// *qemu.MigrationManager; unit tests substitute a fake so no real VM is needed.
type MigrationSession interface {
	// Pause stops guest vCPUs (QMP "stop") so a cold migration transfers a
	// quiescent guest.
	Pause(ctx context.Context) error

	// Resume restarts guest vCPUs (QMP "cont"), used to roll back a failed cold
	// migration.
	Resume(ctx context.Context) error

	// ObjectAdd creates a QMP QOM object (used to install the tls-creds-x509
	// migration credentials).
	ObjectAdd(ctx context.Context, qomType, id string, props map[string]interface{}) error

	// SetParameters applies migration parameters (bandwidth cap, TLS creds,
	// TLS hostname).
	SetParameters(ctx context.Context, params *qemu.MigrationParams) error

	// SetCapabilities enables migration capabilities (e.g. block migration for
	// a cold transfer without shared storage).
	SetCapabilities(ctx context.Context, caps []string) error

	// Migrate begins streaming to the destination URI.
	Migrate(ctx context.Context, uri string) error

	// Status queries the current migration status.
	Status(ctx context.Context) (*qemu.MigrationStatus, error)

	// Cancel aborts an in-progress migration.
	Cancel(ctx context.Context) error

	// Quit shuts down the source QEMU process after the guest has migrated
	// away (QMP "quit"), releasing its resources.
	Quit(ctx context.Context) error
}

// realMigrateSession is the production MigrationSession backed by a live QMP
// monitor and the QEMU migration manager.
type realMigrateSession struct {
	mon *qemu.Monitor
	mgr *qemu.MigrationManager
}

func (s *realMigrateSession) Pause(ctx context.Context) error  { return s.mon.Pause(ctx) }
func (s *realMigrateSession) Resume(ctx context.Context) error { return s.mon.Resume(ctx) }

func (s *realMigrateSession) ObjectAdd(ctx context.Context, qomType, id string, props map[string]interface{}) error {
	args := map[string]interface{}{"qom-type": qomType, "id": id}
	for k, v := range props {
		args[k] = v
	}
	_, err := s.mon.Run(ctx, "object-add", args)
	return err
}

func (s *realMigrateSession) SetParameters(ctx context.Context, params *qemu.MigrationParams) error {
	return s.mgr.SetParameters(ctx, params)
}

func (s *realMigrateSession) SetCapabilities(ctx context.Context, caps []string) error {
	return s.mgr.SetCapabilities(ctx, caps)
}

func (s *realMigrateSession) Migrate(ctx context.Context, uri string) error {
	return s.mgr.Migrate(ctx, uri)
}

func (s *realMigrateSession) Status(ctx context.Context) (*qemu.MigrationStatus, error) {
	return s.mgr.Status(ctx)
}

func (s *realMigrateSession) Cancel(ctx context.Context) error {
	return s.mgr.Cancel(ctx)
}

func (s *realMigrateSession) Quit(ctx context.Context) error {
	_, err := s.mon.Run(ctx, "quit", nil)
	return err
}

// vmMigrationSessionFor connects the instance's QMP monitor (reusing an
// existing connection) and returns a migration session bound to it. It is a
// package-level seam so unit tests can substitute a fake without a real VM.
var vmMigrationSessionFor = defaultVMMigrationSessionFor

func defaultVMMigrationSessionFor(ctx context.Context, o *QEMUOrchestrator, inst *qemuInstance) (MigrationSession, error) {
	mon := inst.vm.Monitor()
	if mon == nil || !mon.IsConnected() {
		if err := inst.vm.ConnectMonitor(ctx); err != nil {
			return nil, &WrappedError{Msg: "failed to connect QMP monitor", Err: err}
		}
		mon = inst.vm.Monitor()
	}
	return &realMigrateSession{mon: mon, mgr: qemu.NewMigrationManager(mon, o.logger)}, nil
}

// MigrateVM migrates a running VM to a peer daemon. Cold migration (the default)
// pauses the guest and transfers RAM + block devices over a TLS-secured stream,
// working without shared storage; live migration keeps the guest running and
// requires shared storage to be declared in the orchestrator config. Both modes
// coordinate the destination receiver through the MigrationCoordinator seam and
// authenticate the stream with CA-issued migration TLS credentials.
func (o *QEMUOrchestrator) MigrateVM(ctx context.Context, instanceID, destination string, opts MigrateOptions) (*MigrationResult, error) {
	if instanceID == "" {
		return nil, ErrInvalidInstanceID
	}
	if destination == "" {
		return nil, ErrMigrationDestinationRequired
	}

	coordinator := o.config.MigrationCoordinator
	if coordinator == nil {
		return nil, ErrMigrationNotConfigured
	}
	tlsProvider := o.config.MigrationTLS
	if tlsProvider == nil {
		return nil, ErrMigrationTLSNotConfigured
	}

	// Resolve migration mode. Live migration is gated on explicit shared
	// storage; requesting it without shared storage is a hard error rather than
	// a silent downgrade.
	mode := MigrateModeCold
	if opts.Live {
		if !o.config.SharedStorageEnabled() {
			return nil, ErrLiveMigrationRequiresSharedStorage
		}
		mode = MigrateModeLive
	}

	o.mu.RLock()
	inst, exists := o.instances[instanceID]
	o.mu.RUnlock()
	if !exists {
		return nil, ErrInstanceNotFound
	}

	// Migration requires a running guest with a live QMP monitor.
	state, err := o.lifecycle.GetState(instanceID)
	if err != nil {
		return nil, err
	}
	if state != StateRunning {
		return nil, &SentinelCauseError{Sentinel: ErrInstanceNotRunning, Cause: &MessageError{Msg: "migration requires a running VM"}}
	}

	inst.mu.Lock()
	spec := MigrationSpec{
		InstanceID: instanceID,
		VMName:     inst.instance.Name,
		Mode:       mode,
		Arch:       o.config.Arch.OrDefault(),
		Config:     inst.instance.Config,
	}
	inst.mu.Unlock()

	// Ask the destination daemon to launch a receiver and hand back the target.
	endpoint, err := coordinator.PrepareIncoming(ctx, destination, spec)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrMigrationFailed, Cause: &WrappedError{Msg: "destination prepare-incoming failed", Err: err}}
	}

	session, err := vmMigrationSessionFor(ctx, o, inst)
	if err != nil {
		// Best-effort abort so the destination reaps the idle receiver.
		_ = coordinator.Finalize(context.WithoutCancel(ctx), destination, spec, err)
		return nil, err
	}

	// Provision the migration TLS credentials from platform CA material. The
	// stream is never established in plaintext.
	credsID, err := tlsProvider.EnsureTLSCreds(ctx, session, endpoint)
	if err != nil {
		_ = coordinator.Finalize(context.WithoutCancel(ctx), destination, spec, err)
		return nil, &SentinelCauseError{Sentinel: ErrMigrationFailed, Cause: &WrappedError{Msg: "migration TLS setup failed", Err: err}}
	}

	params := &qemu.MigrationParams{
		TLSCreds:    credsID,
		TLSHostname: endpoint.TLSHostname,
	}
	if opts.BandwidthLimitMbps > 0 {
		params.MaxBandwidth = int64(opts.BandwidthLimitMbps) * mbpsToBytesPerSecond
	}
	if err := session.SetParameters(ctx, params); err != nil {
		_ = coordinator.Finalize(context.WithoutCancel(ctx), destination, spec, err)
		return nil, &SentinelCauseError{Sentinel: ErrMigrationFailed, Cause: &WrappedError{Msg: "migrate-set-parameters failed", Err: err}}
	}

	// Cold migration transfers block devices (no shared storage) and pauses the
	// guest for a consistent copy; live migration streams RAM only against the
	// shared backing store.
	var caps []string
	paused := false
	if mode == MigrateModeCold {
		caps = append(caps, "block")
		if err := session.Pause(ctx); err != nil {
			_ = coordinator.Finalize(context.WithoutCancel(ctx), destination, spec, err)
			return nil, &SentinelCauseError{Sentinel: ErrMigrationFailed, Cause: &WrappedError{Msg: "pause for cold migration failed", Err: err}}
		}
		paused = true
	}
	if err := session.SetCapabilities(ctx, caps); err != nil {
		o.rollbackMigration(ctx, session, coordinator, destination, spec, paused)
		return nil, &SentinelCauseError{Sentinel: ErrMigrationFailed, Cause: &WrappedError{Msg: "migrate-set-capabilities failed", Err: err}}
	}

	if err := session.Migrate(ctx, endpoint.URI); err != nil {
		o.rollbackMigration(ctx, session, coordinator, destination, spec, paused)
		return nil, &SentinelCauseError{Sentinel: ErrMigrationFailed, Cause: &WrappedError{Msg: "migrate command failed", Err: err}}
	}

	if err := o.waitMigration(ctx, session); err != nil {
		o.rollbackMigration(ctx, session, coordinator, destination, spec, paused)
		return nil, err
	}

	// The guest now runs on the destination. Finalize so it registers and
	// resumes the received VM, then retire the source copy.
	if err := coordinator.Finalize(ctx, destination, spec, nil); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrMigrationFailed, Cause: &WrappedError{Msg: "destination finalize failed", Err: err}}
	}

	// Retire the local copy: the source QEMU is quit (releasing its resources)
	// and the bookkeeping dropped. The guest already moved, so this never goes
	// through Stop's process-kill path; failures are logged, not fatal, because
	// ownership has already transferred.
	if err := session.Quit(context.WithoutCancel(ctx)); err != nil {
		o.logger.Warnf("migration: source quit for %s failed after successful transfer: %v", instanceID, err)
	}
	o.retireMigratedInstance(instanceID)

	o.logger.Infof("Migrated VM %s to %s (%s)", instanceID, destination, mode)
	return &MigrationResult{Mode: mode, Success: true, Message: "migration completed"}, nil
}

// retireMigratedInstance drops all bookkeeping for a VM that has successfully
// migrated to another host: the instance map entry, the port mapping, the
// console broker, the lifecycle record, and the on-disk work directory. It does
// NOT go through Stop (the guest process has already handed off), so it is safe
// even when the source QEMU has exited on its own.
func (o *QEMUOrchestrator) retireMigratedInstance(instanceID string) {
	o.mu.Lock()
	inst, ok := o.instances[instanceID]
	if !ok {
		o.mu.Unlock()
		return
	}
	var workDir string
	if inst.instance != nil && inst.instance.Config != nil {
		workDir = inst.instance.Config.WorkDir
	}
	delete(o.instances, instanceID)
	delete(o.instanceToPort, instanceID)
	o.mu.Unlock()

	o.closeConsole(instanceID)
	if err := o.lifecycle.DeleteInstance(instanceID); err != nil {
		o.logger.Warnf("migration: lifecycle cleanup for %s failed: %v", instanceID, err)
	}
	if workDir != "" {
		if err := os.RemoveAll(workDir); err != nil {
			o.logger.Warnf("migration: work directory cleanup for %s failed: %v", instanceID, err)
		}
	}
}

// rollbackMigration cancels an in-flight migration, resumes a cold-paused guest,
// and aborts the destination receiver. Every step is best-effort: the function
// exists to leave the source usable after a mid-migration failure.
func (o *QEMUOrchestrator) rollbackMigration(ctx context.Context, session MigrationSession, coordinator MigrationCoordinator, destination string, spec MigrationSpec, paused bool) {
	detached := context.WithoutCancel(ctx)
	if err := session.Cancel(detached); err != nil {
		o.logger.Warnf("migration rollback: cancel failed for %s: %v", spec.InstanceID, err)
	}
	if paused {
		if err := session.Resume(detached); err != nil {
			o.logger.Warnf("migration rollback: resume failed for %s: %v", spec.InstanceID, err)
		}
	}
	if err := coordinator.Finalize(detached, destination, spec, ErrMigrationFailed); err != nil {
		o.logger.Warnf("migration rollback: destination finalize failed for %s: %v", spec.InstanceID, err)
	}
}

// waitMigration polls QEMU migration status until it reaches a terminal state
// or the context is cancelled. Polling is ticker-driven (never time.Sleep).
func (o *QEMUOrchestrator) waitMigration(ctx context.Context, session MigrationSession) error {
	ticker := time.NewTicker(migrationStatusPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = session.Cancel(context.WithoutCancel(ctx))
			return ctx.Err()
		case <-ticker.C:
			status, err := session.Status(ctx)
			if err != nil {
				return &SentinelCauseError{Sentinel: ErrMigrationFailed, Cause: &WrappedError{Msg: "query-migrate failed", Err: err}}
			}
			switch status.Status {
			case qemu.MigrationStatusCompleted:
				return nil
			case qemu.MigrationStatusFailed, qemu.MigrationStatusCancelled:
				msg := status.ErrorDescription
				if msg == "" {
					msg = string(status.Status)
				}
				return &SentinelCauseError{Sentinel: ErrMigrationFailed, Cause: &MessageError{Msg: msg}}
			default:
				// setup / active / device / postcopy — keep polling.
			}
		}
	}
}
