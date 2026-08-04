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
	"errors"
)

// =============================================================================
// VM migration capability
// =============================================================================
//
// Migration moves a running VM from this daemon (the source) to a peer
// platformd (the destination). Two modes are supported:
//
//   - Cold migration is ALWAYS available and works WITHOUT shared storage: the
//     source pauses the guest, then QEMU streams both RAM and block devices to
//     a receiving QEMU the destination daemon launched, over a TLS-secured
//     channel. The guest is consistent because its vCPUs are stopped for the
//     transfer.
//
//   - Live migration keeps the guest running and is gated on an explicit
//     shared-storage declaration in the orchestrator config (SharedStorage):
//     only RAM is streamed because the destination reaches the same backing
//     store. Requesting live migration without shared storage fails with a
//     typed error rather than silently degrading.
//
// The migration transport is ALWAYS TLS: the source provisions QEMU migration
// tls-creds from platform CA material via the MigrationTLSProvider seam and
// pins the destination hostname. Plaintext migration is never attempted (no
// InsecureSkipVerify anywhere).
//
// The destination side of the handshake is abstracted behind the
// MigrationCoordinator seam: the source asks the destination (addressed by the
// destination host:port of its mTLS gRPC endpoint) to prepare an incoming
// receiver, streams to the returned endpoint, then finalizes so the destination
// registers the received VM (or, on failure, aborts and cleans up).

// MigrateMode is the migration strategy that was actually chosen for a request.
type MigrateMode string

const (
	// MigrateModeCold pauses the guest and transfers RAM + disks (no shared
	// storage required).
	MigrateModeCold MigrateMode = "cold"

	// MigrateModeLive keeps the guest running and transfers RAM only (requires
	// shared storage).
	MigrateModeLive MigrateMode = "live"
)

// MigrateOptions controls a VM migration request.
type MigrateOptions struct {
	// Live requests a live (shared-storage) migration. When false a cold
	// migration is performed.
	Live bool

	// BandwidthLimitMbps optionally caps the migration transfer rate in
	// megabits per second. Zero means unlimited.
	BandwidthLimitMbps uint64
}

// MigrationResult reports the outcome of a completed migration.
type MigrationResult struct {
	// Mode is the migration strategy that was performed.
	Mode MigrateMode

	// Success is true when the guest now runs on the destination and the source
	// copy has been retired.
	Success bool

	// Message is a human-readable summary.
	Message string
}

// MigrationSpec describes the VM being migrated so the destination daemon can
// launch a matching receiver.
type MigrationSpec struct {
	// InstanceID is the source instance identifier.
	InstanceID string

	// VMName is the guest name.
	VMName string

	// Mode is the requested migration strategy.
	Mode MigrateMode

	// Config is the source VM's configuration (memory, cpus, disks, boot mode)
	// the destination needs to launch an identical receiver.
	Config *InstanceConfig
}

// IncomingEndpoint is the destination-provided migration target the source
// streams to.
type IncomingEndpoint struct {
	// URI is the QEMU migration URI the source hands to the migrate command
	// (for example "tcp:dest.example:49152").
	URI string

	// TLSHostname is the destination hostname the source pins in the migration
	// tls-creds so the encrypted stream authenticates the receiver.
	TLSHostname string
}

// MigrationCoordinator abstracts the destination-daemon side of a migration.
// The production implementation dials the destination platformd over mTLS and
// drives a prepare/finalize RPC pair; unit tests substitute a fake.
type MigrationCoordinator interface {
	// PrepareIncoming asks the destination daemon (addressed by host:port) to
	// launch a receiving QEMU for the VM described by spec and returns the
	// endpoint the source should stream to.
	PrepareIncoming(ctx context.Context, destination string, spec MigrationSpec) (*IncomingEndpoint, error)

	// Finalize notifies the destination that the transfer finished. When
	// streamErr is nil the destination registers and resumes the received VM;
	// otherwise it aborts the receiver and releases its resources.
	Finalize(ctx context.Context, destination string, spec MigrationSpec, streamErr error) error
}

// MigrationTLSProvider supplies the TLS credentials QEMU uses to encrypt and
// authenticate the migration stream. The production implementation provisions a
// QMP tls-creds-x509 object from platform CA material (reached through the
// quicbaas SDK Certificate service); it never configures a plaintext channel.
type MigrationTLSProvider interface {
	// EnsureTLSCreds provisions the migration TLS credentials on the source VM's
	// QMP monitor for a transfer to endpoint and returns the QMP tls-creds
	// object ID to reference from migrate-set-parameters.
	EnsureTLSCreds(ctx context.Context, session MigrationSession, endpoint *IncomingEndpoint) (credsID string, err error)
}

// VMMigrator is the capability interface for migrating a running VM to a peer
// daemon. QEMUOrchestrator implements it; container orchestrators do not, so
// protocol surfaces reject the operation with a typed capability-not-supported
// error rather than a silent stub.
type VMMigrator interface {
	// MigrateVM migrates the running VM identified by instanceID to destination
	// (the destination daemon's mTLS gRPC host:port), choosing cold or live per
	// opts and the orchestrator's shared-storage configuration.
	MigrateVM(ctx context.Context, instanceID, destination string, opts MigrateOptions) (*MigrationResult, error)
}

// =============================================================================
// Migration sentinel errors
// =============================================================================

var (
	// ErrMigrationNotConfigured is returned when no MigrationCoordinator is
	// wired into the orchestrator, so it cannot address a destination daemon.
	ErrMigrationNotConfigured = errors.New("VM migration coordinator not configured")

	// ErrMigrationTLSNotConfigured is returned when no MigrationTLSProvider is
	// wired in. Migration is never attempted in plaintext.
	ErrMigrationTLSNotConfigured = errors.New("VM migration TLS provider not configured")

	// ErrLiveMigrationRequiresSharedStorage is returned when a live migration is
	// requested but the orchestrator config does not declare shared storage.
	ErrLiveMigrationRequiresSharedStorage = errors.New("live migration requires shared storage to be configured")

	// ErrMigrationDestinationRequired is returned when the destination address
	// is empty.
	ErrMigrationDestinationRequired = errors.New("migration destination is required")

	// ErrMigrationFailed is returned when the QEMU migration stream reports a
	// failed terminal status.
	ErrMigrationFailed = errors.New("VM migration failed")
)
