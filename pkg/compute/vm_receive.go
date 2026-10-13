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
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
)

// =============================================================================
// VM migration — destination (receiver) side
// =============================================================================
//
// ReceiveIncoming is the peer of MigrateVM (pkg/compute/qemu_migrate.go). The
// source daemon asks a destination daemon — over the mTLS PrepareMigration RPC —
// to stand up a receiver for an inbound guest. The destination:
//
//   1. materializes short-lived, CA-issued server migration TLS credentials
//      (MigrationServerTLSProvider) so the stream authenticates mutually and is
//      never accepted in plaintext;
//   2. launches a receiving QEMU with "-incoming defer" + the server tls-creds
//      object, then over QMP sets tls-creds and issues migrate-incoming on
//      compute.migration_listen_address (an ephemeral port when its port is 0);
//   3. returns the port and the TLS hostname the source must pin.
//
// FinalizeIncoming commits (resume the received guest) or aborts (tear the
// receiver down) once the source reports the transfer outcome.
//
// The QEMUOrchestrator struct lives in qemu.go and is not extended here; the
// per-orchestrator receiver bookkeeping is kept in a package-level registry
// keyed by the orchestrator pointer so this capability is fully additive.

// Compile-time proof that QEMUOrchestrator provides the destination side of a
// migration.
var _ MigrationReceiver = (*QEMUOrchestrator)(nil)

// ReceiverHandle is what a destination daemon returns to the migrating source so
// it can address the receiver and pin its TLS identity.
type ReceiverHandle struct {
	// ReceiverID is the opaque token the source passes back to
	// FinalizeMigration to commit or abort this receiver.
	ReceiverID string

	// Port is the TCP port the receiving QEMU listens on for the migration
	// stream. The source combines it with the destination host it dialed to
	// form the QEMU migrate URI.
	Port int

	// TLSHostname is the hostname the receiver's migration certificate is issued
	// for; the source pins it in migrate-set-parameters tls-hostname.
	TLSHostname string
}

// MigrationReceiver is the destination-side capability for a VM migration.
// QEMUOrchestrator implements it; container orchestrators do not.
type MigrationReceiver interface {
	// ReceiveIncoming launches a receiving QEMU for the VM described by spec and
	// returns the endpoint (port + TLS hostname) the source streams to.
	ReceiveIncoming(ctx context.Context, spec MigrationSpec) (*ReceiverHandle, error)

	// FinalizeIncoming commits (commit=true: resume the received guest) or
	// aborts (commit=false: tear the receiver down) the receiver identified by
	// receiverID.
	FinalizeIncoming(ctx context.Context, receiverID string, commit bool) error
}

// MigrationServerTLSProvider materializes a directory of QEMU tls-creds-x509
// SERVER credentials (server-cert.pem / server-key.pem / ca-cert.pem) from
// platform CA material for a receiving QEMU launched with -incoming. It is the
// destination-side complement of MigrationTLSProvider (which installs client
// credentials on a live source session). The production concrete satisfies both
// interfaces; ReceiveIncoming type-asserts the configured MigrationTLS provider
// for this capability so no additional config seam is required.
type MigrationServerTLSProvider interface {
	// MaterializeServerCreds issues a short-lived server certificate for
	// hostname, writes the QEMU-expected PEM files into a private directory, and
	// returns that directory alongside a cleanup that removes it. The returned
	// directory is passed to QEMU's "-object tls-creds-x509,endpoint=server".
	MaterializeServerCreds(ctx context.Context, hostname string) (credsDir string, cleanup func(), err error)
}

// =============================================================================
// Receiver-side sentinel errors
// =============================================================================

var (
	// ErrMigrationSpecRequired is returned when ReceiveIncoming is called
	// without a VM configuration to launch the receiver from.
	ErrMigrationSpecRequired = errors.New("migration spec configuration is required")

	// ErrMigrationServerTLSNotConfigured is returned when the configured
	// migration TLS provider cannot supply destination (server) credentials.
	// The receiver is never launched without TLS.
	ErrMigrationServerTLSNotConfigured = errors.New("VM migration server TLS provider not configured")

	// ErrReceiverNotFound is returned when FinalizeIncoming names a receiver
	// that was never prepared (or has already been finalized).
	ErrReceiverNotFound = errors.New("migration receiver not found")

	// ErrMigrationReceiveFailed is returned when the destination cannot stand up
	// or drive the receiving QEMU.
	ErrMigrationReceiveFailed = errors.New("VM migration receive failed")
)

// MigrationListenAddressError refuses a receiver whose bind address cannot be
// determined: compute.migration_listen_address is empty, or is not an IP:port
// a receiving QEMU can listen on. It names the setting and the value.
type MigrationListenAddressError struct {
	Address string
	Reason  string
}

func (e *MigrationListenAddressError) Error() string {
	if e.Address == "" {
		return "compute: migration receiver listen address undetermined: set compute.migration_listen_address"
	}
	return "compute: compute.migration_listen_address " + strconv.Quote(e.Address) + " " + e.Reason
}

// parseMigrationListenAddress resolves compute.migration_listen_address into
// the address a receiving QEMU binds. Port 0 asks for an ephemeral port.
func parseMigrationListenAddress(address string) (netip.AddrPort, error) {
	if address == "" {
		return netip.AddrPort{}, &MigrationListenAddressError{}
	}
	listen, err := netip.ParseAddrPort(address)
	if err != nil {
		return netip.AddrPort{}, &MigrationListenAddressError{Address: address, Reason: "is not an IP:port address"}
	}
	if listen.Addr().IsMulticast() {
		return netip.AddrPort{}, &MigrationListenAddressError{Address: address, Reason: "is a multicast address"}
	}
	return listen, nil
}

// =============================================================================
// Launch seam
// =============================================================================

// incomingReceiver is a launched destination-side receiver. The real
// implementation wraps a receiving *qemu.VM; unit tests substitute a fake so no
// real VM is needed.
type incomingReceiver interface {
	// Port returns the TCP port the receiver accepts the migration stream on.
	Port() int

	// Commit resumes the received guest after a successful transfer.
	Commit(ctx context.Context) error

	// Abort tears the receiver down after a failed or cancelled transfer.
	Abort(ctx context.Context) error
}

// incomingReceiverParams carries everything the launcher needs to stand up a
// receiver.
type incomingReceiverParams struct {
	orchestrator *QEMUOrchestrator
	spec         MigrationSpec
	credsDir     string
	listen       netip.AddrPort
}

// newIncomingReceiver launches a receiving QEMU. It is a package-level seam so
// unit tests can substitute a fake without a real VM or qemu binary.
var newIncomingReceiver = defaultNewIncomingReceiver

// =============================================================================
// Per-orchestrator receiver registry
// =============================================================================

// receiverStore maps a *QEMUOrchestrator to its receiverRegistry. It keeps the
// receiver bookkeeping additive so the QEMUOrchestrator struct (defined in
// qemu.go) does not have to change.
var receiverStore sync.Map // *QEMUOrchestrator -> *receiverRegistry

type receiverRegistry struct {
	mu        sync.Mutex
	receivers map[string]*trackedReceiver
}

// trackedReceiver pairs a launched receiver with the cleanup that releases its
// TLS credential material.
type trackedReceiver struct {
	recv    incomingReceiver
	cleanup func()
}

func receiversFor(o *QEMUOrchestrator) *receiverRegistry {
	if v, ok := receiverStore.Load(o); ok {
		return v.(*receiverRegistry)
	}
	reg := &receiverRegistry{receivers: make(map[string]*trackedReceiver)}
	actual, _ := receiverStore.LoadOrStore(o, reg)
	return actual.(*receiverRegistry)
}

func (r *receiverRegistry) put(id string, tr *trackedReceiver) {
	r.mu.Lock()
	r.receivers[id] = tr
	r.mu.Unlock()
}

func (r *receiverRegistry) take(id string) (*trackedReceiver, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	tr, ok := r.receivers[id]
	if ok {
		delete(r.receivers, id)
	}
	return tr, ok
}

// =============================================================================
// ReceiveIncoming / FinalizeIncoming
// =============================================================================

// ReceiveIncoming stands up a receiving QEMU for an inbound migration. See the
// package overview above for the full handshake.
func (o *QEMUOrchestrator) ReceiveIncoming(ctx context.Context, spec MigrationSpec) (*ReceiverHandle, error) {
	if spec.Config == nil {
		return nil, ErrMigrationSpecRequired
	}

	serverTLS, ok := o.config.MigrationTLS.(MigrationServerTLSProvider)
	if !ok || o.config.MigrationTLS == nil {
		return nil, ErrMigrationServerTLSNotConfigured
	}

	listen, err := parseMigrationListenAddress(o.config.MigrationListenAddress)
	if err != nil {
		return nil, err
	}

	// The receiver's certificate is issued for this host's name; the source pins
	// it as the migration tls-hostname.
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return nil, &SentinelCauseError{Sentinel: ErrMigrationReceiveFailed, Cause: &WrappedError{Msg: "resolve receiver hostname", Err: err}}
	}

	credsDir, cleanup, err := serverTLS.MaterializeServerCreds(ctx, hostname)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrMigrationReceiveFailed, Cause: &WrappedError{Msg: "materialize server migration TLS creds", Err: err}}
	}

	recv, err := newIncomingReceiver(ctx, &incomingReceiverParams{
		orchestrator: o,
		spec:         spec,
		credsDir:     credsDir,
		listen:       listen,
	})
	if err != nil {
		cleanup()
		return nil, &SentinelCauseError{Sentinel: ErrMigrationReceiveFailed, Cause: &WrappedError{Msg: "launch migration receiver", Err: err}}
	}

	receiverID := generateInstanceID()
	receiversFor(o).put(receiverID, &trackedReceiver{recv: recv, cleanup: cleanup})

	o.logger.Infof("Prepared migration receiver %s for VM %s on port %d", receiverID, spec.VMName, recv.Port())
	return &ReceiverHandle{
		ReceiverID:  receiverID,
		Port:        recv.Port(),
		TLSHostname: hostname,
	}, nil
}

// FinalizeIncoming commits or aborts a prepared receiver and always releases its
// TLS credential material.
func (o *QEMUOrchestrator) FinalizeIncoming(ctx context.Context, receiverID string, commit bool) error {
	if receiverID == "" {
		return ErrReceiverNotFound
	}
	tr, ok := receiversFor(o).take(receiverID)
	if !ok {
		return ErrReceiverNotFound
	}
	defer tr.cleanup()

	if commit {
		if err := tr.recv.Commit(ctx); err != nil {
			return &SentinelCauseError{Sentinel: ErrMigrationReceiveFailed, Cause: &WrappedError{Msg: "commit received VM", Err: err}}
		}
		o.logger.Infof("Committed migration receiver %s", receiverID)
		return nil
	}

	if err := tr.recv.Abort(ctx); err != nil {
		return &SentinelCauseError{Sentinel: ErrMigrationReceiveFailed, Cause: &WrappedError{Msg: "abort received VM", Err: err}}
	}
	o.logger.Infof("Aborted migration receiver %s", receiverID)
	return nil
}

// =============================================================================
// Default (production) receiver launcher
// =============================================================================

// qemuIncomingReceiver is the production incomingReceiver backed by a receiving
// QEMU process and its QMP migration manager.
type qemuIncomingReceiver struct {
	vm      *qemu.VM
	monitor *qemu.Monitor
	port    int
}

func (r *qemuIncomingReceiver) Port() int { return r.port }

func (r *qemuIncomingReceiver) Commit(ctx context.Context) error {
	// The transfer has completed on the source; resume the received guest.
	if err := r.monitor.Resume(ctx); err != nil {
		return &WrappedError{Msg: "resume received guest", Err: err}
	}
	return nil
}

func (r *qemuIncomingReceiver) Abort(_ context.Context) error {
	return r.vm.Stop()
}

// defaultNewIncomingReceiver launches a real receiving QEMU: it builds a machine
// model matching the source spec, comes up with "-incoming defer" plus the
// server tls-creds object, then over QMP installs the tls-creds migration
// parameter and issues migrate-incoming on the configured listen address.
func defaultNewIncomingReceiver(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
	o := p.orchestrator

	workDir := filepath.Join(o.config.WorkDir, "incoming-"+generateInstanceID())
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return nil, &WrappedError{Msg: "create receiver work directory", Err: err}
	}

	diskSize := p.spec.Config.DiskSize
	if diskSize == "" {
		diskSize = o.config.DefaultDiskSize
	}
	memory := p.spec.Config.Memory
	if memory <= 0 {
		memory = o.config.DefaultMemory
	}
	cpus := p.spec.Config.CPUs
	if cpus <= 0 {
		cpus = o.config.DefaultCPUs
	}
	networkMode := p.spec.Config.NetworkMode
	if networkMode == "" {
		networkMode = "bridge"
	}

	qcfg := &qemu.Config{
		QEMUBinary:     o.config.QEMUBinary,
		DiskPath:       filepath.Join(workDir, "disk.qcow2"),
		DiskSize:       diskSize,
		Memory:         memory,
		CPUs:           cpus,
		WorkDir:        workDir,
		SecureBoot:     p.spec.Config.SecureBoot,
		Debug:          o.config.Debug,
		OVMFCode:       o.config.OVMFCode,
		OVMFCodeSecure: o.config.OVMFCodeSecure,
		OVMFVars:       o.config.OVMFVars,
		EnableKVM:      p.spec.Config.EnableKVM,
		NoGraphic:      true,
		BootOrder:      "c",
		NetworkMode:    networkMode,
		BridgeName:     o.config.NetworkBridge,
		MACAddress:     p.spec.Config.MACAddress,
	}

	vm, err := qemu.NewVM(qcfg, o.logger)
	if err != nil {
		return nil, &WrappedError{Msg: "create receiver VM", Err: err}
	}

	// A cold migration streams block devices into a fresh image; a live
	// migration reuses the shared backing store. Either way the destination
	// needs the disk file present before QEMU opens it.
	if err := vm.CreateDisk(); err != nil {
		return nil, &WrappedError{Msg: "create receiver disk", Err: err}
	}

	port, err := receiverPort(p.listen)
	if err != nil {
		return nil, &WrappedError{Msg: "allocate receiver port", Err: err}
	}

	credsID, err := vm.StartIncoming(ctx, p.credsDir)
	if err != nil {
		return nil, &WrappedError{Msg: "start receiver QEMU", Err: err}
	}

	if err := vm.ConnectMonitor(ctx); err != nil {
		_ = vm.Stop()
		return nil, &WrappedError{Msg: "connect receiver QMP monitor", Err: err}
	}
	mon := vm.Monitor()
	mgr := qemu.NewMigrationManager(mon, o.logger)

	// Install the migration TLS parameter BEFORE accepting the connection so the
	// incoming stream is authenticated and encrypted.
	if err := mgr.SetParameters(ctx, &qemu.MigrationParams{TLSCreds: credsID}); err != nil {
		_ = vm.Stop()
		return nil, &WrappedError{Msg: "set receiver migration TLS parameter", Err: err}
	}
	if err := mgr.MigrateIncoming(ctx, migrateIncomingURI(p.listen.Addr(), port)); err != nil {
		_ = vm.Stop()
		return nil, &WrappedError{Msg: "arm receiver migrate-incoming", Err: err}
	}

	return &qemuIncomingReceiver{vm: vm, monitor: mon, port: port}, nil
}

// receiverPort is the TCP port the receiver listens on: the configured port,
// or for port 0 a free port reserved by briefly binding the listen address
// and released for QEMU to rebind. The window between the two is small.
func receiverPort(listen netip.AddrPort) (int, error) {
	if listen.Port() != 0 {
		return int(listen.Port()), nil
	}
	l, err := net.Listen("tcp", listen.String())
	if err != nil {
		return 0, err
	}
	defer l.Close()
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		return 0, &MessageError{Msg: "unexpected listener address type"}
	}
	return addr.Port, nil
}

// migrateIncomingURI is the QEMU migrate-incoming URI for host and port;
// an IPv6 host is bracketed.
func migrateIncomingURI(host netip.Addr, port int) string {
	return "tcp:" + net.JoinHostPort(host.String(), strconv.Itoa(port))
}
