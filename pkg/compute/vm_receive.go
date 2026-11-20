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
	"time"

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
// MigrationArchMismatchError refuses a receiver for a guest whose architecture
// differs from the one this host runs: QEMU cannot load an x86_64 guest's state
// into an aarch64 machine or the reverse. Both values are resolved, so an empty
// source arch reads as x86_64.
type MigrationArchMismatchError struct {
	Source      qemu.Arch
	Destination qemu.Arch
}

func (e *MigrationArchMismatchError) Error() string {
	return "compute: migration source guest arch " + strconv.Quote(string(e.Source)) +
		" does not match this host's guest arch " + strconv.Quote(string(e.Destination))
}

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

	// VM returns the receiving QEMU, which a committed receiver hands to the
	// orchestrator as a normal instance.
	VM() *qemu.VM

	// Transferring reports whether a migration stream is in progress (or
	// complete and awaiting finalize), which renews the receiver lifetime.
	Transferring(ctx context.Context) bool
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
	// spec is the migration the receiver was prepared for; a committed
	// receiver is adopted as an instance from it.
	spec MigrationSpec
	// endLifetime stops the receiver's lifetime watch once it is finalized
	// or reaped.
	endLifetime context.CancelFunc
}

// receiverLifetime bounds idle preparation: how long a prepared receiver waits
// with no migration stream in progress. If the prepare reply is lost or the
// caller goes away, the orchestrator reaps the receiver (aborts its QEMU and
// releases its TLS material) at this deadline instead of leaving it running.
// An active transfer renews it at each deadline, so a long migration is not
// stopped mid-stream. Tests shorten it.
var receiverLifetime = 30 * time.Minute

// receiverStatusTimeout bounds the query-migrate a lifetime check makes.
const receiverStatusTimeout = 10 * time.Second

// watchReceiverLifetime reaps receiverID when a lifetime passes with no
// transfer in progress, renewing it while one is. It stops when ended closes
// (FinalizeIncoming or Close took the receiver).
func (o *QEMUOrchestrator) watchReceiverLifetime(ended <-chan struct{}, receiverID string, lifetime time.Duration) {
	for {
		timer := time.NewTimer(lifetime)
		select {
		case <-ended:
			timer.Stop()
			return
		case <-timer.C:
		}
		tr, ok := receiversFor(o).peek(receiverID)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), receiverStatusTimeout)
		transferring := tr.recv.Transferring(ctx)
		cancel()
		if !transferring {
			o.reapReceiver(receiverID, "lifetime expired before finalize")
			return
		}
		o.logger.Infof("Migration receiver %s is transferring; renewing its lifetime by %s", receiverID, lifetime)
	}
}

// adoptReceived hands a committed receiver's QEMU to the orchestrator as a
// running instance, under the source InstanceID when it is free, so the
// migrated guest is listed, stoppable and closed like any other. A running
// QEMU gets the same exit watch Start installs.
func (o *QEMUOrchestrator) adoptReceived(tr *trackedReceiver) (string, error) {
	vm := tr.recv.VM()
	if vm == nil {
		return "", &MessageError{Msg: "received VM has no QEMU process"}
	}

	// A fresh config with the destination's resolved runtime paths: the spec
	// carries the source's settings only, and disk operations, snapshots and
	// Delete need the receiver's work directory and disk.
	config := &InstanceConfig{}
	if tr.spec.Config != nil {
		*config = *tr.spec.Config
	}
	if qcfg := vm.GetConfig(); qcfg != nil {
		config.WorkDir = qcfg.WorkDir
		config.DiskPath = qcfg.DiskPath
		if qcfg.DiskSize != "" {
			config.DiskSize = qcfg.DiskSize
		}
		if qcfg.Memory > 0 {
			config.Memory = qcfg.Memory
		}
		if qcfg.CPUs > 0 {
			config.CPUs = qcfg.CPUs
		}
	}

	o.mu.Lock()
	instanceID := tr.spec.InstanceID
	if _, taken := o.instances[instanceID]; instanceID == "" || taken {
		instanceID = generateInstanceID()
	}
	for _, state := range []InstanceState{StateCreating, StateStopped, StateStarting, StateRunning} {
		if err := o.lifecycle.SetState(instanceID, state); err != nil {
			_ = o.lifecycle.DeleteInstance(instanceID)
			o.mu.Unlock()
			return "", err
		}
	}
	now := time.Now()
	qemuInst := &qemuInstance{
		vm: vm,
		instance: &Instance{
			ID:                 instanceID,
			Name:               tr.spec.VMName,
			Type:               ComputeTypeVM,
			State:              StateRunning,
			Config:             config,
			NetworkAttachments: []NetworkAttachment{},
			CreatedAt:          now,
			UpdatedAt:          now,
			StartedAt:          now,
			Metadata:           map[string]string{"migrated": "true"},
			PID:                vm.GetPID(),
		},
	}
	// The run and its exit watcher are in place before the instance is
	// published, so a stop that lands at once finds the run to wait on and
	// the watcher records the exit and reaps the process.
	// A receiver that already waits on its process hands that waiter over:
	// a second vm.Wait on the same process would fail at once.
	waitExit := vm.Wait
	if w, ok := tr.recv.(interface {
		Done() <-chan struct{}
		ExitErr() error
	}); ok && w.Done() != nil {
		waitExit = func() error {
			<-w.Done()
			return w.ExitErr()
		}
	}
	if vm.IsRunning() {
		run := &qemuRun{cancel: func() {}, done: make(chan struct{})}
		qemuInst.run = run
		go func() {
			defer close(run.done)
			if err := waitExit(); err != nil {
				o.logger.Errorf("VM %s exited with error: %v", instanceID, err)
			}
			o.recordExit(instanceID, qemuInst)
		}()
	}
	o.instances[instanceID] = qemuInst
	o.mu.Unlock()

	if hook := receiverAdoptedHook; hook != nil {
		hook(instanceID)
	}
	return instanceID, nil
}

// receiverAdoptedHook, when set by a test, runs right after a received
// instance is published.
var receiverAdoptedHook func(instanceID string)

// reapReceiver aborts and releases a receiver that was never finalized. It is a
// no-op when the receiver has already been taken.
func (o *QEMUOrchestrator) reapReceiver(receiverID, reason string) {
	tr, ok := receiversFor(o).take(receiverID)
	if !ok {
		return
	}
	o.releaseReceiver(receiverID, tr, reason)
}

func (o *QEMUOrchestrator) releaseReceiver(receiverID string, tr *trackedReceiver, reason string) {
	if tr.endLifetime != nil {
		tr.endLifetime()
	}
	defer tr.cleanup()
	if err := tr.recv.Abort(context.Background()); err != nil {
		o.logger.Errorf("Failed to abort migration receiver %s (%s): %v", receiverID, reason, err)
		return
	}
	o.logger.Infof("Aborted migration receiver %s: %s", receiverID, reason)
}

// closeReceivers reaps every receiver still pending on o; Close calls it so
// orchestrator shutdown does not leak receiving QEMUs.
func (o *QEMUOrchestrator) closeReceivers() {
	for id, tr := range receiversFor(o).takeAll() {
		o.releaseReceiver(id, tr, "orchestrator shutdown")
	}
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

// peek returns the receiver tracked under id without removing it.
func (r *receiverRegistry) peek(id string) (*trackedReceiver, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	tr, ok := r.receivers[id]
	return tr, ok
}

func (r *receiverRegistry) takeAll() map[string]*trackedReceiver {
	r.mu.Lock()
	defer r.mu.Unlock()
	all := r.receivers
	r.receivers = make(map[string]*trackedReceiver)
	return all
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

	// The receiver is built from this host's arch profile; refuse a guest it
	// cannot run before any credential is issued or QEMU started.
	if source, destination := spec.Arch.OrDefault(), o.config.Arch.OrDefault(); source != destination {
		return nil, &MigrationArchMismatchError{Source: source, Destination: destination}
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

	// The receiver lives until FinalizeIncoming commits or aborts it, not until
	// the prepare request ends: the transfer arrives on a later request, so the
	// receiving QEMU must not be killed when this request's context is cancelled.
	recv, err := newIncomingReceiver(context.WithoutCancel(ctx), &incomingReceiverParams{
		orchestrator: o,
		spec:         spec,
		credsDir:     credsDir,
		listen:       listen,
	})
	if err != nil {
		cleanup()
		return nil, &SentinelCauseError{Sentinel: ErrMigrationReceiveFailed, Cause: &WrappedError{Msg: "launch migration receiver", Err: err}}
	}

	// The orchestrator, not the request, owns the receiver's lifetime: it is
	// reaped when receiverLifetime passes with no transfer in progress, unless
	// FinalizeIncoming or Close takes it first.
	receiverID := generateInstanceID()
	ended, endLifetime := context.WithCancel(context.Background())
	receiversFor(o).put(receiverID, &trackedReceiver{recv: recv, cleanup: cleanup, spec: spec, endLifetime: endLifetime})
	go o.watchReceiverLifetime(ended.Done(), receiverID, receiverLifetime)

	// A caller that went away before the reply never gets the receiver token,
	// so nobody could finalize it: reap it now rather than at the deadline.
	if err := ctx.Err(); err != nil {
		o.reapReceiver(receiverID, "prepare request cancelled before the reply")
		return nil, &SentinelCauseError{Sentinel: ErrMigrationReceiveFailed, Cause: &WrappedError{Msg: "prepare request cancelled", Err: err}}
	}

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
	if commit {
		// The receiver stays owned by this call until adoption succeeds: a
		// failed or expired Commit, or a failed adoption, aborts it so its
		// QEMU process (started without the request context) is killed and
		// reaped rather than left running with no owner.
		if err := tr.recv.Commit(ctx); err != nil {
			o.releaseReceiver(receiverID, tr, "commit failed")
			return &SentinelCauseError{Sentinel: ErrMigrationReceiveFailed, Cause: &WrappedError{Msg: "commit received VM", Err: err}}
		}
		// The resumed guest becomes a normal instance before success is
		// acknowledged, so it can be listed, stopped and closed.
		instanceID, err := o.adoptReceived(tr)
		if err != nil {
			o.logger.Errorf("Committed migration receiver %s but could not adopt its VM: %v", receiverID, err)
			o.releaseReceiver(receiverID, tr, "adoption failed")
			return &SentinelCauseError{Sentinel: ErrMigrationReceiveFailed, Cause: &WrappedError{Msg: "adopt received VM", Err: err}}
		}
		if tr.endLifetime != nil {
			tr.endLifetime()
		}
		tr.cleanup()
		o.logger.Infof("Committed migration receiver %s as instance %s", receiverID, instanceID)
		return nil
	}

	if tr.endLifetime != nil {
		tr.endLifetime()
	}
	defer tr.cleanup()
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
	mgr     *qemu.MigrationManager
	port    int
	// proc waits on the receiving QEMU from its launch, so an aborted
	// receiver is reaped and an adopted one keeps the same waiter.
	proc *receiverProcess
}

// receiverStopGrace bounds each wait for the receiver process to exit:
// after the stop, and again after the kill that follows a stop it ignored.
var receiverStopGrace = 10 * time.Second

// receiverProcess is the waiter of one launched receiver process. done
// closes once wait has returned, that is once the process has been reaped;
// err is wait's result, readable after done.
type receiverProcess struct {
	stop func() error
	kill func() error
	done chan struct{}
	err  error
}

// startReceiverProcess starts the waiter of a launched process: wait reaps
// it, stop asks it to exit, kill forces it.
func startReceiverProcess(wait, stop, kill func() error) *receiverProcess {
	p := &receiverProcess{stop: stop, kill: kill, done: make(chan struct{})}
	go func() {
		p.err = wait()
		close(p.done)
	}()
	return p
}

// terminate stops the process and returns once it has been reaped: it
// waits receiverStopGrace after the stop, then kills the process and waits
// as long again.
func (p *receiverProcess) terminate() error {
	select {
	case <-p.done:
		return nil
	default:
	}
	stopErr := p.stop()
	select {
	case <-p.done:
		return nil
	case <-time.After(receiverStopGrace):
	}
	killErr := p.kill()
	select {
	case <-p.done:
		return nil
	case <-time.After(receiverStopGrace):
	}
	return &WrappedError{Msg: "receiver process did not exit after stop and kill", Err: errors.Join(stopErr, killErr)}
}

// VM returns the receiving QEMU.
func (r *qemuIncomingReceiver) VM() *qemu.VM { return r.vm }

// Transferring reports whether query-migrate shows a stream in progress or
// complete and awaiting finalize. An unanswered query counts as idle.
func (r *qemuIncomingReceiver) Transferring(ctx context.Context) bool {
	if r.mgr == nil {
		return false
	}
	st, err := r.mgr.Status(ctx)
	if err != nil || st == nil {
		return false
	}
	switch st.Status {
	case qemu.MigrationStatusSetup,
		qemu.MigrationStatusActive,
		qemu.MigrationStatusPostcopyActive,
		qemu.MigrationStatusPostcopyPaused,
		qemu.MigrationStatusPostcopyRecover,
		qemu.MigrationStatusPreSwitchover,
		qemu.MigrationStatusDevice,
		qemu.MigrationStatusCompleted:
		return true
	}
	return false
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
	if r.proc != nil {
		return r.proc.terminate()
	}
	return r.vm.Stop()
}

// Done is closed once the receiver's process has been reaped.
func (r *qemuIncomingReceiver) Done() <-chan struct{} {
	if r.proc == nil {
		return nil
	}
	return r.proc.done
}

// ExitErr is the receiver process's exit result, valid once Done is closed.
func (r *qemuIncomingReceiver) ExitErr() error {
	if r.proc == nil {
		return nil
	}
	return r.proc.err
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

	qcfg := o.config.qemuBase()
	qcfg.DiskPath = filepath.Join(workDir, "disk.qcow2")
	qcfg.DiskSize = diskSize
	qcfg.Memory = memory
	qcfg.CPUs = cpus
	qcfg.WorkDir = workDir
	qcfg.SecureBoot = p.spec.Config.SecureBoot
	qcfg.EnableKVM = p.spec.Config.EnableKVM
	qcfg.NetworkMode = networkMode
	qcfg.MACAddress = p.spec.Config.MACAddress

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
	// The waiter runs from launch, so every exit of the receiver, aborted,
	// failed or adopted, is reaped.
	proc := startReceiverProcess(vm.Wait, vm.Stop, vm.ForceStop)

	if err := vm.ConnectMonitor(ctx); err != nil {
		_ = proc.terminate()
		return nil, &WrappedError{Msg: "connect receiver QMP monitor", Err: err}
	}
	mon := vm.Monitor()
	mgr := qemu.NewMigrationManager(mon, o.logger)

	// Install the migration TLS parameter BEFORE accepting the connection so the
	// incoming stream is authenticated and encrypted.
	if err := mgr.SetParameters(ctx, &qemu.MigrationParams{TLSCreds: credsID}); err != nil {
		_ = proc.terminate()
		return nil, &WrappedError{Msg: "set receiver migration TLS parameter", Err: err}
	}
	if err := mgr.MigrateIncoming(ctx, migrateIncomingURI(p.listen.Addr(), port)); err != nil {
		_ = proc.terminate()
		return nil, &WrappedError{Msg: "arm receiver migrate-incoming", Err: err}
	}

	return &qemuIncomingReceiver{vm: vm, monitor: mon, mgr: mgr, port: port, proc: proc}, nil
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
