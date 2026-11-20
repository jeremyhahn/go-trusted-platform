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

package process

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc"
	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"golang.org/x/sys/unix"
)

// Defaults for the supervisor's timings. They are fields on Config so a test
// drives them with an injected clock and a production deployment can widen
// them from configuration.
const (
	// DefaultReadyTimeout bounds how long a freshly launched child has to
	// answer on its control socket.
	DefaultReadyTimeout = 10 * time.Second
	// DefaultStopTimeout bounds a graceful stop before SIGKILL.
	DefaultStopTimeout = 10 * time.Second
	// DefaultRestartBackoff is the first delay after a crash; it doubles up
	// to DefaultRestartBackoffMax.
	DefaultRestartBackoff = 500 * time.Millisecond
	// DefaultRestartBackoffMax caps the doubling.
	DefaultRestartBackoffMax = 30 * time.Second
	// DefaultRestartBudget is how many crashes a process may have inside
	// DefaultRestartWindow before the supervisor stops restarting it.
	DefaultRestartBudget = 5
	// DefaultRestartWindow is that window.
	DefaultRestartWindow = 5 * time.Minute
)

// Clock is the supervisor's view of time. Tests inject one so backoff and
// the restart window are exercised without sleeping.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

// systemClock is the production Clock.
type systemClock struct{}

func (systemClock) Now() time.Time                         { return time.Now() }
func (systemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Config configures a Supervisor.
type Config struct {
	// Launcher starts children; nil means ExecLauncher.
	Launcher Launcher
	// Cgroups places children in cgroup v2 leaves; nil or a manager with no
	// Parent disables placement.
	Cgroups *CgroupManager
	// RuntimeDir holds the per-process control sockets, e.g. /run/gatewayd.
	RuntimeDir string
	// Inherited is the part of the supervisor's command line every child is
	// started with: the configuration file, the state directory and the
	// log settings.
	Inherited Inherited
	// UID and GID are the credentials the unprivileged classes drop to.
	UID, GID uint32
	// SocketGID, when non-negative, owns the control sockets so an
	// unprivileged child can reach the datapath process's socket.
	SocketGID int
	// ReadyTimeout, StopTimeout, RestartBackoff, RestartBackoffMax,
	// RestartBudget and RestartWindow default to the Default* constants.
	ReadyTimeout      time.Duration
	StopTimeout       time.Duration
	RestartBackoff    time.Duration
	RestartBackoffMax time.Duration
	RestartBudget     int
	RestartWindow     time.Duration
	// WatchdogInterval is the watchdog interval given to every process
	// whose definition sets none: the child must send WATCHDOG=1 at least
	// once per interval once it is ready. Zero leaves the watchdog off.
	WatchdogInterval time.Duration
	// OnChildExit, when set, runs after every exit of a child the
	// supervisor did not ask for (a crash, a SIGKILL, a missed watchdog)
	// and before its restart backoff. An error is logged at Error, recorded
	// in the process's health, and the hook is called again on each
	// backoff tick until it succeeds or a relaunched child is up. It is
	// not called on an operator stop.
	OnChildExit func(ctx context.Context, def Definition) error
	// Clock is the time source; nil means the system clock.
	Clock Clock
	// Logger receives supervision events; nil means slog.Default().
	Logger *slog.Logger
}

// withDefaults fills the zero values.
func (c Config) withDefaults() Config {
	if c.Launcher == nil {
		c.Launcher = &ExecLauncher{}
	}
	if c.ReadyTimeout == 0 {
		c.ReadyTimeout = DefaultReadyTimeout
	}
	if c.StopTimeout == 0 {
		c.StopTimeout = DefaultStopTimeout
	}
	if c.RestartBackoff == 0 {
		c.RestartBackoff = DefaultRestartBackoff
	}
	if c.RestartBackoffMax == 0 {
		c.RestartBackoffMax = DefaultRestartBackoffMax
	}
	if c.RestartBudget == 0 {
		c.RestartBudget = DefaultRestartBudget
	}
	if c.RestartWindow == 0 {
		c.RestartWindow = DefaultRestartWindow
	}
	if c.Clock == nil {
		c.Clock = systemClock{}
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return c
}

// Supervisor runs each gateway service in the child process its class table
// entry names, restarts a child that dies, and answers the parent gateway's
// questions about its services. It implements gateway.ServiceSupervisor.
type Supervisor struct {
	cfg Config

	mu        sync.Mutex
	processes map[string]*supervised
	stopped   bool

	// applying is held, as a one-slot semaphore, across every send of a
	// desired document to a child: Apply's and the relaunch's re-send
	// (#557). Serialising the two sends, and reading the document only once
	// the slot is held, is what keeps a re-send from overwriting a newer
	// document with an older one. It is a channel rather than a mutex so a
	// caller waiting for it still honours its context.
	applying chan struct{}

	// fchown changes the owner of a state file handed to a child
	// (handOverStateFiles); unix.Fchown, replaced in tests so none changes
	// a file's owner on the host.
	fchown func(fd, uid, gid int) error

	// desired is the last document Apply was given. A process that
	// reconciles a section of it and is started after that apply is given
	// it at launch.
	desired *gwstate.DesiredConfig
}

// supervised is one child process the supervisor owns.
type supervised struct {
	def Definition
	// wanted is the set of services the parent has asked this process for.
	// The process runs while it is non-empty.
	wanted map[string]bool
	// socket is its control socket path.
	socket string

	child  Child
	client *ipc.Client
	// notify is the current child's sd_notify socket, bound under the
	// runtime directory and passed to it as NOTIFY_SOCKET.
	notify *NotifySocket
	// ready is the current child's readiness signal: its notify reader
	// closes it on the child's first READY=1. Each launch makes a new one.
	ready chan struct{}
	// cancel stops the watch goroutine and the launch context.
	cancel context.CancelFunc
	// done closes when the watch goroutine has exited.
	done chan struct{}
	// failure is the reason the process is not running, nil while it is.
	failure error
	// startedAt is when the current child was launched.
	startedAt time.Time
	// restarts are the crash times inside the current window.
	restarts []time.Time
	// backoff is the current restart delay.
	backoff time.Duration
	// stopping is set while stopProcess is tearing the process down. The
	// watch goroutine reads it before relaunching, so a crash that lands
	// during a stop is not restarted into an orphan the stop has already
	// stopped waiting for.
	stopping bool
	// launching is the claim on a launch that has not assigned child yet.
	// Deciding to launch and assigning proc.child are separate critical
	// sections — the launch itself must not hold s.mu, because it execs —
	// so without the claim two callers starting two services of the same
	// process both see no child and both launch. The second launch would
	// overwrite child, client, cancel and done, leaving the first child
	// running with nothing watching it and nothing able to stop it: an
	// orphan holding CAP_NET_ADMIN, which is the failure this package
	// exists to prevent.
	launching bool
	// followPending records a datapath relaunch that landed while this
	// Follows process was launching: that launch may already have
	// restored its state into the datapath child that is gone, so the
	// process is relaunched once more when the launch completes.
	followPending bool
	// withdrawal fences a given-up follower's peer withdrawal against its
	// replacement launch. noteRestart registers it in the critical section
	// that decides the give-up, and only when no launch is claimed; a
	// launch claimant reads it in its own claim section, cancels it and
	// waits on its done before it execs the replacement, so no withdrawal
	// request outlives the claim.
	withdrawal *withdrawal
	// desired is the last desired document Apply sent to this process. A
	// child that crashed took what it had applied with it, and the new one
	// sweeps its predecessor's flows on Start, so a relaunched child is
	// given this document again before the restart counts (#557). It is
	// kept across a stop: it is still the parent's last desired document.
	desired *gwstate.DesiredConfig
	// restoring is set from the claim of a relaunch until the relaunched
	// child has been given desired. While it is set the process's services
	// are reported down, never up with their configuration missing.
	restoring bool
	// missed is the watchdog failure of missedChild: the watchdog records
	// it before stopping that child, and watch reports it, rather than the
	// signal's exit, when that child is reaped.
	missed      error
	missedChild Child
	// exitHookErr is the last failure of Config.OnChildExit for this
	// process's last unrequested exit; nil once the hook has succeeded.
	// restartLoop retries the hook on each backoff tick while it is set.
	exitHookErr error
	// launchGen counts launch claims: it is bumped under s.mu at every
	// place that sets launching. An exit hook records it when it is
	// decided and runs only while it is unchanged, so a hook is fenced to
	// the child that exited and never runs over a replacement.
	launchGen uint64
	// claimGen is the generation of the launch claim launching holds: it
	// is set with launching at every claim. A child of that same
	// generation that exits before the claim is released (a crash during
	// readiness) still gets its exit hook; only a claim for a newer
	// generation is a replacement the hook must not run over.
	claimGen uint64
	// cleaning is set while Config.OnChildExit runs for this process. A
	// launch claim that finds it set waits on cleanDone before it claims.
	cleaning bool
	// cleanDone is closed when the exit-hook call that set cleaning
	// returns.
	cleanDone chan struct{}
}

// withdrawal is a given-up follower's in-flight peer withdrawal: ctx is
// cancelled by a replacement claimant, and done closes when the
// withdrawal has returned.
type withdrawal struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	// stop is closed by a launch claimant (awaitWithdrawal): the withdrawal
	// starts no further round and stops waiting out its backoff, but a
	// ReconcileVPNPeers call in flight runs to its own deadline.
	stop     chan struct{}
	stopOnce sync.Once
	// err is the failure of the last round's calls, nil when every call
	// it made was answered. Written before done closes, read after.
	err error
}

// New builds a supervisor. Nothing is launched until StartService.
func New(cfg Config) *Supervisor {
	return &Supervisor{
		cfg:       cfg.withDefaults(),
		processes: make(map[string]*supervised),
		applying:  make(chan struct{}, 1),
		fchown:    unix.Fchown,
	}
}

// socketPath is where a process's control socket lives.
func (s *Supervisor) socketPath(process string) string {
	return filepath.Join(s.cfg.RuntimeDir, process+".sock")
}

// StartService implements gateway.ServiceSupervisor: it makes sure the
// process hosting the service is running and the service is active in it.
func (s *Supervisor) StartService(ctx context.Context, service string) error {
	def, err := DefinitionForService(service)
	if err != nil {
		return err
	}
	// def is a copy: the package's definitions are left as they are.
	if def.WatchdogInterval == 0 {
		def.WatchdogInterval = s.cfg.WatchdogInterval
	}
	// A definition's own interval, or a Config built without Settings, has
	// not been checked yet: refuse one the child would get as WATCHDOG_USEC=0.
	if err := checkWatchdogInterval(def.WatchdogInterval); err != nil {
		return err
	}

	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return &ErrSupervisorStopped{}
	}
	proc, ok := s.processes[def.Name]
	if !ok {
		proc = &supervised{def: def, wanted: map[string]bool{}, socket: s.socketPath(def.Name)}
		s.processes[def.Name] = proc
	}
	// An exit hook in flight is cleaning up after the last child: the
	// claim below waits for it, so the cleanup never runs over this launch.
	if err := s.awaitCleaningLocked(ctx, proc); err != nil {
		s.mu.Unlock()
		return err
	}
	if s.stopped {
		s.mu.Unlock()
		return &ErrSupervisorStopped{}
	}
	proc.wanted[service] = true
	proc.stopping = false
	if proc.desired == nil && def.ReconcilesDesired {
		// Started after an apply: its launch is given that document.
		proc.desired = s.desired
	}
	// Claim the launch, or leave it to whoever holds the claim. A caller
	// that does not launch still waits for the service below: the readiness
	// poll already tolerates a process mid-launch, so it is the natural
	// second caller.
	claimed := proc.child == nil && !proc.launching
	var pending *withdrawal
	// replacing records a claim over a child that went down unrequested
	// (a crash backing off, a given-up budget, a failed start): its
	// followers' state went with that child, and the restart loop that
	// would have replayed them finds this replacement live and returns.
	replacing := false
	if claimed {
		replacing = proc.failure != nil
		// Read with the claim: a give-up either registered its withdrawal
		// before this point, or sees the claim and registers none.
		pending = proc.withdrawal
		proc.launchGen++
		proc.launching = true
		proc.claimGen = proc.launchGen
		proc.followPending = false
		// A process started again after a stop, or while its restart is
		// backing off, still has its predecessor's desired document; the
		// parent's version check will not send it again (#557).
		proc.restoring = proc.desired != nil
	}
	s.mu.Unlock()

	if claimed {
		launched := false
		err := awaitWithdrawal(ctx, pending)
		if err == nil {
			err = s.launch(ctx, proc)
			launched = err == nil
		}
		if launched {
			err = s.serveLaunched(ctx, proc)
		}
		s.mu.Lock()
		proc.launching = false
		proc.restoring = false
		if launched && err != nil {
			// serveLaunched stopped the child; its services are down for
			// that reason, for every caller still waiting on them.
			proc.failure = err
		}
		if err == nil {
			// The replacement is up: the last exit's cleanup is moot, and
			// a restart loop must not retry it over this child.
			proc.exitHookErr = nil
		}
		s.mu.Unlock()
		if err != nil {
			s.releaseFailedStart(ctx, proc, service)
			return err
		}
		if replacing {
			s.relaunchFollowers(ctx, proc)
		}
		s.relaunchPendingFollower(ctx, proc)
	}
	if err := s.awaitService(ctx, proc, service); err != nil {
		s.releaseFailedStart(ctx, proc, service)
		return err
	}
	return nil
}

// releaseFailedStart undoes a StartService that could not bring its service
// up. Without it the service stays in wanted and, when the failure was the
// child answering that the service is inactive, the child it just launched
// stays running: the gateway's own start rollback (node.go) unwinds only the
// handlers it already started, and the one that failed is not among them. For
// the kernel class that is a live CAP_NET_ADMIN child for a startup that
// failed — the orphan this package exists to prevent, reached through the
// start path instead of the stop path.
//
// The process itself only stops when the failed service was its last: another
// caller's service in the same process keeps it running.
func (s *Supervisor) releaseFailedStart(ctx context.Context, proc *supervised, service string) {
	s.mu.Lock()
	delete(proc.wanted, service)
	remaining := len(proc.wanted)
	failure := proc.failure
	s.mu.Unlock()
	if remaining > 0 {
		return
	}
	// The teardown does not inherit the caller's cancellation: a start that
	// failed because its context was cancelled still has a child to stop,
	// and StopTimeout already bounds the wait.
	if err := s.stopProcess(context.WithoutCancel(ctx), proc); err != nil {
		s.cfg.Logger.Error("gatewayd supervisor: stopping a process whose start failed",
			slog.String("process", proc.def.Name),
			slog.String("service", service),
			slog.Any("error", err))
	}
	// The teardown clears the failure, as it must for a stop someone asked
	// for. This one nobody asked for: the process is down for the reason the
	// start recorded (a re-send of the desired document that failed, #557),
	// and health has to say so rather than that it was never started. A
	// start that claimed the process meanwhile owns its state.
	s.mu.Lock()
	if proc.child == nil && !proc.launching && proc.failure == nil {
		proc.failure = failure
	}
	s.mu.Unlock()
}

// abandonLaunch stops a child that was started for a process no longer
// wanted, and releases everything the launch acquired for it. Nothing is
// published, so no watch goroutine exists to reap the child — this does it.
func (s *Supervisor) abandonLaunch(ctx context.Context, proc *supervised, child Child, client *ipc.Client, cancel context.CancelFunc) {
	s.cfg.Logger.Warn("gatewayd supervisor: stopping a child whose process was released while it started",
		slog.String("process", proc.def.Name), slog.Int("pid", child.PID()))
	if err := client.Close(); err != nil {
		s.cfg.Logger.Warn("gatewayd supervisor: closing an abandoned launch's client",
			slog.String("process", proc.def.Name), slog.Any("error", err))
	}
	// Nothing published this child, so it has no watch goroutine and nothing
	// else will ever reap it. The reap happens here, and it goes through the
	// same bounded graceful-then-kill sequence as a normal stop: a plain Wait
	// on a child that ignores SIGTERM would block this call — and with it the
	// StartService that is still inside launch — forever.
	reaped := make(chan struct{})
	go func() {
		defer close(reaped)
		if err := child.Wait(); err != nil {
			s.cfg.Logger.Debug("gatewayd supervisor: abandoned child exited",
				slog.String("process", proc.def.Name), slog.Any("error", err))
		}
	}()
	if err := s.terminate(context.WithoutCancel(ctx), proc.def.Name, child, reaped); err != nil {
		s.cfg.Logger.Error("gatewayd supervisor: stopping an abandoned child",
			slog.String("process", proc.def.Name), slog.Any("error", err))
	}
	cancel()
	s.removeCgroup(context.WithoutCancel(ctx), proc)
}

// runtimeDirMode is the control-socket directory's mode: the service
// account's group may create, reach and remove its own entries, and nothing
// else on the host may do anything at all.
//
// Group WRITE is the part that is easy to get wrong and fatal when it is:
// every unprivileged child binds its own control socket AFTER dropping to the
// service uid, and creating an entry in a directory needs write on the
// directory. At mode 0750 — the directory still owned by the root supervisor,
// with only the group changed — routing, proxy, provisioning and vpn all get
// EACCES from bind and time out in readiness, which reads as a broken child
// rather than as a directory permission.
//
// The sticky bit is what makes group write safe: parsers share one account, so
// without it any one of them could unlink another's control socket and take
// over the name.
//
// The setgid bit is what gives every control socket the service group without
// a chown. A socket bound in a setgid directory takes the directory's group
// from the kernel, so the datapath child — uid 0, but holding only
// CAP_NET_ADMIN and CAP_NET_RAW, and not a member of the service group — gets
// a socket the parsers can reach without needing CAP_CHOWN in its steady state.
const runtimeDirMode = os.ModeSticky | os.ModeSetgid | 0o770

// ensureRuntimeDir makes the control-socket directory exist, owned by the
// service account's group, writable by it and setgid so every socket bound in
// it gets that group. The packaged init script creates
// it too; doing it here keeps a hand-started supervisor working and is
// idempotent.
func (s *Supervisor) ensureRuntimeDir() error {
	dir := s.cfg.RuntimeDir
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, runtimeDirMode); err != nil {
		return &ErrSocketDir{Path: dir, Op: "create", Cause: err}
	}
	if s.cfg.SocketGID >= 0 {
		if err := os.Chown(dir, -1, s.cfg.SocketGID); err != nil {
			// A supervisor without the privilege to chown is a developer
			// run, not a fleet one; the sockets it creates are its own.
			s.cfg.Logger.Warn("gatewayd supervisor: setting the control-socket directory group",
				slog.String("path", dir), slog.Any("error", err))
		}
	}
	// MkdirAll leaves an existing directory's mode alone, and the packaged
	// init script may have created it, so the mode is set rather than
	// assumed. It follows the chown: the kernel keeps a setgid bit only for
	// a caller in the directory's group or holding CAP_FSETID.
	if err := os.Chmod(dir, runtimeDirMode); err != nil {
		s.cfg.Logger.Warn("gatewayd supervisor: setting the control-socket directory mode",
			slog.String("path", dir), slog.Any("error", err))
	}
	// Verify rather than hope. A directory the children cannot write is a
	// refusal now, naming the directory, instead of four readiness timeouts
	// that name the children.
	info, err := os.Stat(dir)
	if err != nil {
		return &ErrSocketDir{Path: dir, Op: "stat", Cause: err}
	}
	if fault := socketDirFault(dir, info.Mode(), s.cfg.SocketGID >= 0); fault != nil {
		return &ErrSocketDir{Path: dir, Op: "secure", Cause: fault}
	}
	return nil
}

// socketDirFault reports what keeps the children from using a control-socket
// directory of the given mode, or nil. A directory that hands out a socket
// group must also be setgid: otherwise the datapath child binds its socket in
// its own group and has no privilege to change it.
func socketDirFault(path string, mode os.FileMode, socketGroup bool) error {
	if !bindableByServiceGroup(mode) {
		return &ErrSocketDirNotGroupWritable{Path: path, Mode: mode.Perm()}
	}
	if socketGroup && mode&os.ModeSetgid == 0 {
		return &ErrSocketDirNotSetgid{Path: path, Mode: mode.Perm()}
	}
	return nil
}

// bindableByServiceGroup reports whether a control-socket directory's mode
// lets an unprivileged child create its own socket in it. Read, write and
// execute for the group are all required: write to create the entry, execute
// to traverse, read for the child to find what it left there across a restart.
func bindableByServiceGroup(mode os.FileMode) bool {
	return mode.Perm()&0o070 == 0o070
}

// stateDirMode keeps a process's state to the process: the vpn child's
// revocation journal decides which leases a restart may reinstate.
const stateDirMode = 0o700

// ensureStateDir makes the process's state directory under the data directory
// exist and belong to the credentials the process runs with. The data
// directory belongs to root, so an unprivileged child could not create it
// itself. With no data directory the child resolves its own default, and
// there is nothing to lay out.
func (s *Supervisor) ensureStateDir(def Definition) error {
	if def.StateDir == "" || s.cfg.Inherited.DataDir == "" {
		return nil
	}
	dir := filepath.Join(s.cfg.Inherited.DataDir, def.StateDir)
	if err := os.MkdirAll(dir, stateDirMode); err != nil {
		return &ErrStateDir{Process: def.Name, Path: dir, Op: "create", Cause: err}
	}
	if def.Unprivileged {
		if err := os.Chown(dir, int(s.cfg.UID), int(s.cfg.GID)); err != nil {
			return &ErrStateDir{Process: def.Name, Path: dir, Op: "chown", Cause: err}
		}
		if err := grantTraverse(s.cfg.Inherited.DataDir, s.cfg.UID, s.cfg.GID); err != nil {
			return &ErrStateDir{Process: def.Name, Path: s.cfg.Inherited.DataDir, Op: "traverse", Cause: err}
		}
		if err := s.handOverStateFiles(def, dir); err != nil {
			return err
		}
	}
	// MkdirAll leaves an existing directory's mode alone.
	if err := os.Chmod(dir, stateDirMode); err != nil {
		return &ErrStateDir{Process: def.Name, Path: dir, Op: "chmod", Cause: err}
	}
	return nil
}

// grantTraverse adds search permission to a directory for a child running as
// uid and gid, so an unprivileged child can reach its own state directory
// beneath it. The bit goes into the one class the kernel checks for that child
// (traverseBit): a root:<group> directory at 0700 gains g+x, not o+x, which
// the child's group match would never consult. Nothing else changes: no class
// gains read, no other class gains anything, and a directory the child can
// already traverse is left alone. The data directory may already exist at
// 0700 — gatewayd's tunnels record and the ESP inventory both create it that
// way — so the bit is added to whatever mode it has.
func grantTraverse(path string, uid, gid uint32) error {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return err
	}
	mode := st.Mode & 0o7777
	search := traverseBit(st.Uid, st.Gid, uid, gid)
	if mode&search != 0 {
		return nil
	}
	return syscall.Chmod(path, mode|search)
}

// traverseBit is the one execute bit the kernel checks for a process with uid
// and gid on a directory owned by ownerUID:ownerGID. Exactly one permission
// class applies: owner if the uid matches, else group if the gid matches, else
// other; a class that does not apply is never consulted. The child holds no
// supplementary group but its own (dropCredentials), so gid is its only group.
func traverseBit(ownerUID, ownerGID, uid, gid uint32) uint32 {
	switch {
	case ownerUID == uid:
		return 0o100
	case ownerGID == gid:
		return 0o010
	default:
		return 0o001
	}
}

// launch starts the child and its watch goroutine.
func (s *Supervisor) launch(ctx context.Context, proc *supervised) error {
	if err := s.ensureRuntimeDir(); err != nil {
		return err
	}
	// The previous child's socket, after a crash, still holds the path:
	// close it before binding the new one there.
	s.mu.Lock()
	s.closeNotifyLocked(proc)
	s.mu.Unlock()
	notifyPath := filepath.Join(s.cfg.RuntimeDir, proc.def.Name+".notify")
	if err := os.Remove(notifyPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	notify, err := ListenNotify(notifyPath, 0, s.cfg.SocketGID)
	if err != nil {
		return err
	}
	published := false
	defer func() {
		if published {
			return
		}
		if cerr := notify.Close(); cerr != nil {
			s.cfg.Logger.Warn("gatewayd supervisor: closing an unpublished notify socket",
				slog.String("process", proc.def.Name), slog.Any("error", cerr))
		}
	}()
	if err := s.ensureStateDir(proc.def); err != nil {
		return err
	}
	// Cgroups may be nil: CgroupManager's methods take a nil receiver and
	// report placement disabled (Enabled is m != nil && m.Parent != ""),
	// so a nil manager yields no leaf rather than a dereference.
	// TestCgroupManager_DisabledDoesNothing pins that.
	leaf, err := s.cfg.Cgroups.Prepare(proc.def)
	if err != nil {
		return err
	}
	spec := Spec{
		Definition: proc.def,
		Socket:     proc.socket,
		Inherited:  s.cfg.Inherited,
		UID:        s.cfg.UID,
		GID:        s.cfg.GID,
		SocketGID:  s.cfg.SocketGID,
		// The supervisor is this process; the child admits its uid on the
		// control service.
		SupervisorUID: uint32(os.Getuid()),
		CgroupFD:      -1,
		NotifySocket:  notifyPath,
	}
	if leaf != nil {
		spec.CgroupFD = int(leaf.Fd())
	}

	// The launch context outlives this call: it is the child's lifetime,
	// cancelled by Stop or by the watch goroutine giving up.
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	child, err := s.cfg.Launcher.Launch(runCtx, spec)
	if leaf != nil {
		if cerr := leaf.Close(); cerr != nil {
			s.cfg.Logger.Warn("gatewayd supervisor: closing cgroup leaf",
				slog.String("process", proc.def.Name), slog.Any("error", cerr))
		}
	}
	if err != nil {
		cancel()
		return err
	}
	notify.SetPid(child.PID())

	client, err := ipc.Dial(proc.socket)
	if err != nil {
		// The child is already running and nothing watches it yet: no watch
		// goroutine has been started, so nobody would Wait for it and it
		// would sit unreaped until the supervisor exits. Stop it here, and
		// reap it, before reporting the dial failure.
		if serr := child.Signal(syscall.SIGTERM); serr != nil && !errors.Is(serr, os.ErrProcessDone) {
			s.cfg.Logger.Warn("gatewayd supervisor: signalling a child whose socket could not be dialled",
				slog.String("process", proc.def.Name), slog.Any("error", serr))
		}
		if werr := child.Wait(); werr != nil {
			s.cfg.Logger.Debug("gatewayd supervisor: child exited after a failed dial",
				slog.String("process", proc.def.Name), slog.Any("error", werr))
		}
		cancel()
		return err
	}

	// Publishing is the last thing, and it is conditional. The launch ran
	// unlocked — it execs — so a stop can have released the process's last
	// service while this child was starting. That stop found no child to
	// signal (this one is not published yet), tore the process down and
	// returned success; publishing now would leave a live child, with a
	// watch goroutine, for a service nobody wants — and for the kernel
	// class that child holds CAP_NET_ADMIN.
	s.mu.Lock()
	if abandoned := s.stopped || proc.stopping || len(proc.wanted) == 0; abandoned {
		s.mu.Unlock()
		s.abandonLaunch(ctx, proc, child, client, cancel)
		return &ErrLaunchAbandoned{Process: proc.def.Name}
	}
	proc.child = child
	proc.client = client
	proc.notify = notify
	published = true
	ready := make(chan struct{})
	proc.ready = ready
	proc.cancel = cancel
	proc.startedAt = s.cfg.Clock.Now()
	proc.failure = nil
	proc.done = make(chan struct{})
	done := proc.done
	s.mu.Unlock()

	// wd is the child's watchdog deadline, kept by its notify reader (nil
	// without a watchdog); gone closes when the child's notify reader ends,
	// with its socket.
	wd := newWatchdogState(proc.def.WatchdogInterval, s.cfg.Clock)
	gone := make(chan struct{})
	go s.readNotify(proc.def.Name, notify, ready, wd, gone)
	go s.watch(runCtx, proc, child, notify, done)
	if wd != nil {
		go s.watchdog(runCtx, proc, child, wd, ready, gone)
	}

	s.cfg.Logger.Info("gatewayd supervisor: process started",
		slog.String("process", proc.def.Name),
		slog.String("class", string(proc.def.Class)),
		slog.Int("pid", child.PID()))
	return nil
}

// childStarting holds the gateway states a child reports before its
// Gateway.Start has finished: STOPPED until Start begins, INITIALIZING while
// it runs. A service health read in these states describes a start still in
// flight, not its outcome.
var childStarting = map[ipcv1.ProcessState]bool{
	ipcv1.ProcessState_PROCESS_STATE_UNSPECIFIED:  true,
	ipcv1.ProcessState_PROCESS_STATE_STOPPED:      true,
	ipcv1.ProcessState_PROCESS_STATE_INITIALIZING: true,
}

// awaitService polls the child's control socket until the service reports
// active, the readiness deadline passes, or the child dies.
func (s *Supervisor) awaitService(ctx context.Context, proc *supervised, service string) error {
	deadline := s.cfg.Clock.Now().Add(s.cfg.ReadyTimeout)
	var lastErr error
	var detail string
	var seen chan struct{}
	for {
		s.mu.Lock()
		client, failure, restoring, ready := proc.client, proc.failure, proc.restoring, proc.ready
		s.mu.Unlock()
		if ready == seen {
			// Already woken by this child's READY=1: a closed channel in
			// the select would spin the loop.
			ready = nil
		}
		if failure != nil {
			return &ErrProcessDown{Process: proc.def.Name, Service: service, Cause: failure}
		}
		// A child still being given its predecessor's document is not up
		// yet, whatever its services say.
		if client != nil && !restoring {
			status, err := client.Status(ctx)
			if err != nil {
				lastErr = err
			} else {
				lastErr = nil
				detail = status.GetStartError()
				// A child answers before its Gateway.Start has run, and
				// until Start returns every hosted service reports
				// "not active" as its health. That is not a verdict:
				// stopping the child here cancels the start in flight
				// (the OVS pipeline install among it). Only a start error
				// or the deadline below ends the wait early.
				if detail == "" && childStarting[status.GetState()] {
					status = nil
				}
				for _, svc := range status.GetServices() {
					if svc.GetName() != service {
						continue
					}
					if svc.GetActive() {
						return nil
					}
					if svc.GetHealthError() != "" {
						detail = svc.GetHealthError()
					}
				}
				if detail != "" {
					return &ErrServiceNotActiveInProcess{Service: service, Process: proc.def.Name, Detail: detail}
				}
			}
		}
		if !s.cfg.Clock.Now().Before(deadline) {
			if lastErr != nil {
				return &ErrProcessUnreachable{
					Process: proc.def.Name, Socket: proc.socket,
					Waited: s.cfg.ReadyTimeout, Cause: lastErr,
				}
			}
			return &ErrServiceNotActiveInProcess{Service: service, Process: proc.def.Name, Detail: detail}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ready:
			seen = ready
		case <-s.cfg.Clock.After(readyPollInterval):
		}
	}
}

// readyPollInterval is how often a starting child is asked whether its
// services are up.
const readyPollInterval = 25 * time.Millisecond

// watchdogState is one child's watchdog deadline, kept by its notify reader
// and read by its watchdog. Each WATCHDOG=1 updates it on receipt, so no
// keep-alive is ever dropped or judged by when the watchdog gets to it
// (Codex P1 #1928). Every stamp reads the clock under the same lock as the
// expiry decision, so each keep-alive is ordered before or after it (Codex
// P1 #1928 round 4). A nil *watchdogState is a child without a watchdog.
type watchdogState struct {
	interval time.Duration
	clock    Clock

	mu sync.Mutex
	// deadline is absolute, on clock; zero until READY=1.
	deadline time.Time
	// missed is set by a keep-alive received after the deadline.
	missed bool
	// expired is set by expire once the child has missed its watchdog;
	// it is final: no later keep-alive revives the child.
	expired bool
	// wake tells the watchdog the state changed. One pending signal is
	// enough: the watchdog reads the whole state each time.
	wake chan struct{}
}

func newWatchdogState(interval time.Duration, clock Clock) *watchdogState {
	if interval <= 0 {
		return nil
	}
	return &watchdogState{interval: interval, clock: clock, wake: make(chan struct{}, 1)}
}

// ready sets the first deadline, one interval after READY=1's receipt.
func (w *watchdogState) ready() {
	if w == nil {
		return
	}
	w.mu.Lock()
	if w.deadline.IsZero() {
		w.deadline = w.clock.Now().Add(w.interval)
	}
	w.mu.Unlock()
	// No wake-up: the watchdog reads the state once ready closes.
}

// keepAlive records a WATCHDOG=1 received now: past the deadline it is a
// miss, otherwise the deadline moves to one interval after it. Before
// READY=1 there is no deadline yet, and after the expiry the verdict is
// final: in both cases a keep-alive changes nothing.
func (w *watchdogState) keepAlive() {
	if w == nil {
		return
	}
	w.mu.Lock()
	now := w.clock.Now()
	switch {
	case w.deadline.IsZero(), w.expired:
	case now.After(w.deadline):
		w.missed = true
	default:
		w.deadline = now.Add(w.interval)
	}
	w.mu.Unlock()
	w.signal()
}

func (w *watchdogState) signal() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// expire decides, under the stamps' lock, whether the child has missed its
// watchdog: once the deadline has passed (or a keep-alive came late) it
// sets the final expired verdict and reports it; otherwise it returns how
// long the child has left.
func (w *watchdogState) expire() (left time.Duration, expired bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.expired {
		return 0, true
	}
	left = w.deadline.Sub(w.clock.Now())
	if w.missed || left <= 0 {
		w.expired = true
		return 0, true
	}
	return left, false
}

// watch waits for the child to exit and restarts it while the parent still
// wants services from it and its restart budget holds.
func (s *Supervisor) watch(ctx context.Context, proc *supervised, child Child, notify *NotifySocket, done chan struct{}) {
	defer close(done)

	waitErr := child.Wait()

	s.mu.Lock()
	// The child is reaped: its notify socket goes with it, which is what
	// ends its reader. Nothing else would close it when no launch follows
	// (an exhausted restart budget).
	s.closeNotifyOfLocked(proc, notify)
	// A stop cancelled the context, or is under way: the exit is expected
	// and the process stays down (or is relaunched by whoever stopped it).
	if ctx.Err() != nil || s.stopped || proc.stopping || len(proc.wanted) == 0 {
		proc.child = nil
		proc.missed, proc.missedChild = nil, nil
		s.closeClientLocked(proc)
		s.mu.Unlock()
		return
	}
	proc.child = nil
	s.closeClientLocked(proc)
	// A child its watchdog stopped failed by missing its keep-alive, not
	// by the signal that ended it.
	var failure, cause error = &ErrProcessExited{Process: proc.def.Name, Cause: waitErr}, waitErr
	if proc.missedChild == child && proc.missed != nil {
		failure, cause = proc.missed, proc.missed
	}
	proc.missed, proc.missedChild = nil, nil
	// Recorded with the child cleared: a StartService claim made before
	// runExitHook or noteRestart sees a replacement and replays followers.
	proc.failure = failure
	// The generation that exited: the hook below and its retries clean up
	// after this child only, never over a replacement claimed since.
	gen := proc.launchGen
	s.mu.Unlock()

	s.runExitHook(ctx, proc, gen)
	s.restartLoop(ctx, proc, gen, failure, cause)
}

// runExitHook calls Config.OnChildExit for proc's unrequested exit and
// records the outcome: a failure is logged at Error and kept in
// proc.exitHookErr, which noteRestart folds into the process's health and
// restartLoop retries on each backoff tick. gen is the launch generation
// that exited: the hook runs only while no child is up or claimed and the
// generation is unchanged, with proc.cleaning set so launch claims wait.
func (s *Supervisor) runExitHook(ctx context.Context, proc *supervised, gen uint64) {
	if s.cfg.OnChildExit == nil {
		return
	}
	// Fenced to the exited child: a replacement that is running, or whose
	// launch is claimed, owns the process's state now, and the hook's
	// cleanup would tear down what it set up. A hook already in flight is
	// left to finish alone. A claim held for gen itself is the exited
	// child's own unfinished launch (a crash during readiness): its
	// cleanup is owed, so only a claim for another generation skips it.
	s.mu.Lock()
	if proc.child != nil || (proc.launching && proc.claimGen != gen) || proc.cleaning || proc.launchGen != gen {
		s.mu.Unlock()
		return
	}
	proc.cleaning = true
	done := make(chan struct{})
	proc.cleanDone = done
	s.mu.Unlock()

	err := s.cfg.OnChildExit(ctx, proc.def)
	if err != nil {
		err = &ErrExitHook{Process: proc.def.Name, Cause: err}
		s.cfg.Logger.Error("gatewayd supervisor: child exit hook failed",
			slog.String("process", proc.def.Name), slog.Any("error", err))
	}
	s.mu.Lock()
	proc.cleaning = false
	proc.cleanDone = nil
	close(done)
	if proc.launchGen == gen {
		proc.exitHookErr = err
	}
	s.mu.Unlock()
}

// awaitCleaningLocked waits, with s.mu held on entry and on return, until no
// exit hook is running for proc. Every launch claim of a process with no
// child calls it first, so cleanup after an exit and the replacement launch
// are serialized.
func (s *Supervisor) awaitCleaningLocked(ctx context.Context, proc *supervised) error {
	for proc.cleaning {
		done := proc.cleanDone
		s.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			s.mu.Lock()
			return ctx.Err()
		}
		s.mu.Lock()
	}
	return nil
}

// ErrExitHook reports a failed Config.OnChildExit call.
type ErrExitHook struct {
	Process string
	Cause   error
}

func (e *ErrExitHook) Error() string {
	return "gatewayd supervisor: exit hook for process " + e.Process + " failed: " + e.Cause.Error()
}

func (e *ErrExitHook) Unwrap() error { return e.Cause }

// restartLoop brings a process back up, and keeps trying while its restart
// budget holds.
//
// The loop is the point. A single attempt would let one transient launch
// failure — a cgroup leaf that could not be written, an exec that lost a race
// with a package upgrade — leave still-wanted services down for good with the
// budget untouched, because the watch goroutine that would have tried again
// has already returned. A failed relaunch therefore spends budget exactly like
// a crash does, which is also what stops the loop from spinning forever
// against a process that can never start.
func (s *Supervisor) restartLoop(ctx context.Context, proc *supervised, gen uint64, failure error, cause error) {
	for {
		backoff, over, w := s.noteRestart(ctx, proc, gen, failure, cause)
		if over {
			if w != nil {
				w.err = s.withdrawFollowerPeers(w.ctx, w.stop, proc)
				w.cancel()
				close(w.done)
				s.mu.Lock()
				if proc.withdrawal == w {
					proc.withdrawal = nil
				}
				s.mu.Unlock()
			}
			s.retryExitHookPastBudget(ctx, proc, gen)
			return
		}
		s.cfg.Logger.Warn("gatewayd supervisor: process down, restarting",
			slog.String("process", proc.def.Name),
			slog.Duration("backoff", backoff),
			slog.Any("error", cause),
			s.memoryAttr(proc.def.Name))

		select {
		case <-ctx.Done():
			return
		case <-s.cfg.Clock.After(backoff):
		}

		s.mu.Lock()
		hookPending := proc.exitHookErr != nil
		s.mu.Unlock()
		if hookPending {
			s.runExitHook(ctx, proc, gen)
		}

		s.mu.Lock()
		if err := s.awaitCleaningLocked(ctx, proc); err != nil {
			s.mu.Unlock()
			return
		}
		stillWanted := !s.stopped && !proc.stopping && len(proc.wanted) > 0 && proc.child == nil && !proc.launching
		if stillWanted {
			proc.launchGen++
			gen = proc.launchGen
			proc.launching = true
			proc.claimGen = proc.launchGen
			proc.followPending = false
			proc.restoring = proc.desired != nil
		}
		s.mu.Unlock()
		if !stillWanted {
			return
		}
		err := s.launch(ctx, proc)
		if err == nil {
			err = s.serveLaunched(ctx, proc)
		}
		s.mu.Lock()
		proc.restoring = false
		s.mu.Unlock()
		if err == nil {
			err = s.awaitWanted(ctx, proc)
		}
		s.mu.Lock()
		proc.launching = false
		s.mu.Unlock()
		if err == nil {
			// The relaunched child is up: a stale exit-hook failure no
			// longer describes it.
			s.mu.Lock()
			proc.exitHookErr = nil
			s.mu.Unlock()
			s.relaunchFollowers(ctx, proc)
			s.relaunchPendingFollower(ctx, proc)
			return
		}
		s.cfg.Logger.Error("gatewayd supervisor: restart failed",
			slog.String("process", proc.def.Name), slog.Any("error", err))
		failure, cause = err, err
	}
}

// retryExitHookPastBudget keeps retrying a failed exit hook of a given-up
// process on its own doubling backoff until it succeeds, the supervisor or
// the watch context stops, or a replacement of another generation takes the
// process over (#2029 Codex r1). A non-follower has no withdrawal, so
// without this the kernel state the hook removes (the WireGuard hub and its
// peers) would outlive its process with nothing able to revoke it. gen is
// the generation that gave up: runExitHook fences every retry to it. The
// failure stays in the process's health, joined to the give-up, until a
// retry succeeds.
func (s *Supervisor) retryExitHookPastBudget(ctx context.Context, proc *supervised, gen uint64) {
	// givenUp reports, with s.mu held, whether gen's give-up is still the
	// process's state: a replacement owns failure from its claim on.
	givenUp := func() bool {
		return !s.stopped && proc.child == nil && !proc.launching && proc.launchGen == gen
	}
	s.mu.Lock()
	budget := proc.failure
	showHookErr := func() {
		if !givenUp() {
			return
		}
		proc.failure = budget
		if proc.exitHookErr != nil {
			proc.failure = errors.Join(budget, proc.exitHookErr)
		}
	}
	showHookErr()
	s.mu.Unlock()

	backoff := s.cfg.RestartBackoff
	for {
		s.mu.Lock()
		pending := proc.exitHookErr != nil && givenUp()
		s.mu.Unlock()
		if !pending {
			return
		}
		s.cfg.Logger.Warn("gatewayd supervisor: retrying child exit hook past the restart budget",
			slog.String("process", proc.def.Name), slog.Duration("backoff", backoff))
		select {
		case <-ctx.Done():
			return
		case <-s.cfg.Clock.After(backoff):
		}
		s.runExitHook(ctx, proc, gen)
		s.mu.Lock()
		showHookErr()
		s.mu.Unlock()
		if backoff < s.cfg.RestartBackoffMax {
			backoff = min(backoff*2, s.cfg.RestartBackoffMax)
		}
	}
}

// followerVPNPlanes names the VPN planes a datapath child may host for a
// follower (vpn.DataPlaneWireGuard and vpn.DataPlaneMASQUE; the vpn package
// is not imported here, so the names are repeated).
var followerVPNPlanes = []string{"wireguard", "masque"}

// withdrawFollowerPeers removes every peer the datapath child hosts for a
// follower the supervisor has given up on. The follower is the only lease
// expiry authority, so its peers must not outlive it; a later start of the
// follower reinstalls the leases that are still valid (Restore). A plane the
// datapath does not host confirms at once. A refusal, a transport failure or
// a missing datapath is logged and retried, the backoff doubling from
// RestartBackoff up to RestartBackoffMax, until every plane is confirmed, ctx
// ends (stopProcess cancels it at Shutdown), the supervisor stops, or the
// follower launches again and becomes the expiry authority. A replacement
// launch cancels ctx and waits for this to return (awaitWithdrawal), so no
// withdrawal request outlives the launch claim.
func (s *Supervisor) withdrawFollowerPeers(ctx context.Context, stop <-chan struct{}, proc *supervised) error {
	pending := append([]string(nil), followerVPNPlanes...)
	backoff := s.cfg.RestartBackoff
	var lastErr error
	for {
		// A new launch of the follower is the expiry authority again and
		// reconciles the hosted peers at its own start: checked before
		// every round, the first included.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		select {
		case <-stop:
			return lastErr
		default:
		}
		if s.followerRelaunched(proc) {
			return lastErr
		}
		pending, lastErr = s.withdrawRound(ctx, stop, proc, pending)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if len(pending) == 0 {
			s.cfg.Logger.Info("gatewayd supervisor: vpn peers withdrawn from the datapath",
				slog.String("process", proc.def.Name))
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-stop:
			return lastErr
		case <-s.cfg.Clock.After(backoff):
		}
		backoff *= 2
		if backoff > s.cfg.RestartBackoffMax {
			backoff = s.cfg.RestartBackoffMax
		}
	}
}

// followerRelaunched reports whether a given-up follower is being, or has
// been, launched again (or is stopping), so its withdrawal must not run.
func (s *Supervisor) followerRelaunched(proc *supervised) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopped || proc.stopping || proc.child != nil || proc.launching
}

// withdrawRound asks the datapath once to withdraw every peer of each pending
// plane and returns the planes whose withdrawal it did not confirm. Without a
// datapath every plane stays pending. Each request runs on ctx, which a
// replacement launch cancels before it execs the new child, so the datapath
// handler stops a withdrawal the replacement fenced; the planes not yet
// asked stay pending.
func (s *Supervisor) withdrawRound(ctx context.Context, stop <-chan struct{}, proc *supervised, pending []string) ([]string, error) {
	client, err := s.followedClient(proc.def.Follows)
	if err != nil {
		s.cfg.Logger.Warn("gatewayd supervisor: no followed process to withdraw the given-up process's vpn peers from",
			slog.String("process", proc.def.Name), slog.Any("error", err))
		return pending, nil
	}
	var left []string
	var callErr error
	for i, plane := range pending {
		if ctx.Err() != nil {
			return append(left, pending[i:]...), callErr
		}
		select {
		case <-stop:
			return append(left, pending[i:]...), callErr
		default:
		}
		rctx, cancel := context.WithTimeout(ctx, statusTimeout)
		resp, err := client.ReconcileVPNPeers(rctx, &ipcv1.ReconcileVPNPeersRequest{DataPlane: plane})
		cancel()
		switch {
		case err != nil:
			s.cfg.Logger.Warn("gatewayd supervisor: withdrawing vpn peers failed",
				slog.String("process", proc.def.Name), slog.String("plane", plane), slog.Any("error", err))
			left = append(left, plane)
			// No answer means no acknowledgement that the datapath's
			// handler finished: it may still run after this returns.
			callErr = errors.Join(callErr, err)
		case resp.GetRefusal() != nil:
			s.cfg.Logger.Warn("gatewayd supervisor: datapath refused the vpn peer withdrawal",
				slog.String("process", proc.def.Name), slog.String("plane", plane),
				slog.String("refusal", resp.GetRefusal().String()))
			left = append(left, plane)
		}
	}
	return left, callErr
}

// awaitWithdrawal fences the launch the caller has claimed against a given-up
// follower's peer withdrawal. It stops the withdrawal from starting another
// round or waiting out its backoff, but it does not cancel a
// ReconcileVPNPeers call in flight: a cancelled gRPC call returns at once
// while the datapath's handler may still run, and would then remove the
// peers the replacement restores with its old, empty keep list. It waits for
// that call to return, within the call's own deadline, which is the server's
// acknowledgement that the handler finished.
//
// A withdrawal whose last call failed or timed out carries no such
// acknowledgement: awaitWithdrawal returns an error and the caller does not
// launch in this round, so the follower stays given up (fail closed) and the
// next start retries. It returns ctx.Err() when ctx ends first.
func awaitWithdrawal(ctx context.Context, w *withdrawal) error {
	if w == nil {
		return nil
	}
	w.stopOnce.Do(func() { close(w.stop) })
	select {
	case <-w.done:
		if w.err != nil {
			return fmt.Errorf("process: the given-up follower's vpn peer withdrawal was not acknowledged: %w", w.err)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// relaunchFollowers relaunches every running process that keeps state in
// the followed child (Definition.Follows names it) once followed, the
// relaunched process, answers. The crashed datapath child took that
// state with it, and such a process reinstalls it only at its start: the
// vpn child's Restore reinstalls each stored lease into the new planes.
// The process is reported down (restoring) until that start is done.
func (s *Supervisor) relaunchFollowers(ctx context.Context, followed *supervised) {
	s.mu.Lock()
	var followers []*supervised
	for _, p := range s.processes {
		if p == followed || p.def.Follows != followed.def.Name || s.stopped || p.stopping || len(p.wanted) == 0 {
			continue
		}
		if p.launching {
			// Its launch may already have restored into the datapath child
			// that is gone: relaunch it once that launch completes.
			p.followPending = true
			continue
		}
		if p.child == nil {
			continue
		}
		p.launchGen++
		p.launching = true
		p.claimGen = p.launchGen
		p.followPending = false
		followers = append(followers, p)
	}
	s.mu.Unlock()

	for _, p := range followers {
		s.relaunchFollower(ctx, p)
	}
}

// relaunchPendingFollower relaunches proc, whose launch has just
// completed, when a datapath relaunch landed while it was in flight
// (followPending). It does nothing otherwise.
func (s *Supervisor) relaunchPendingFollower(ctx context.Context, proc *supervised) {
	s.mu.Lock()
	claimed := proc.followPending && !s.stopped && !proc.stopping && !proc.launching &&
		proc.child != nil && len(proc.wanted) > 0
	proc.followPending = false
	if claimed {
		proc.launchGen++
		proc.launching = true
		proc.claimGen = proc.launchGen
	}
	s.mu.Unlock()
	if claimed {
		s.relaunchFollower(ctx, proc)
	}
}

// relaunchFollower stops and relaunches p, a Follows process the
// caller has claimed (p.launching), so its start reinstalls its state
// into the current datapath child.
func (s *Supervisor) relaunchFollower(ctx context.Context, p *supervised) {
	if err := s.stopProcess(ctx, p); err != nil {
		s.mu.Lock()
		p.launching = false
		p.followPending = false
		s.mu.Unlock()
		s.cfg.Logger.Error("gatewayd supervisor: stopping a process for the datapath relaunch failed",
			slog.String("process", p.def.Name), slog.Any("error", err))
		return
	}
	s.mu.Lock()
	p.stopping = false
	stillWanted := !s.stopped && len(p.wanted) > 0
	p.restoring = stillWanted && p.desired != nil
	s.mu.Unlock()
	var err error
	if stillWanted {
		s.cfg.Logger.Info("gatewayd supervisor: relaunching a process after the datapath relaunch",
			slog.String("process", p.def.Name))
		if err = s.launch(ctx, p); err == nil {
			err = s.serveLaunched(ctx, p)
		}
	}
	s.mu.Lock()
	p.restoring = false
	s.mu.Unlock()
	if stillWanted && err == nil {
		err = s.awaitWanted(ctx, p)
	}
	s.mu.Lock()
	p.launching = false
	gen := p.launchGen
	if err == nil {
		p.exitHookErr = nil
	}
	s.mu.Unlock()
	if err != nil {
		s.cfg.Logger.Error("gatewayd supervisor: relaunch after the datapath relaunch failed",
			slog.String("process", p.def.Name), slog.Any("error", err))
		go s.restartLoop(ctx, p, gen, err, err)
		return
	}
	s.relaunchPendingFollower(ctx, p)
}

// noteRestart records one restart against the budget and returns the backoff
// to wait before the next attempt. It reports over when the budget is spent,
// having left the exhaustion in the process's failure for the health report.
func (s *Supervisor) noteRestart(ctx context.Context, proc *supervised, gen uint64, failure error, cause error) (time.Duration, bool, *withdrawal) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// A replacement of another generation is up or claimed: it owns the
	// process's failure, budget and follower replay, so this loop's
	// bookkeeping stops here. A claim of gen itself (a crash during
	// readiness) is not fenced.
	if proc.child != nil || (proc.launching && proc.claimGen != gen) {
		return 0, true, nil
	}

	now := s.cfg.Clock.Now()
	// A process that stayed up longer than the whole window is not in a
	// crash loop; its history and its backoff start over, so a daily crash
	// never accumulates into a refusal to restart.
	if !proc.startedAt.IsZero() && now.Sub(proc.startedAt) > s.cfg.RestartWindow {
		proc.restarts = nil
		proc.backoff = 0
	}
	// The reset above applies once per down-cycle, not once per attempt.
	// Leaving startedAt behind would let a process that ran for a week and
	// then cannot be relaunched clear its own history on every pass, so the
	// budget would never be reached and the loop would retry forever.
	proc.startedAt = time.Time{}
	proc.restarts = append(withinWindow(proc.restarts, now, s.cfg.RestartWindow), now)
	if len(proc.restarts) > s.cfg.RestartBudget {
		proc.failure = &ErrRestartBudgetExhausted{
			Process:  proc.def.Name,
			Restarts: len(proc.restarts),
			Window:   s.cfg.RestartWindow,
			Last:     cause,
		}
		s.cfg.Logger.Error("gatewayd supervisor: giving up on process", slog.Any("error", proc.failure))
		// A given-up follower leaves its peers in the datapath with no
		// expiry authority. Its withdrawal is registered here, under the
		// lock that decided the give-up, and only when no replacement
		// launch is claimed: a claimant either came first (and restores
		// its own peers) or sees this withdrawal and fences it.
		if proc.def.Follows == "" || proc.child != nil || proc.launching || s.stopped || proc.stopping {
			return 0, true, nil
		}
		wctx, cancel := context.WithCancel(ctx)
		w := &withdrawal{ctx: wctx, cancel: cancel, done: make(chan struct{}), stop: make(chan struct{})}
		proc.withdrawal = w
		return 0, true, w
	}
	if proc.backoff == 0 {
		proc.backoff = s.cfg.RestartBackoff
	} else if proc.backoff < s.cfg.RestartBackoffMax {
		proc.backoff *= 2
		if proc.backoff > s.cfg.RestartBackoffMax {
			proc.backoff = s.cfg.RestartBackoffMax
		}
	}
	proc.failure = failure
	if proc.exitHookErr != nil {
		proc.failure = errors.Join(failure, proc.exitHookErr)
	}
	return proc.backoff, false, nil
}

// awaitProcess waits for a freshly launched child to answer on its control
// socket. It asks only that the child is serving; which of its services came
// up is the caller's question in StartService, and the health report's
// afterwards.
func (s *Supervisor) awaitProcess(ctx context.Context, proc *supervised) error {
	started := s.cfg.Clock.Now()
	deadline := started.Add(s.cfg.ReadyTimeout)
	var lastErr error
	var seen chan struct{}
	for {
		s.mu.Lock()
		client, failure, ready := proc.client, proc.failure, proc.ready
		s.mu.Unlock()
		if ready == seen {
			// Already woken by this child's READY=1: a closed channel in
			// the select would spin the loop.
			ready = nil
		}
		if failure != nil {
			return &ErrProcessDown{Process: proc.def.Name, Cause: failure}
		}
		if client != nil {
			if _, err := client.Status(ctx); err == nil {
				s.cfg.Logger.Info("gatewayd supervisor: process answering",
					slog.String("process", proc.def.Name),
					slog.Duration("waited", s.cfg.Clock.Now().Sub(started)))
				return nil
			} else {
				lastErr = err
			}
		}
		if !s.cfg.Clock.Now().Before(deadline) {
			return &ErrProcessUnreachable{
				Process: proc.def.Name, Socket: proc.socket,
				Waited: s.cfg.ReadyTimeout, Cause: lastErr,
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ready:
			seen = ready
		case <-s.cfg.Clock.After(readyPollInterval):
		}
	}
}

// restoreDesired gives a relaunched child the last desired document its
// process was sent (#557). The new child starts with nothing applied — its
// applied version is empty, so its own version check cannot skip the
// document — while the parent still holds that document's version and would
// skip it, which is why the re-send belongs here and not in the parent. A
// process that was never sent a document gets nothing.
//
// The document is read only once the apply slot is held: an Apply that
// arrives during the relaunch either ran first, and is the document read
// here, or waits for this send and overwrites it. A newer document is never
// overwritten by an older one.
// serveLaunched has a child just launched in place of an earlier one — a
// relaunch after a crash, or a start after a stop — prove it serves before it
// counts: ipc.Dial is lazy (grpc.NewClient connects on the first call), so a
// child that starts and never answers would otherwise be accepted as live.
// Serving includes holding the desired config its predecessor held, so the
// child is given it once it answers (#557). A child that fails either is
// stopped, and the reason returned.
func (s *Supervisor) serveLaunched(ctx context.Context, proc *supervised) error {
	ready := s.awaitProcess(ctx, proc)
	if ready == nil {
		ready = s.restoreDesired(ctx, proc)
	}
	if ready != nil {
		// This one is published, so it has a child and a watch goroutine of
		// its own; both have to go. A launch that FAILED published nothing
		// and cleaned up after itself, which is why this is not in that
		// path: proc.cancel would still be the crashed child's, and that
		// context is the one a restart loop is running under.
		s.stopUnservingChild(ctx, proc)
	}
	return ready
}

// awaitWanted waits, once a relaunched child has been given its document,
// for every service still wanted of it to start. A child that answers its
// socket and took its document has not recovered if its Gateway.Start
// failed (a vpn child that could not fetch its lease projection during a
// control-plane outage keeps serving that start error, VPN inactive): it is
// stopped, and the caller retries it as a failed restart.
func (s *Supervisor) awaitWanted(ctx context.Context, proc *supervised) error {
	s.mu.Lock()
	services := make([]string, 0, len(proc.wanted))
	for service := range proc.wanted {
		services = append(services, service)
	}
	s.mu.Unlock()
	for _, service := range services {
		if err := s.awaitService(ctx, proc, service); err != nil {
			s.stopUnservingChild(ctx, proc)
			return err
		}
	}
	return nil
}

func (s *Supervisor) restoreDesired(ctx context.Context, proc *supervised) error {
	if err := s.acquireApply(ctx); err != nil {
		return err
	}
	defer s.releaseApply()

	s.mu.Lock()
	desired, client, failure := proc.desired, proc.client, proc.failure
	s.mu.Unlock()
	if desired == nil {
		return nil
	}
	if client == nil {
		// The child answered and then died; its watch goroutine took the
		// client with it.
		return &ErrDesiredRestoreFailed{
			Process: proc.def.Name, Version: desired.EffectiveVersion(),
			Cause: &ErrProcessDown{Process: proc.def.Name, Cause: failure},
		}
	}
	applyCtx, cancel := context.WithTimeout(ctx, s.cfg.ReadyTimeout)
	defer cancel()
	if _, err := client.ApplyDesired(applyCtx, desired); err != nil {
		return &ErrDesiredRestoreFailed{Process: proc.def.Name, Version: desired.EffectiveVersion(), Cause: err}
	}
	s.cfg.Logger.Info("gatewayd supervisor: desired config re-applied to relaunched process",
		slog.String("process", proc.def.Name),
		slog.String("version", desired.EffectiveVersion()))
	return nil
}

// acquireApply takes the apply slot, or gives up when ctx ends.
func (s *Supervisor) acquireApply(ctx context.Context) error {
	select {
	case s.applying <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// releaseApply returns the apply slot.
func (s *Supervisor) releaseApply() {
	<-s.applying
}

// stopUnservingChild ends a child that was launched but never answered, so the
// next restart attempt does not race the last one's leftovers.
func (s *Supervisor) stopUnservingChild(ctx context.Context, proc *supervised) {
	s.mu.Lock()
	child, cancel, done, notify := proc.child, proc.cancel, proc.done, proc.notify
	proc.cancel = nil
	s.mu.Unlock()

	// Cancel FIRST here, unlike a stop. This child has a watch goroutine that
	// would otherwise see a still-wanted process and start a second restart
	// loop competing with this one; a cancelled context is what sends it down
	// its expected-exit path instead. Cancelling is safe to do first because
	// the launcher's cancellation is a SIGTERM, not a kill.
	if cancel != nil {
		cancel()
	}
	if child == nil {
		s.mu.Lock()
		s.closeNotifyOfLocked(proc, notify)
		s.mu.Unlock()
		return
	}
	if err := s.terminate(context.WithoutCancel(ctx), proc.def.Name, child, done); err != nil {
		s.cfg.Logger.Error("gatewayd supervisor: stopping a child that never served",
			slog.String("process", proc.def.Name), slog.Any("error", err))
	}
	s.mu.Lock()
	proc.child = nil
	s.closeClientLocked(proc)
	// The watch goroutine closes it on reaping; this covers a child that
	// would not die, so its reader does not outlive the teardown.
	s.closeNotifyOfLocked(proc, notify)
	s.mu.Unlock()
}

// withinWindow keeps the timestamps inside the trailing window.
func withinWindow(times []time.Time, now time.Time, window time.Duration) []time.Time {
	cutoff := now.Add(-window)
	kept := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	return kept
}

// closeClientLocked releases the IPC connection. The caller holds s.mu.
func (s *Supervisor) closeClientLocked(proc *supervised) {
	if proc.client == nil {
		return
	}
	if err := proc.client.Close(); err != nil {
		s.cfg.Logger.Warn("gatewayd supervisor: closing process client",
			slog.String("process", proc.def.Name), slog.Any("error", err))
	}
	proc.client = nil
}

// closeNotifyLocked releases the child's sd_notify socket. The caller holds
// s.mu.
func (s *Supervisor) closeNotifyLocked(proc *supervised) {
	if proc.notify == nil {
		return
	}
	if err := proc.notify.Close(); err != nil {
		s.cfg.Logger.Warn("gatewayd supervisor: closing process notify socket",
			slog.String("process", proc.def.Name), slog.Any("error", err))
	}
	proc.notify = nil
}

// closeNotifyOfLocked closes notify only while it is still proc's current
// notify socket: a newer launch's socket is never closed on behalf of an
// older child, and a socket already closed (proc.notify reset to nil) is not
// closed twice. The caller holds s.mu.
func (s *Supervisor) closeNotifyOfLocked(proc *supervised, notify *NotifySocket) {
	if notify == nil || proc.notify != notify {
		return
	}
	s.closeNotifyLocked(proc)
}

// readNotify reads one child's notify socket until closeNotifyLocked closes
// it. It closes ready on the child's first READY=1, so a wait for the child
// asks again at once rather than a poll interval later; the poll stays the
// fallback for a child that never notifies. It touches no proc field: the
// socket and the channel are its own launch's, passed in.
func (s *Supervisor) readNotify(process string, notify *NotifySocket, ready chan struct{}, wd *watchdogState, gone chan struct{}) {
	defer close(gone)
	signalled := false
	for {
		msg, err := notify.Receive(time.Time{})
		if err != nil {
			var sockErr *ErrNotifySocket
			if errors.As(err, &sockErr) {
				// Closed by closeNotifyLocked: this child's socket is gone.
				return
			}
			s.cfg.Logger.Warn("gatewayd supervisor: unparsable notify datagram",
				slog.String("process", process), slog.Any("error", err))
			continue
		}
		if msg.Status != "" {
			s.cfg.Logger.Debug("gatewayd supervisor: process status",
				slog.String("process", process), slog.Int("pid", msg.Pid), slog.String("status", msg.Status))
		}
		if msg.Stopping {
			s.cfg.Logger.Info("gatewayd supervisor: process stopping",
				slog.String("process", process), slog.Int("pid", msg.Pid))
		}
		if msg.Ready && !signalled {
			signalled = true
			// The first deadline counts from READY=1's receipt.
			wd.ready()
			close(ready)
		}
		if msg.Watchdog {
			// Judged on receipt against the absolute deadline, never by
			// when the watchdog gets to it (Codex P1 #1928).
			wd.keepAlive()
		}
	}
}

// watchdog enforces a ready child's WATCHDOG=1 keep-alives: from its
// readiness, every keep-alive re-arms a deadline of one interval, and a
// deadline that passes stops the child, recording ErrWatchdogMissed as its
// failure so that watch restarts it through the restart backoff. It acts
// only on child, never on a later launch, and returns when the child's
// notify reader ends (the child is reaped) or the launch context is
// cancelled.
func (s *Supervisor) watchdog(ctx context.Context, proc *supervised, child Child, wd *watchdogState, ready <-chan struct{}, gone <-chan struct{}) {
	interval := wd.interval
	select {
	case <-ready:
	case <-gone:
		return
	case <-ctx.Done():
		return
	}
	// The deadline is absolute and kept by the notify reader (Codex P1
	// #1928): on every wake-up or timer the watchdog waits only for the
	// time left to it, so a late wake-up never extends it.
	for {
		// The child is stopped only on expire's verdict, taken under the
		// lock that orders every keep-alive stamp (Codex P1 #1928 round 4).
		left, expired := wd.expire()
		if expired {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-gone:
			return
		case <-wd.wake:
		case <-s.cfg.Clock.After(left):
		}
	}

	s.mu.Lock()
	current := proc.child == child && !proc.stopping && !s.stopped
	if current {
		proc.missed = &ErrWatchdogMissed{Process: proc.def.Name, Interval: interval}
		proc.missedChild = child
	}
	s.mu.Unlock()
	if !current {
		return
	}
	s.cfg.Logger.Warn("gatewayd supervisor: process missed its watchdog, stopping it",
		slog.String("process", proc.def.Name),
		slog.Duration("interval", interval),
		slog.Int("pid", child.PID()))
	// gone closes when watch has reaped the child and closed its notify
	// socket; watch's done would wait for the whole restart.
	if err := s.terminate(ctx, proc.def.Name, child, gone); err != nil && ctx.Err() == nil {
		s.cfg.Logger.Warn("gatewayd supervisor: stopping a process that missed its watchdog",
			slog.String("process", proc.def.Name), slog.Any("error", err))
	}
}

// StopService implements gateway.ServiceSupervisor: the service is released,
// and the process stops once none of its services remain wanted.
func (s *Supervisor) StopService(ctx context.Context, service string) error {
	def, err := DefinitionForService(service)
	if err != nil {
		return err
	}
	s.mu.Lock()
	proc, ok := s.processes[def.Name]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	delete(proc.wanted, service)
	remaining := len(proc.wanted)
	s.mu.Unlock()

	if remaining > 0 {
		return nil
	}
	return s.stopProcess(ctx, proc)
}

// stopProcess signals the child, waits for its watch goroutine, and kills it
// if the graceful stop does not land inside StopTimeout.
func (s *Supervisor) stopProcess(ctx context.Context, proc *supervised) error {
	s.mu.Lock()
	proc.stopping = true
	child, cancel, done := proc.child, proc.cancel, proc.done
	proc.cancel = nil
	s.mu.Unlock()

	// The cancel is deliberately NOT called here. The launch context is the
	// one exec.CommandContext watches, and cancelling it asks the child to
	// stop — so cancelling before SIGTERM would race the signal this function
	// is about to send and collapse the whole StopTimeout window into one
	// cancellation. It runs once the child has been reaped, below, where its
	// remaining job is to release the context and stop the watch goroutine
	// from relaunching.
	if child == nil {
		if cancel != nil {
			cancel()
		}
		// No child to signal — it exited on its own, or its restart budget
		// ran out. The rest of the teardown still has to happen: the
		// process's cgroup leaf outlives the child that was born into it,
		// and a failure left over from the crash would otherwise be
		// reported for a process nobody is running any more.
		s.clearProcessState(proc)
		s.removeCgroup(ctx, proc)
		return nil
	}
	if err := s.terminate(ctx, proc.def.Name, child, done); err != nil {
		return err
	}
	if cancel != nil {
		cancel()
	}

	s.clearProcessState(proc)
	s.removeCgroup(ctx, proc)
	s.cfg.Logger.Info("gatewayd supervisor: process stopped", slog.String("process", proc.def.Name))
	return nil
}

// terminate asks a child to stop and kills it if it does not, waiting on the
// channel that closes when it has been reaped. It is the one place the
// graceful-then-kill sequence lives, so every path that ends a child is bound
// by StopTimeout rather than waiting on it forever.
func (s *Supervisor) terminate(ctx context.Context, name string, child Child, done <-chan struct{}) error {
	if err := child.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		s.cfg.Logger.Warn("gatewayd supervisor: signalling process",
			slog.String("process", name), slog.Any("error", err))
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.cfg.Clock.After(s.cfg.StopTimeout):
	}
	s.cfg.Logger.Warn("gatewayd supervisor: process did not stop, killing",
		slog.String("process", name))
	if err := child.Signal(syscall.SIGKILL); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return &ErrProcessDown{Process: name, Cause: err}
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// clearProcessState returns a stopped process to its pre-launch state, so a
// later start is not judged by the crash history of the run before it.
func (s *Supervisor) clearProcessState(proc *supervised) {
	s.mu.Lock()
	defer s.mu.Unlock()
	proc.child = nil
	proc.failure = nil
	proc.restarts = nil
	proc.backoff = 0
	s.closeClientLocked(proc)
	s.closeNotifyLocked(proc)
}

// removeCgroup deletes the process's cgroup leaf. A leaf that cannot be
// removed is logged rather than retried: it means something is still in it,
// which the stop above was supposed to have ended.
func (s *Supervisor) removeCgroup(ctx context.Context, proc *supervised) {
	// Nil-safe for the same reason as Prepare in launch. The leaf's
	// accounting is read before the leaf goes: it is the class's measured
	// peak for the whole time the process was up.
	if s.cfg.Cgroups.Enabled() {
		s.cfg.Logger.Info("gatewayd supervisor: process memory",
			slog.String("process", proc.def.Name), s.memoryAttr(proc.def.Name))
	}
	// The kernel empties the leaf moments after the child is reaped; a
	// leaf still populated after StopTimeout has a process in it that
	// outlived the child.
	removeCtx, cancel := context.WithTimeout(ctx, s.cfg.StopTimeout)
	defer cancel()
	if err := s.cfg.Cgroups.Remove(removeCtx, proc.def.Name); err != nil {
		s.cfg.Logger.Warn("gatewayd supervisor: removing cgroup leaf",
			slog.String("process", proc.def.Name), slog.Any("error", err))
	}
}

// memoryAttr is a process's leaf memory accounting as one log attribute, so
// the gatewayd log carries the measured peak of every class and the OOM
// kills behind a restart. It is empty when cgroup placement is off.
func (s *Supervisor) memoryAttr(name string) slog.Attr {
	if !s.cfg.Cgroups.Enabled() {
		return slog.Attr{}
	}
	usage, err := s.cfg.Cgroups.Memory(name)
	if err != nil {
		return slog.Any("memory_error", err)
	}
	peak := slog.Int64("peak", usage.Peak)
	if !usage.HasPeak {
		peak = slog.String("peak", "absent")
	}
	return slog.Group("memory",
		slog.Int64("current", usage.Current),
		peak,
		slog.Int64("oom_kill", usage.OOMKill))
}

// ServiceActive implements gateway.ServiceSupervisor. It is the child's own
// verdict, read over the control socket; a process that is down reports
// nothing active.
// Supervises implements gateway.ServiceSupervisor: a service is supervised
// once the process the class table places it in has moved out of process.
// A service the table does not place is not supervised, so the gateway keeps
// it in-process and reports its own refusal for it.
func (s *Supervisor) Supervises(service string) bool {
	def, err := DefinitionForService(service)
	return err == nil && def.Supervised
}

func (s *Supervisor) ServiceActive(service string) bool {
	status, _, err := s.serviceStatus(service)
	if err != nil {
		return false
	}
	return status.active
}

// ServiceHealth implements gateway.ServiceSupervisor.
func (s *Supervisor) ServiceHealth(service string) error {
	status, proc, err := s.serviceStatus(service)
	if err != nil {
		return err
	}
	if !status.found {
		return &ErrServiceNotActiveInProcess{Service: service, Process: proc, Detail: status.startError}
	}
	if !status.healthy {
		return &ErrServiceNotActiveInProcess{Service: service, Process: proc, Detail: status.healthError}
	}
	return nil
}

// serviceView is one service's line out of a child's Status response.
type serviceView struct {
	found       bool
	active      bool
	healthy     bool
	healthError string
	startError  string
}

// serviceStatus asks the owning child about one service.
func (s *Supervisor) serviceStatus(service string) (serviceView, string, error) {
	def, client, err := s.serviceClient(service)
	if err != nil {
		return serviceView{}, def.Name, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), statusTimeout)
	defer cancel()
	status, err := client.Status(ctx)
	if err != nil {
		return serviceView{}, def.Name, &ErrProcessDown{Process: def.Name, Service: service, Cause: err}
	}
	view := serviceView{startError: status.GetStartError()}
	for _, svc := range status.GetServices() {
		if svc.GetName() != service {
			continue
		}
		view.found = true
		view.active = svc.GetActive()
		view.healthy = svc.GetHealthy()
		view.healthError = svc.GetHealthError()
	}
	return view, def.Name, nil
}

// serviceClient is the control client of the process owning the service,
// or ErrProcessDown naming why there is none.
func (s *Supervisor) serviceClient(service string) (Definition, *ipc.Client, error) {
	def, err := DefinitionForService(service)
	if err != nil {
		return Definition{}, nil, err
	}
	s.mu.Lock()
	proc, ok := s.processes[def.Name]
	var client *ipc.Client
	var failure error
	restoring := false
	if ok {
		client, failure, restoring = proc.client, proc.failure, proc.restoring
	}
	s.mu.Unlock()

	if ok && client != nil && restoring {
		return def, nil, &ErrProcessDown{Process: def.Name, Service: service, Cause: &ErrDesiredNotRestored{Process: def.Name}}
	}
	if !ok || client == nil {
		if failure == nil {
			// No client and no recorded failure means nothing ever started
			// this process. Saying "supervisor stopped" there would report a
			// shutdown that has not happened.
			failure = &ErrProcessNeverStarted{Process: def.Name}
		}
		return def, nil, &ErrProcessDown{Process: def.Name, Service: service, Cause: failure}
	}
	return def, client, nil
}

// ServiceSnapshot reads the snapshot of the child process hosting the
// service over its control socket. A process that is down, or a socket that
// no longer answers, is ErrProcessDown.
func (s *Supervisor) ServiceSnapshot(ctx context.Context, service string) (*gwstate.Snapshot, error) {
	def, client, err := s.serviceClient(service)
	if err != nil {
		return nil, err
	}
	snap, err := client.Snapshot(ctx)
	if err != nil {
		return nil, &ErrProcessDown{Process: def.Name, Service: service, Cause: err}
	}
	return snap, nil
}

// statusTimeout bounds a status question to a child.
const statusTimeout = 2 * time.Second

// datapathProcess returns the kernel-class process and its live client, which
// owns the load-balancer and NAT services the desired document reconciles.
//
// The class table has exactly one kernel-class process today, but the table
// is data rather than a type: a second one would make an arbitrary choice
// here, silently, and the desired configuration would land in whichever
// process the map iteration reached first. So the ambiguity is a refusal,
// not a pick.
func (s *Supervisor) datapathProcess() (*supervised, *ipc.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	datapath, err := s.kernelProcessLocked(true)
	if err != nil {
		return nil, nil, err
	}
	return datapath, datapath.client, nil
}

// followedClient returns the serving client of the process a follower
// names in Definition.Follows (the `wireguard` process for the vpn row).
func (s *Supervisor) followedClient(name string) (*ipc.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	proc, ok := s.processes[name]
	if !ok || proc.client == nil {
		var cause error = &ErrProcessNeverStarted{Process: name}
		if ok && proc.failure != nil {
			cause = proc.failure
		}
		return nil, &ErrProcessDown{Process: name, Cause: cause}
	}
	return proc.client, nil
}

// kernelProcessLocked returns the one kernel-class process the supervisor
// knows, only among those with a child serving when serving is set. The
// caller holds s.mu.
func (s *Supervisor) kernelProcessLocked(serving bool) (*supervised, error) {
	var datapath *supervised
	var names []string
	for _, proc := range s.processes {
		// The wireguard row is kernel-class too, but it hosts the VPN
		// planes, not the datapath.
		if proc.def.Class != ClassKernel || proc.def.Name == WireGuardProcess || (serving && proc.client == nil) {
			continue
		}
		names = append(names, proc.def.Name)
		datapath = proc
	}
	switch {
	case len(names) == 0:
		return nil, &ErrNoDatapathProcess{}
	case len(names) > 1:
		sort.Strings(names)
		return nil, &ErrAmbiguousDatapath{Processes: names}
	}
	return datapath, nil
}

// recordDesired keeps a document that arrived while the datapath process has
// no child serving — in its restart backoff, mid-relaunch, or stopped — as the
// process's desired document, so the child that comes back is given it rather
// than the older one its predecessor held (#557). The document is not applied
// yet, and the caller is told so: reporting success would have the parent
// believe the version is applied while nothing holds it.
func (s *Supervisor) recordDesired(desired *gwstate.DesiredConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return &ErrNoDatapathProcess{}
	}
	proc, err := s.kernelProcessLocked(false)
	if err != nil {
		return err
	}
	proc.desired = desired
	// A launch already under way reads the document only once it holds the
	// apply slot this caller holds now, so it re-sends this one; until then
	// its services are not reported up.
	if proc.launching {
		proc.restoring = true
	}
	return &ErrDesiredPending{Process: proc.def.Name, Version: desired.EffectiveVersion()}
}

// Apply implements gateway.ServiceSupervisor: the desired document goes to
// every process that reconciles a section of it: the kernel-class process
// (load balancer, NAT), whose state Apply reports, and the vpn child. Each
// process keeps the document, so a child relaunched after a crash, or
// started after this apply, is given it (restoreDesired); the sends hold the
// apply slot so that re-send can never land after them with an older
// document. A child that fails the document joins its error to the result.
// The state is the datapath child's own even then, so with an error it does
// not say the document is applied: the gateway keeps its previous version
// until every child has applied it (#1070).
func (s *Supervisor) Apply(ctx context.Context, desired *gwstate.DesiredConfig) (gwstate.DesiredConfigState, error) {
	if err := s.acquireApply(ctx); err != nil {
		return gwstate.DesiredConfigState{}, err
	}
	defer s.releaseApply()

	forwardErr := s.forwardDesired(ctx, desired)
	state, err := s.applyDatapath(ctx, desired)
	if forwardErr != nil {
		return state, errors.Join(err, forwardErr)
	}
	return state, err
}

// applyDatapath sends the desired document to the datapath child, whose
// reconciliation state is the one Apply reports, or records it for the next
// datapath child when none is serving.
func (s *Supervisor) applyDatapath(ctx context.Context, desired *gwstate.DesiredConfig) (gwstate.DesiredConfigState, error) {
	proc, client, err := s.datapathProcess()
	var noDatapath *ErrNoDatapathProcess
	if errors.As(err, &noDatapath) {
		return gwstate.DesiredConfigState{}, s.recordDesired(desired)
	}
	if err != nil {
		return gwstate.DesiredConfigState{}, err
	}
	s.mu.Lock()
	proc.desired = desired
	s.mu.Unlock()
	return client.ApplyDesired(ctx, desired)
}

// forwardDesired records the desired document for every parser child that
// reconciles a section of it (the vpn child) and sends it to each one that
// is serving (#557). One that is not serving yet — stopped, backing off or
// mid-launch — is given it by its launch's restore, which waits for the
// apply slot the caller holds. The caller holds the apply slot.
func (s *Supervisor) forwardDesired(ctx context.Context, desired *gwstate.DesiredConfig) error {
	type target struct {
		proc   *supervised
		client *ipc.Client
	}
	var targets []target
	s.mu.Lock()
	s.desired = desired
	for _, proc := range s.processes {
		if proc.def.Class == ClassKernel || !proc.def.ReconcilesDesired {
			continue
		}
		proc.desired = desired
		if proc.launching {
			proc.restoring = true
		}
		if proc.client != nil {
			targets = append(targets, target{proc: proc, client: proc.client})
		}
	}
	s.mu.Unlock()

	var failures []error
	for _, t := range targets {
		if _, err := t.client.ApplyDesired(ctx, desired); err != nil {
			failures = append(failures, &ErrDesiredForwardFailed{
				Process: t.proc.def.Name, Version: desired.EffectiveVersion(), Cause: err})
			continue
		}
		// The child that answered now holds the document restoring stands
		// for. A relaunch past its restore (awaiting readiness) clears
		// restoring no more, so this forward is what clears it; a child
		// relaunched since has another client and keeps its own.
		s.mu.Lock()
		if t.proc.client == t.client && t.proc.desired == desired {
			t.proc.restoring = false
		}
		s.mu.Unlock()
	}
	return errors.Join(failures...)
}

// Snapshot returns the datapath child's telemetry snapshot.
func (s *Supervisor) Snapshot(ctx context.Context) (*gwstate.Snapshot, error) {
	_, client, err := s.datapathProcess()
	if err != nil {
		return nil, err
	}
	return client.Snapshot(ctx)
}

// Shutdown stops every child. After it returns, StartService refuses.
func (s *Supervisor) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	procs := make([]*supervised, 0, len(s.processes))
	for _, proc := range s.processes {
		proc.wanted = map[string]bool{}
		procs = append(procs, proc)
	}
	s.mu.Unlock()

	var failures []error
	for _, proc := range procs {
		if err := s.stopProcess(ctx, proc); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// Supervisor implements the gateway's supervisor seam.
var _ gateway.ServiceSupervisor = (*Supervisor)(nil)
