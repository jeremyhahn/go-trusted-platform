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
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
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
}

// New builds a supervisor. Nothing is launched until StartService.
func New(cfg Config) *Supervisor {
	return &Supervisor{
		cfg:       cfg.withDefaults(),
		processes: make(map[string]*supervised),
		applying:  make(chan struct{}, 1),
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
	proc.wanted[service] = true
	proc.stopping = false
	// Claim the launch, or leave it to whoever holds the claim. A caller
	// that does not launch still waits for the service below: the readiness
	// poll already tolerates a process mid-launch, so it is the natural
	// second caller.
	claimed := proc.child == nil && !proc.launching
	if claimed {
		proc.launching = true
		// A process started again after a stop, or while its restart is
		// backing off, still has its predecessor's desired document; the
		// parent's version check will not send it again (#557).
		proc.restoring = proc.desired != nil
	}
	s.mu.Unlock()

	if claimed {
		err := s.launch(ctx, proc)
		launched := err == nil
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
		s.mu.Unlock()
		if err != nil {
			s.releaseFailedStart(ctx, proc, service)
			return err
		}
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
	s.removeCgroup(proc)
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
const runtimeDirMode = os.ModeSticky | 0o770

// ensureRuntimeDir makes the control-socket directory exist, owned by the
// service account's group and writable by it. The packaged init script creates
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
	// MkdirAll leaves an existing directory's mode alone, and the packaged
	// init script may have created it, so the mode is set rather than
	// assumed.
	if err := os.Chmod(dir, runtimeDirMode); err != nil {
		s.cfg.Logger.Warn("gatewayd supervisor: setting the control-socket directory mode",
			slog.String("path", dir), slog.Any("error", err))
	}
	if s.cfg.SocketGID >= 0 {
		if err := os.Chown(dir, -1, s.cfg.SocketGID); err != nil {
			// A supervisor without the privilege to chown is a developer
			// run, not a fleet one; the sockets it creates are its own.
			s.cfg.Logger.Warn("gatewayd supervisor: setting the control-socket directory group",
				slog.String("path", dir), slog.Any("error", err))
		}
	}
	// Verify rather than hope. A directory the children cannot write is a
	// refusal now, naming the directory, instead of four readiness timeouts
	// that name the children.
	info, err := os.Stat(dir)
	if err != nil {
		return &ErrSocketDir{Path: dir, Op: "stat", Cause: err}
	}
	if !bindableByServiceGroup(info.Mode()) {
		return &ErrSocketDir{
			Path: dir, Op: "secure",
			Cause: &ErrSocketDirNotGroupWritable{Path: dir, Mode: info.Mode().Perm()},
		}
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

// launch starts the child and its watch goroutine.
func (s *Supervisor) launch(ctx context.Context, proc *supervised) error {
	if err := s.ensureRuntimeDir(); err != nil {
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
	proc.cancel = cancel
	proc.startedAt = s.cfg.Clock.Now()
	proc.failure = nil
	proc.done = make(chan struct{})
	done := proc.done
	s.mu.Unlock()

	go s.watch(runCtx, proc, child, done)

	s.cfg.Logger.Info("gatewayd supervisor: process started",
		slog.String("process", proc.def.Name),
		slog.String("class", string(proc.def.Class)),
		slog.Int("pid", child.PID()))
	return nil
}

// awaitService polls the child's control socket until the service reports
// active, the readiness deadline passes, or the child dies.
func (s *Supervisor) awaitService(ctx context.Context, proc *supervised, service string) error {
	deadline := s.cfg.Clock.Now().Add(s.cfg.ReadyTimeout)
	var lastErr error
	var detail string
	for {
		s.mu.Lock()
		client, failure, restoring := proc.client, proc.failure, proc.restoring
		s.mu.Unlock()
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
		case <-s.cfg.Clock.After(readyPollInterval):
		}
	}
}

// readyPollInterval is how often a starting child is asked whether its
// services are up.
const readyPollInterval = 25 * time.Millisecond

// watch waits for the child to exit and restarts it while the parent still
// wants services from it and its restart budget holds.
func (s *Supervisor) watch(ctx context.Context, proc *supervised, child Child, done chan struct{}) {
	defer close(done)

	waitErr := child.Wait()

	s.mu.Lock()
	// A stop cancelled the context: the exit is expected and the process
	// stays down.
	if ctx.Err() != nil || s.stopped || len(proc.wanted) == 0 {
		proc.child = nil
		s.closeClientLocked(proc)
		s.mu.Unlock()
		return
	}
	proc.child = nil
	s.closeClientLocked(proc)
	s.mu.Unlock()

	s.restartLoop(ctx, proc, &ErrProcessExited{Process: proc.def.Name, Cause: waitErr}, waitErr)
}

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
func (s *Supervisor) restartLoop(ctx context.Context, proc *supervised, failure error, cause error) {
	for {
		backoff, over := s.noteRestart(proc, failure, cause)
		if over {
			return
		}
		s.cfg.Logger.Warn("gatewayd supervisor: process down, restarting",
			slog.String("process", proc.def.Name),
			slog.Duration("backoff", backoff),
			slog.Any("error", cause))

		select {
		case <-ctx.Done():
			return
		case <-s.cfg.Clock.After(backoff):
		}

		s.mu.Lock()
		stillWanted := !s.stopped && !proc.stopping && len(proc.wanted) > 0 && proc.child == nil && !proc.launching
		if stillWanted {
			proc.launching = true
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
		proc.launching = false
		proc.restoring = false
		s.mu.Unlock()
		if err == nil {
			return
		}
		s.cfg.Logger.Error("gatewayd supervisor: restart failed",
			slog.String("process", proc.def.Name), slog.Any("error", err))
		failure, cause = err, err
	}
}

// noteRestart records one restart against the budget and returns the backoff
// to wait before the next attempt. It reports over when the budget is spent,
// having left the exhaustion in the process's failure for the health report.
func (s *Supervisor) noteRestart(proc *supervised, failure error, cause error) (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

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
		return 0, true
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
	return proc.backoff, false
}

// awaitProcess waits for a freshly launched child to answer on its control
// socket. It asks only that the child is serving; which of its services came
// up is the caller's question in StartService, and the health report's
// afterwards.
func (s *Supervisor) awaitProcess(ctx context.Context, proc *supervised) error {
	deadline := s.cfg.Clock.Now().Add(s.cfg.ReadyTimeout)
	var lastErr error
	for {
		s.mu.Lock()
		client, failure := proc.client, proc.failure
		s.mu.Unlock()
		if failure != nil {
			return &ErrProcessDown{Process: proc.def.Name, Cause: failure}
		}
		if client != nil {
			if _, err := client.Status(ctx); err == nil {
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
	child, cancel, done := proc.child, proc.cancel, proc.done
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
		return
	}
	if err := s.terminate(context.WithoutCancel(ctx), proc.def.Name, child, done); err != nil {
		s.cfg.Logger.Error("gatewayd supervisor: stopping a child that never served",
			slog.String("process", proc.def.Name), slog.Any("error", err))
	}
	s.mu.Lock()
	proc.child = nil
	s.closeClientLocked(proc)
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
		s.removeCgroup(proc)
		return nil
	}
	if err := s.terminate(ctx, proc.def.Name, child, done); err != nil {
		return err
	}
	if cancel != nil {
		cancel()
	}

	s.clearProcessState(proc)
	s.removeCgroup(proc)
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
}

// removeCgroup deletes the process's cgroup leaf. A leaf that cannot be
// removed is logged rather than retried: it means something is still in it,
// which the stop above was supposed to have ended.
func (s *Supervisor) removeCgroup(proc *supervised) {
	// Nil-safe for the same reason as Prepare in launch.
	if err := s.cfg.Cgroups.Remove(proc.def.Name); err != nil {
		s.cfg.Logger.Warn("gatewayd supervisor: removing cgroup leaf",
			slog.String("process", proc.def.Name), slog.Any("error", err))
	}
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
// owns every service that reconciles a desired document.
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

// kernelProcessLocked returns the one kernel-class process the supervisor
// knows, only among those with a child serving when serving is set. The
// caller holds s.mu.
func (s *Supervisor) kernelProcessLocked(serving bool) (*supervised, error) {
	var datapath *supervised
	var names []string
	for _, proc := range s.processes {
		if proc.def.Class != ClassKernel || (serving && proc.client == nil) {
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
// the kernel-class process, which owns every service that reconciles it.
// The process keeps the document, so a child relaunched after a crash is
// given it again (restoreDesired); the send holds the apply slot so that
// re-send can never land after it with an older document.
func (s *Supervisor) Apply(ctx context.Context, desired *gwstate.DesiredConfig) (gwstate.DesiredConfigState, error) {
	if err := s.acquireApply(ctx); err != nil {
		return gwstate.DesiredConfigState{}, err
	}
	defer s.releaseApply()

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
