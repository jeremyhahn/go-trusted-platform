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
	"fmt"
	"os"
	"strings"
	"time"
)

// ErrServiceUnplaced reports a gateway service with no process in the class
// table. The supervisor refuses rather than inventing a placement.
type ErrServiceUnplaced struct {
	Service string
}

func (e *ErrServiceUnplaced) Error() string {
	return fmt.Sprintf("gatewayd supervisor: service %q has no process class", e.Service)
}

// ErrUnknownProcess reports a process name that is not in the class table.
type ErrUnknownProcess struct {
	Process string
}

func (e *ErrUnknownProcess) Error() string {
	return fmt.Sprintf("gatewayd supervisor: no process named %q", e.Process)
}

// ErrProcessLaunch reports a child that could not be started.
type ErrProcessLaunch struct {
	Process string
	Cause   error
}

func (e *ErrProcessLaunch) Error() string {
	return fmt.Sprintf("gatewayd supervisor: launching process %q: %v", e.Process, e.Cause)
}

func (e *ErrProcessLaunch) Unwrap() error { return e.Cause }

// ErrProcessUnreachable reports a child that started but whose control
// socket never answered within the readiness deadline.
type ErrProcessUnreachable struct {
	Process string
	Socket  string
	Waited  time.Duration
	Cause   error
}

func (e *ErrProcessUnreachable) Error() string {
	return fmt.Sprintf("gatewayd supervisor: process %q did not answer on %s within %s: %v",
		e.Process, e.Socket, e.Waited, e.Cause)
}

func (e *ErrProcessUnreachable) Unwrap() error { return e.Cause }

// ErrServiceNotActiveInProcess reports a child that came up without the
// service the supervisor asked it for. Detail carries the child's own start
// error or health text when it reported one.
type ErrServiceNotActiveInProcess struct {
	Service string
	Process string
	Detail  string
}

func (e *ErrServiceNotActiveInProcess) Error() string {
	msg := fmt.Sprintf("gatewayd supervisor: process %q did not activate service %q", e.Process, e.Service)
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// ErrProcessDown reports a service whose owning process is not running.
type ErrProcessDown struct {
	Process string
	Service string
	Cause   error
}

func (e *ErrProcessDown) Error() string {
	msg := fmt.Sprintf("gatewayd supervisor: process %q hosting service %q is not running", e.Process, e.Service)
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e *ErrProcessDown) Unwrap() error { return e.Cause }

// ErrProcessExited reports the exit of a child the supervisor still wants.
// It is the cause carried inside ErrProcessDown, so a service-level error
// reads as "service X's process exited" once rather than naming the process
// twice.
type ErrProcessExited struct {
	Process string
	Cause   error
}

func (e *ErrProcessExited) Error() string {
	msg := fmt.Sprintf("process %q exited", e.Process)
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e *ErrProcessExited) Unwrap() error { return e.Cause }

// ErrRestartBudgetExhausted reports a process that crashed more times than
// its budget allows inside the window. The supervisor stops restarting it and
// the services it hosted stay unhealthy, which is louder and safer at an
// internet edge than an endless crash loop.
type ErrRestartBudgetExhausted struct {
	Process  string
	Restarts int
	Window   time.Duration
	Last     error
}

func (e *ErrRestartBudgetExhausted) Error() string {
	msg := fmt.Sprintf("gatewayd supervisor: process %q exhausted its restart budget (%d restarts in %s)",
		e.Process, e.Restarts, e.Window)
	if e.Last != nil {
		msg += "; last exit: " + e.Last.Error()
	}
	return msg
}

func (e *ErrRestartBudgetExhausted) Unwrap() error { return e.Last }

// ErrNoDatapathProcess reports an Apply with no kernel-class process running
// to apply it.
type ErrNoDatapathProcess struct{}

func (e *ErrNoDatapathProcess) Error() string {
	return "gatewayd supervisor: no datapath process is running to apply the desired configuration"
}

// ErrAmbiguousDatapath reports more than one kernel-class process running at
// once. The desired configuration goes to the process that owns the datapath,
// and with two of them there is no such process — routing to either would be
// an arbitrary choice made silently.
type ErrAmbiguousDatapath struct {
	Processes []string
}

func (e *ErrAmbiguousDatapath) Error() string {
	return fmt.Sprintf("gatewayd supervisor: %d kernel-class processes are running (%s); the desired configuration has no single owner",
		len(e.Processes), strings.Join(e.Processes, ", "))
}

// ErrLaunchAbandoned reports a launch that finished after the process it was
// for had been released. The child is stopped and reaped rather than
// published: a start that lost to a stop is a failed start, not a running
// process nobody asked for.
type ErrLaunchAbandoned struct {
	Process string
}

func (e *ErrLaunchAbandoned) Error() string {
	return fmt.Sprintf("gatewayd supervisor: process %q was released while it was starting; the child was stopped", e.Process)
}

// ErrProcessNeverStarted reports a service whose process has not been
// started. It is distinct from ErrSupervisorStopped: an operator reading a
// health report needs to know the difference between "not started yet" and
// "the supervisor has shut down".
type ErrProcessNeverStarted struct {
	Process string
}

func (e *ErrProcessNeverStarted) Error() string {
	return fmt.Sprintf("gatewayd supervisor: process %q has not been started", e.Process)
}

// ErrSupervisorStopped reports a call made after Shutdown.
type ErrSupervisorStopped struct{}

func (e *ErrSupervisorStopped) Error() string {
	return "gatewayd supervisor: stopped"
}

// ErrCgroup reports a cgroup v2 leaf the supervisor could not create or
// configure.
type ErrCgroup struct {
	Path  string
	Op    string
	Cause error
}

func (e *ErrCgroup) Error() string {
	return fmt.Sprintf("gatewayd supervisor: cgroup %s %q: %v", e.Op, e.Path, e.Cause)
}

func (e *ErrCgroup) Unwrap() error { return e.Cause }

// ErrHardening reports a child-side privilege drop that failed. The child
// exits on it: running with more privilege than its class allows is not a
// degraded mode, it is the thing the model exists to prevent.
type ErrHardening struct {
	Step  string
	Cause error
}

func (e *ErrHardening) Error() string {
	return fmt.Sprintf("gatewayd service: %s: %v", e.Step, e.Cause)
}

func (e *ErrHardening) Unwrap() error { return e.Cause }

// ErrSocketDirNotGroupWritable reports a control-socket directory the
// unprivileged children could not bind in. Every parser class creates its own
// socket after dropping to the service uid, so a directory its group cannot
// write is four readiness timeouts waiting to happen.
type ErrSocketDirNotGroupWritable struct {
	Path string
	Mode os.FileMode
}

func (e *ErrSocketDirNotGroupWritable) Error() string {
	return fmt.Sprintf("mode %04o denies the service group the write permission every unprivileged child needs to bind its control socket", e.Mode)
}

// ErrSupervisorExited reports a child that lost its supervisor during the
// privilege drop, in the window where the parent-death signal was disarmed by
// the credential change and not yet re-armed. The child exits on it: a child
// with no supervisor is the orphan the signal exists to prevent.
type ErrSupervisorExited struct {
	// Parent is the supervisor's pid as the child saw it before the drop.
	Parent int
	// Now is the pid the child was reparented to.
	Now int
}

func (e *ErrSupervisorExited) Error() string {
	return fmt.Sprintf("gatewayd service: the supervisor (pid %d) exited during the privilege drop; reparented to pid %d", e.Parent, e.Now)
}

// ErrPrivilegeNotHeld is a re-executed child whose credentials do not match
// its class: a thread kept a capability, a uid or a group the class does not
// allow, or no_new_privs is unset. The child refuses to start rather than
// run with more privilege than the class table gives it.
type ErrPrivilegeNotHeld struct {
	// Task is the thread id the mismatch was read from.
	Task string
	// Field is the /proc status field, e.g. "CapEff" or "Uid".
	Field string
	// Want and Got are the expected and the observed value.
	Want, Got string
}

func (e *ErrPrivilegeNotHeld) Error() string {
	return fmt.Sprintf("gatewayd service: thread %s: %s is %q, the class requires %q", e.Task, e.Field, e.Got, e.Want)
}

// ErrSocketDir reports a control-socket directory the supervisor could not
// create or secure.
type ErrSocketDir struct {
	Path  string
	Op    string
	Cause error
}

func (e *ErrSocketDir) Error() string {
	return fmt.Sprintf("gatewayd supervisor: control socket directory %s %q: %v", e.Op, e.Path, e.Cause)
}

func (e *ErrSocketDir) Unwrap() error { return e.Cause }
