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
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Spec is one child launch: which process definition, where its control
// socket goes, and what the supervisor prepared for it.
type Spec struct {
	// Definition is the process being launched.
	Definition Definition
	// Socket is the control socket path the child must listen on.
	Socket string
	// Inherited is the part of the supervisor's own command line the child
	// is started with, so it resolves the same configuration and state.
	Inherited Inherited
	// UID and GID are the credentials an unprivileged child drops to.
	UID, GID uint32
	// SocketGID, when non-negative, owns the child's control socket so a
	// parser process can reach the datapath process's surface.
	SocketGID int
	// SupervisorUID is the uid the child admits on its control service. It
	// is passed explicitly rather than assumed to be root, so a supervisor
	// run by a developer can still talk to its own children.
	SupervisorUID uint32
	// CgroupFD, when non-negative, is an open cgroup v2 leaf directory the
	// kernel places the child in at clone time (clone3 CLONE_INTO_CGROUP),
	// so the child is never accounted outside its own limits.
	CgroupFD int
}

// Inherited holds the gatewayd root flags a child is started with. A child
// is a fresh gatewayd invocation that resolves these the way the supervisor
// did, so anything the supervisor was given on its command line and not
// passed on here silently falls back to the flag default in the child.
type Inherited struct {
	// ConfigFile is the gatewayd config the child reads. It reads the same
	// file the supervisor did: a process hosts a subset of the services,
	// not a subset of the configuration.
	ConfigFile string
	// DataDir is the gatewayd state directory (--data-dir). The proxy's
	// TOFU pin store lives under it, so a child resolving the default
	// instead would open a different store and trust peers afresh.
	DataDir string
	// LogFormat and Debug select the child's log handler and level, so
	// every process of one gatewayd logs the same way.
	LogFormat string
	Debug     bool
}

// args returns the root flags that carry the inherited settings. An empty
// value is left out, so the child applies the same default the supervisor
// did.
func (in Inherited) args() []string {
	var args []string
	if in.ConfigFile != "" {
		args = append(args, "--config", in.ConfigFile)
	}
	if in.DataDir != "" {
		args = append(args, "--data-dir", in.DataDir)
	}
	if in.LogFormat != "" {
		args = append(args, "--log-format", in.LogFormat)
	}
	if in.Debug {
		args = append(args, "--debug")
	}
	return args
}

// Args returns the child's command line after the executable: the fixed
// `service run` verb, the per-process control arguments, then the root
// flags the child inherits from the supervisor.
func (spec Spec) Args() []string {
	args := []string{
		"service", "run", spec.Definition.Name,
		"--ipc-socket", spec.Socket,
		"--socket-group", strconv.Itoa(spec.SocketGID),
		"--supervisor-uid", strconv.FormatUint(uint64(spec.SupervisorUID), 10),
		"--uid", strconv.FormatUint(uint64(spec.UID), 10),
		"--gid", strconv.FormatUint(uint64(spec.GID), 10),
	}
	return append(args, spec.Inherited.args()...)
}

// Child is a launched process the supervisor watches.
type Child interface {
	// PID is the child's process id.
	PID() int
	// Wait blocks until the child exits and returns its exit error, nil on
	// a clean exit.
	Wait() error
	// Signal sends a signal to the child.
	Signal(sig os.Signal) error
}

// Launcher starts child processes. The exec launcher is production; tests
// substitute one that runs the child in-process.
type Launcher interface {
	Launch(ctx context.Context, spec Spec) (Child, error)
}

// ExecLauncher runs `gatewayd service run <process>` as a real child of this
// process, with the class's privilege drop applied on both sides of the exec:
// the ambient capability set and the cgroup here, the bounding set,
// no_new_privs and the uid drop in the child before it opens anything.
type ExecLauncher struct {
	// Binary is the gatewayd executable; empty means this process's own
	// executable, which is what keeps the attestation surface singular.
	Binary string
	// Env is the child environment; nil means this process's environment.
	Env []string
	// Stdout and Stderr receive the child's output; nil means this
	// process's own, so OpenRC's log redirection covers every child.
	Stdout, Stderr *os.File
}

// binary resolves the executable to launch.
func (l *ExecLauncher) binary() (string, error) {
	if l.Binary != "" {
		return l.Binary, nil
	}
	return os.Executable()
}

// Launch implements Launcher.
func (l *ExecLauncher) Launch(ctx context.Context, spec Spec) (Child, error) {
	binary, err := l.binary()
	if err != nil {
		return nil, &ErrProcessLaunch{Process: spec.Definition.Name, Cause: err}
	}
	args := spec.Args()
	// The binary is this process's own executable unless a deployment names
	// another; the arguments are a fixed verb plus paths from the daemon's
	// own configuration. Nothing here comes from the network.
	cmd := exec.CommandContext(ctx, binary, args...) // #nosec G204 -- gatewayd re-executes itself with a fixed argument shape
	cmd.Env = l.Env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if l.Stdout != nil {
		cmd.Stdout = l.Stdout
	}
	if l.Stderr != nil {
		cmd.Stderr = l.Stderr
	}
	cmd.SysProcAttr = sysProcAttr(spec)
	// exec.CommandContext's default cancellation is Process.Kill. A child of
	// this supervisor holds kernel state — flows, nftables rules, XFRM
	// policy, WireGuard links — that it withdraws on SIGTERM, so a context
	// cancellation asks it to stop rather than shooting it. Escalating to
	// SIGKILL is the supervisor's job, bounded by StopTimeout; doing it here
	// would take that window away from every cancellation path.
	cmd.Cancel = func() error {
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		return nil
	}
	if err := cmd.Start(); err != nil {
		return nil, &ErrProcessLaunch{Process: spec.Definition.Name, Cause: err}
	}
	return &execChild{cmd: cmd}, nil
}

// parentDeathSignal is what the kernel sends a child when its supervisor
// dies. It is SIGKILL, not SIGTERM: a child that is terminated runs its
// stop path, and the datapath's stop path withdraws every flow, route and
// rule it installed, so a supervisor crash would take the forwarding plane
// down with it. A killed child leaves its kernel state where it is; the
// successor supervisor's datapath adopts it through the cookie-scoped
// reconcile, and BGP peers see a dropped session rather than a Cease, so
// graceful restart keeps their routes. A planned stop still signals SIGTERM.
const parentDeathSignal = syscall.SIGKILL

// sysProcAttr builds the child's clone attributes: the ambient capability
// set the class keeps, the cgroup leaf to be born into, and the parent-death
// signal so a supervisor that dies never leaves orphaned children running.
func sysProcAttr(spec Spec) *syscall.SysProcAttr {
	attr := &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: parentDeathSignal,
	}
	if len(spec.Definition.Capabilities) > 0 {
		attr.AmbientCaps = append([]uintptr(nil), spec.Definition.Capabilities...)
	}
	if spec.CgroupFD >= 0 {
		attr.UseCgroupFD = true
		attr.CgroupFD = spec.CgroupFD
	}
	return attr
}

// execChild adapts exec.Cmd to Child.
type execChild struct {
	cmd *exec.Cmd
}

func (c *execChild) PID() int { return c.cmd.Process.Pid }

func (c *execChild) Wait() error { return c.cmd.Wait() }

func (c *execChild) Signal(sig os.Signal) error { return c.cmd.Process.Signal(sig) }

// hardenOps are the privilege-dropping syscalls Harden makes. Dropping
// privilege is irreversible, so this is the seam a unit test uses to assert
// the order the kernel requires without the test binary permanently losing
// its own capabilities. Production always runs kernelHardenOps.
type hardenOps interface {
	prctl(option, arg2, arg3, arg4, arg5 uintptr) error
	setgroups(gids []int) error
	setresgid(rgid, egid, sgid int) error
	setresuid(ruid, euid, suid int) error
	capset(header *unix.CapUserHeader, data *[2]unix.CapUserData) error
	seccomp(filter []unix.SockFilter) error
	getppid() int
}

// kernelHardenOps makes the real syscalls.
type kernelHardenOps struct{}

func (kernelHardenOps) prctl(option, arg2, arg3, arg4, arg5 uintptr) error {
	return unix.Prctl(int(option), arg2, arg3, arg4, arg5)
}

// setgroups uses the standard library rather than x/sys: the standard
// library applies the change to every thread of the process, and a
// per-thread group list would leave the goroutines already parked on other
// threads holding the supervisor's groups.
func (kernelHardenOps) setgroups(gids []int) error { return syscall.Setgroups(gids) }

func (kernelHardenOps) setresgid(rgid, egid, sgid int) error {
	return unix.Setresgid(rgid, egid, sgid)
}

func (kernelHardenOps) setresuid(ruid, euid, suid int) error {
	return unix.Setresuid(ruid, euid, suid)
}

func (kernelHardenOps) capset(header *unix.CapUserHeader, data *[2]unix.CapUserData) error {
	return unix.Capset(header, &data[0])
}

// seccomp installs filter on every thread of the process at once
// (SECCOMP_FILTER_FLAG_TSYNC). A filter on the calling thread alone would
// leave the threads the Go runtime already started unconfined, the #657
// problem again. On a synchronisation failure the kernel returns the id of
// the thread it could not move and installs the filter on none.
func (kernelHardenOps) seccomp(filter []unix.SockFilter) error {
	if len(filter) == 0 || len(filter) > unix.BPF_MAXINSNS {
		return unix.EINVAL
	}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	thread, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(filter)
	if errno != 0 {
		return errno
	}
	if thread != 0 {
		return &ErrSeccompThreadNotSynced{Thread: int(thread)}
	}
	return nil
}

func (kernelHardenOps) getppid() int { return os.Getppid() }

// harden applies the child-side half of the privilege drop.
//
// The order is the one the kernel requires, and every step exists:
//
//  1. no_new_privs, so nothing this process later execs can regain privilege.
//  2. the bounding set reduced to the class's capabilities, so nothing the
//     class does not name can ever be acquired again. It happens here,
//     before the uid drop, because PR_CAPBSET_DROP needs CAP_SETPCAP in the
//     effective set and the drop below leaves a parser without it — a
//     bounding reduction attempted afterwards fails with EPERM and takes the
//     whole child down with it.
//  3. for an unprivileged class only: the supplementary groups reduced to the
//     service group (Linux keeps the inherited list across the uid and gid
//     change), PR_SET_KEEPCAPS so the uid change does not clear the permitted
//     set and with it the ambient capabilities the parent granted, then the
//     gid and the uid, gid first because dropping the uid first would take
//     away the privilege needed to drop the gid.
//  4. the capability sets rewritten to exactly the class's capabilities —
//     permitted, effective and inheritable — and those raised back into the
//     ambient set. This runs for BOTH classes. Reducing the bounding set does
//     not take a capability out of the permitted or effective set, so a
//     kernel-class child that skipped this step would keep every capability
//     root started with, CAP_SYS_ADMIN and CAP_DAC_OVERRIDE included, and the
//     class table's promise that everything else is dropped would hold only
//     for what it could acquire later, not for what it already had. For an
//     unprivileged class this is also what takes back the root permitted set
//     that PR_SET_KEEPCAPS deliberately carried across the uid drop.
//  5. the parent-death signal re-armed. commit_creds() clears a task's
//     pdeath_signal whenever its euid, egid or capability set changes, so
//     every step above that drops privilege also disarms the Pdeathsig the
//     parent set at clone time. Re-arming it is what keeps the guarantee that
//     a dead supervisor never leaves a child programming the kernel. The
//     re-arm is unconditional: on a kernel where a given step did not clear
//     it, setting it again is a no-op.
//
// A failure at any step is fatal to the child: running with more privilege
// than the class allows is the thing this model exists to prevent.
//
// Every step changes the calling thread only; EnterHardened is what turns
// the one hardened thread into a hardened process.
func harden(def Definition, uid, gid uint32, ops hardenOps) error {
	// Read before anything drops privilege, so the re-arm below can tell
	// whether the supervisor died inside the window where nothing was armed.
	parent := ops.getppid()

	if err := ops.prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return &ErrHardening{Step: "set no_new_privs", Cause: err}
	}
	if err := dropBoundingSet(def, ops); err != nil {
		return err
	}
	if def.Unprivileged {
		if err := dropCredentials(uid, gid, ops); err != nil {
			return err
		}
	}
	if err := setCapabilities(def.Capabilities, ops); err != nil {
		return err
	}
	if def.Unprivileged {
		if err := ops.prctl(unix.PR_SET_KEEPCAPS, 0, 0, 0, 0); err != nil {
			return &ErrHardening{Step: "clear keepcaps", Cause: err}
		}
	}
	return rearmParentDeath(parent, ops)
}

// dropCredentials takes the child to the service account: its supplementary
// groups, then its gid, then its uid, with the permitted set held across the
// change so the class's capabilities survive it.
func dropCredentials(uid, gid uint32, ops hardenOps) error {
	if err := ops.setgroups([]int{int(gid)}); err != nil {
		return &ErrHardening{Step: "drop supplementary groups", Cause: err}
	}
	if err := ops.prctl(unix.PR_SET_KEEPCAPS, 1, 0, 0, 0); err != nil {
		return &ErrHardening{Step: "keep capabilities across the uid drop", Cause: err}
	}
	if err := ops.setresgid(int(gid), int(gid), int(gid)); err != nil {
		return &ErrHardening{Step: "drop gid", Cause: err}
	}
	if err := ops.setresuid(int(uid), int(uid), int(uid)); err != nil {
		return &ErrHardening{Step: "drop uid", Cause: err}
	}
	return nil
}

// rearmParentDeath re-arms the parent-death signal the privilege drop cleared
// and refuses to continue if the supervisor died while it was disarmed.
func rearmParentDeath(parent int, ops hardenOps) error {
	if err := ops.prctl(unix.PR_SET_PDEATHSIG, uintptr(parentDeathSignal), 0, 0, 0); err != nil {
		return &ErrHardening{Step: "re-arm the parent-death signal", Cause: err}
	}
	// Between the credential change that disarmed the signal and the re-arm
	// above, the supervisor may have exited: the kernel had nothing to
	// deliver, so the child would keep running with no supervisor. A changed
	// parent is exactly that window, and the child refuses rather than
	// becoming the orphan the signal exists to prevent.
	if now := ops.getppid(); now != parent {
		return &ErrHardening{
			Step:  "re-arm the parent-death signal",
			Cause: &ErrSupervisorExited{Parent: parent, Now: now},
		}
	}
	return nil
}

// dropBoundingSet reduces the capability bounding set to the class's own
// capabilities. It must run while the caller still holds CAP_SETPCAP.
func dropBoundingSet(def Definition, ops hardenOps) error {
	for _, capability := range def.BoundingDrops() {
		if err := ops.prctl(unix.PR_CAPBSET_DROP, capability, 0, 0, 0); err != nil {
			// A capability this kernel does not know is not in the bounding
			// set either; anything else is a real failure.
			if errors.Is(err, unix.EINVAL) {
				continue
			}
			return &ErrHardening{Step: "drop bounding capability", Cause: err}
		}
	}
	return nil
}

// setCapabilities rewrites the permitted, effective and inheritable sets to
// exactly the class's capabilities, then raises those into the ambient set so
// they survive the next exec.
//
// It runs even for a class that names no capability: PR_SET_KEEPCAPS carried
// the whole root permitted set across the uid drop, and only this rewrite
// takes back what the class does not name. Skipping it would leave an
// unprivileged parser holding a permitted set it could raise into effective
// at will.
func setCapabilities(capabilities []uintptr, ops hardenOps) error {
	mask := capabilityMask(capabilities)
	low, high := uint32(mask), uint32(mask>>32)
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	data := [2]unix.CapUserData{
		{Effective: low, Permitted: low, Inheritable: low},
		{Effective: high, Permitted: high, Inheritable: high},
	}
	if err := ops.capset(&header, &data); err != nil {
		return &ErrHardening{Step: "set the class capabilities after the uid drop", Cause: err}
	}
	for _, capability := range capabilities {
		if err := ops.prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, capability, 0, 0); err != nil {
			return &ErrHardening{Step: "raise ambient capability", Cause: err}
		}
	}
	return nil
}
