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

//go:build linux

package process

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// ---------------------------------------------------------------------------
// The class table
// ---------------------------------------------------------------------------

func TestClassTable_EveryGatewayServiceIsPlaced(t *testing.T) {
	// Every service the gateway can enable must have a process, or the
	// supervisor has nowhere to start it and the section fails with
	// ErrServiceUnplaced. The list comes from the gateway's own
	// EnabledServices over a configuration with every section switched on,
	// not from a copy kept here: a hand-written copy is how nat64, which
	// landed after this table, went unplaced (#631 review).
	services := append(everySection(t).EnabledServices(), gateway.ServiceProxy)
	require.Contains(t, services, gateway.ServiceNAT64, "the reflection did not switch every section on")
	for _, service := range services {
		def, err := DefinitionForService(service)
		require.NoErrorf(t, err, "service %q has no process", service)
		assert.NotEmpty(t, def.Name)
	}
	var unplaced *ErrServiceUnplaced
	_, err := DefinitionForService("not-a-service")
	require.ErrorAs(t, err, &unplaced)
}

func TestClassTable_TheTranslatorRunsInTheKernelClass(t *testing.T) {
	// NAT64 programs OVS flows and drives the Jool kernel module, so it
	// needs the datapath process's CAP_NET_ADMIN.
	def, err := DefinitionForService(gateway.ServiceNAT64)
	require.NoError(t, err)
	assert.Equal(t, "datapath", def.Name)
	assert.Equal(t, ClassKernel, def.Class)
}

// everySection returns a gateway configuration with every service section
// switched on. It walks the struct, so a section added to GatewayConfig
// later is switched on here without anyone remembering to: a pointer to a
// section is allocated with its Enabled flag set, and a list section gets
// one entry.
func everySection(t *testing.T) *gateway.GatewayConfig {
	t.Helper()
	cfg := &gateway.GatewayConfig{Enabled: true}
	v := reflect.ValueOf(cfg).Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if !field.CanSet() {
			continue
		}
		switch {
		case field.Kind() == reflect.Pointer && field.Type().Elem().Kind() == reflect.Struct:
			section := reflect.New(field.Type().Elem())
			if enabled := section.Elem().FieldByName("Enabled"); enabled.IsValid() && enabled.Kind() == reflect.Bool {
				enabled.SetBool(true)
			}
			field.Set(section)
		case field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.Struct:
			field.Set(reflect.Append(field, reflect.New(field.Type().Elem()).Elem()))
		}
	}
	return cfg
}

func TestClassTable_OnlyTheKernelClassKeepsNetAdmin(t *testing.T) {
	kernel := 0
	for _, def := range Definitions() {
		holdsNetAdmin := false
		for _, capability := range def.Capabilities {
			if capability == unix.CAP_NET_ADMIN {
				holdsNetAdmin = true
			}
		}
		switch def.Class {
		case ClassKernel:
			kernel++
			assert.Truef(t, holdsNetAdmin, "kernel process %q must keep CAP_NET_ADMIN", def.Name)
			assert.Falsef(t, def.Unprivileged, "kernel process %q programs the kernel and stays root", def.Name)
		case ClassParser:
			assert.Falsef(t, holdsNetAdmin, "parser process %q must not hold CAP_NET_ADMIN", def.Name)
			assert.Truef(t, def.Unprivileged, "parser process %q must drop its uid", def.Name)
		}
		assert.NotZerof(t, def.MemoryMax, "process %q needs a memory limit", def.Name)
		assert.NotEmptyf(t, def.CPUMax, "process %q needs a cpu limit", def.Name)
	}
	assert.Equal(t, 1, kernel, "exactly one process programs the kernel")
}

func TestProcesses_OnlyTheNeededOnesWithOnlyTheEnabledServices(t *testing.T) {
	defs, err := Processes([]string{gateway.ServiceNAT, gateway.ServiceProxy, gateway.ServiceFirewall})
	require.NoError(t, err)
	require.Len(t, defs, 2)
	assert.Equal(t, "datapath", defs[0].Name)
	assert.Equal(t, []string{gateway.ServiceFirewall, gateway.ServiceNAT}, defs[0].Services,
		"the hosted services keep the table's start order, not the caller's")
	assert.Equal(t, "proxy", defs[1].Name)
	assert.Equal(t, []string{gateway.ServiceProxy}, defs[1].Services)

	_, err = Processes([]string{"invented"})
	var unplaced *ErrServiceUnplaced
	require.ErrorAs(t, err, &unplaced)
}

func TestBoundingDrops_KeepsOnlyTheClassCapabilities(t *testing.T) {
	def, err := DefinitionByName("datapath")
	require.NoError(t, err)
	drops := def.BoundingDrops()
	for _, capability := range drops {
		assert.NotEqual(t, uintptr(unix.CAP_NET_ADMIN), capability)
		assert.NotEqual(t, uintptr(unix.CAP_NET_RAW), capability)
	}
	assert.Len(t, drops, int(unix.CAP_LAST_CAP+1)-2)
	assert.Contains(t, drops, uintptr(unix.CAP_SYS_ADMIN))

	_, err = DefinitionByName("nope")
	var unknown *ErrUnknownProcess
	require.ErrorAs(t, err, &unknown)
}

// ---------------------------------------------------------------------------
// A fake launcher whose children are real IPC servers on real sockets
// ---------------------------------------------------------------------------

// fakeNode is a child gateway: its services report what the test scripts.
type fakeNode struct {
	mu       sync.Mutex
	services []gateway.ServiceReport
	applied  *gwstate.DesiredConfig
	state    gwstate.DesiredConfigState
	applyErr error
}

func (f *fakeNode) GetState() gateway.GatewayState { return gateway.GatewayStateRunning }

func (f *fakeNode) ServiceReports() []gateway.ServiceReport {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]gateway.ServiceReport(nil), f.services...)
}

func (f *fakeNode) setHealth(service string, active bool, health error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.services {
		if f.services[i].Name == service {
			f.services[i].Active = active
			f.services[i].Health = health
		}
	}
}

func (f *fakeNode) Snapshot() *gwstate.Snapshot {
	return &gwstate.Snapshot{GatewayID: "child"}
}

func (f *fakeNode) Apply(_ context.Context, desired *gwstate.DesiredConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = desired
	return f.applyErr
}

func (f *fakeNode) DesiredConfigState() gwstate.DesiredConfigState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state
}

// fakeChild is a launched process that serves the real IPC on the spec's
// socket. Exiting is a test action: exit() unblocks Wait the way a crash
// does, and a signal ends it the way a graceful stop does.
type fakeChild struct {
	pid    int
	server *ipc.Server
	node   *fakeNode

	once sync.Once
	done chan struct{}
	err  error

	mu      sync.Mutex
	signals []os.Signal
	// stubborn children ignore SIGTERM, the way a service wedged in a
	// syscall does; only SIGKILL ends them.
	stubborn bool
	// launcher receives this child's events for the ordered log.
	launcher *fakeLauncher
}

func (c *fakeChild) PID() int { return c.pid }

func (c *fakeChild) Wait() error {
	<-c.done
	return c.err
}

func (c *fakeChild) Signal(sig os.Signal) error {
	c.mu.Lock()
	c.signals = append(c.signals, sig)
	ignore := c.stubborn && sig == syscall.SIGTERM
	c.mu.Unlock()
	if c.launcher != nil {
		c.launcher.record("signal:" + sig.String())
	}
	if ignore {
		return nil
	}
	c.exit(nil)
	return nil
}

func (c *fakeChild) signalled() []os.Signal {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]os.Signal(nil), c.signals...)
}

// exit stops the child's server and unblocks Wait, once.
func (c *fakeChild) exit(err error) {
	c.once.Do(func() {
		c.err = err
		c.server.Stop()
		close(c.done)
	})
}

// fakeLauncher launches fakeChild instances and records every launch.
type fakeLauncher struct {
	t *testing.T

	mu       sync.Mutex
	launches []Spec
	children []*fakeChild
	nodes    map[string]*fakeNode
	failWith error
	nextPID  int
	// gate, when set, blocks inside Launch until it is closed, so a test
	// can run a stop while a launch is in flight. launched is closed once
	// Launch has been entered.
	gate     chan struct{}
	launched chan struct{}
	// stubborn makes every child it launches ignore SIGTERM.
	stubborn bool
	// mute makes a child start and never serve the socket the supervisor
	// dialled, the way a child that dies between exec and listen does.
	mute bool
	// events is an ordered log of what the supervisor did to its children,
	// so a test can assert the ORDER of a signal and a cancellation rather
	// than only that both happened.
	events []string
}

func (l *fakeLauncher) record(event string) {
	l.mu.Lock()
	l.events = append(l.events, event)
	l.mu.Unlock()
}

func (l *fakeLauncher) eventLog() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

func newFakeLauncher(t *testing.T) *fakeLauncher {
	return &fakeLauncher{t: t, nodes: map[string]*fakeNode{}, nextPID: 1000}
}

// node returns (creating on first use) the scripted node for a process, so a
// test can set a service unhealthy after the child is up.
func (l *fakeLauncher) node(process string, services []string) *fakeNode {
	l.mu.Lock()
	defer l.mu.Unlock()
	node, ok := l.nodes[process]
	if !ok {
		node = &fakeNode{}
		for _, service := range services {
			node.services = append(node.services, gateway.ServiceReport{Name: service, Active: true})
		}
		l.nodes[process] = node
	}
	return node
}

func (l *fakeLauncher) Launch(ctx context.Context, spec Spec) (Child, error) {
	l.mu.Lock()
	gate, launched := l.gate, l.launched
	l.mu.Unlock()
	if launched != nil {
		close(launched)
	}
	if gate != nil {
		<-gate
	}
	l.mu.Lock()
	l.launches = append(l.launches, spec)
	failure := l.failWith
	l.nextPID++
	pid := l.nextPID
	l.mu.Unlock()
	if failure != nil {
		return nil, &ErrProcessLaunch{Process: spec.Definition.Name, Cause: failure}
	}

	// exec.CommandContext watches the launch context, so the fake watches it
	// too: cancelling it is an action on the child and belongs in the log.
	go func() {
		<-ctx.Done()
		l.record("cancel")
	}()

	node := l.node(spec.Definition.Name, spec.Definition.Services)
	// The supervisor runs as this test process, so the policy that admits
	// it is the one naming this uid.
	uid := uint32(os.Getuid())
	server := ipc.NewServer(node, ipc.Policy{ControlUIDs: []uint32{uid}, DatapathUIDs: []uint32{uid}})
	socket := spec.Socket
	l.mu.Lock()
	mute := l.mute
	l.mu.Unlock()
	if mute {
		// The child is up but nothing is listening where the supervisor
		// dialled. ipc.Dial cannot notice — grpc.NewClient is lazy — so only
		// a readiness check catches it.
		socket = filepath.Join(l.t.TempDir(), "unreachable.sock")
	}
	if err := server.Listen(socket, 0o600, -1); err != nil {
		return nil, err
	}
	l.mu.Lock()
	stubborn := l.stubborn
	l.mu.Unlock()
	child := &fakeChild{pid: pid, server: server, node: node, done: make(chan struct{}), stubborn: stubborn, launcher: l}
	go func() {
		if err := server.Serve(); err != nil {
			l.t.Errorf("child %s serve: %v", spec.Definition.Name, err)
		}
	}()

	l.mu.Lock()
	l.children = append(l.children, child)
	l.mu.Unlock()
	return child, nil
}

func (l *fakeLauncher) launchCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.launches)
}

func (l *fakeLauncher) allChildren() []*fakeChild {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]*fakeChild(nil), l.children...)
}

func (l *fakeLauncher) lastChild() *fakeChild {
	l.mu.Lock()
	defer l.mu.Unlock()
	require.NotEmpty(l.t, l.children)
	return l.children[len(l.children)-1]
}

// testClock is a real-time clock with a recorded history of the delays it
// was asked for, so backoff growth is asserted without waiting for it.
type testClock struct {
	mu     sync.Mutex
	delays []time.Duration
}

func (c *testClock) Now() time.Time { return time.Now() }

func (c *testClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	c.delays = append(c.delays, d)
	c.mu.Unlock()
	// Restart delays are collapsed so the tests do not sleep; the recorded
	// value is what the backoff policy chose.
	return time.After(time.Millisecond)
}

func (c *testClock) restartDelays(minimum time.Duration) []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []time.Duration
	for _, d := range c.delays {
		if d >= minimum {
			out = append(out, d)
		}
	}
	return out
}

// newSupervisor builds a supervisor over the fake launcher with sockets in a
// short-lived directory (Unix socket paths are length-limited).
func newSupervisor(t *testing.T, tune func(*Config)) (*Supervisor, *fakeLauncher, *testClock) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "gwsup")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })

	launcher := newFakeLauncher(t)
	clock := &testClock{}
	cfg := Config{
		Launcher:      launcher,
		RuntimeDir:    dir,
		ConfigFile:    filepath.Join(dir, "config.yaml"),
		SocketGID:     -1,
		Clock:         clock,
		ReadyTimeout:  2 * time.Second,
		StopTimeout:   2 * time.Second,
		RestartWindow: time.Minute,
	}
	if tune != nil {
		tune(&cfg)
	}
	supervisor := New(cfg)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = supervisor.Shutdown(ctx)
	})
	return supervisor, launcher, clock
}

func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// ---------------------------------------------------------------------------
// The supervisor
// ---------------------------------------------------------------------------

func TestStartService_LaunchesTheOwningProcessOncePerProcess(t *testing.T) {
	supervisor, launcher, _ := newSupervisor(t, nil)
	ctx := testContext(t)

	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceFirewall))
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceNAT))
	assert.Equal(t, 1, launcher.launchCount(), "both services live in the datapath process")

	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceTransit))
	assert.Equal(t, 2, launcher.launchCount(), "routing is its own process")

	launched := launcher.launches[0]
	assert.Equal(t, "datapath", launched.Definition.Name)
	assert.Equal(t, uint32(os.Getuid()), launched.SupervisorUID,
		"the child admits the supervisor's own uid, not an assumed root")
	assert.True(t, strings.HasSuffix(launched.Socket, "datapath.sock"))
	assert.Equal(t, -1, launched.CgroupFD, "no cgroup manager means no placement")

	assert.True(t, supervisor.ServiceActive(gateway.ServiceFirewall))
	assert.NoError(t, supervisor.ServiceHealth(gateway.ServiceNAT))
}

func TestStartService_CreatesTheControlSocketDirectory(t *testing.T) {
	supervisor, _, _ := newSupervisor(t, func(c *Config) {
		c.RuntimeDir = filepath.Join(c.RuntimeDir, "run", "gatewayd")
		c.SocketGID = os.Getgid()
	})
	require.NoError(t, supervisor.StartService(testContext(t), gateway.ServiceFirewall))

	info, err := os.Stat(supervisor.cfg.RuntimeDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o770), info.Mode().Perm(),
		"every unprivileged child binds its own socket here AFTER dropping to the service uid, "+
			"so the service group needs write; at 0750 every parser gets EACCES from bind")
	assert.NotZero(t, info.Mode()&os.ModeSticky,
		"the parsers share one account, so the sticky bit is what stops one unlinking another's socket")
	assert.Zero(t, info.Mode().Perm()&0o007, "and nothing else on the host may do anything")

	// An unusable path is a typed error, not a launch that half-happens.
	blocked := &Supervisor{cfg: Config{RuntimeDir: filepath.Join(t.TempDir(), "file", "under", "a", "file")}}
	require.NoError(t, os.WriteFile(filepath.Dir(filepath.Dir(filepath.Dir(blocked.cfg.RuntimeDir))), []byte("x"), 0o600))
	var dirErr *ErrSocketDir
	require.ErrorAs(t, blocked.ensureRuntimeDir(), &dirErr)
}

func TestEnsureRuntimeDir_RepairsADirectoryTheChildrenCouldNotBindIn(t *testing.T) {
	// The packaged init script creates this directory too, and an older one
	// created it 0750. The supervisor brings it to the mode its children
	// actually need instead of launching four parsers that all get EACCES
	// from bind and time out in readiness.
	dir := filepath.Join(t.TempDir(), "run")
	require.NoError(t, os.Mkdir(dir, 0o750))

	supervisor := New(Config{RuntimeDir: dir, SocketGID: -1, Logger: slog.New(slog.DiscardHandler)})
	require.NoError(t, supervisor.ensureRuntimeDir())

	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o770), info.Mode().Perm())
	assert.NotZero(t, info.Mode()&os.ModeSticky)

	// Idempotent: the second call is the common one, and it must not churn.
	require.NoError(t, supervisor.ensureRuntimeDir())
}

func TestBindableByServiceGroup_TheModesAChildCanAndCannotBindIn(t *testing.T) {
	// A directory whose group cannot write is the whole failure: an
	// unprivileged child binds its control socket AFTER dropping to the
	// service uid, and creating an entry needs write on the directory.
	for mode, bindable := range map[os.FileMode]bool{
		0o770: true,
		0o775: true,
		0o750: false, // group r-x but no w: the mode this package shipped with
		0o700: false, // the supervisor's own, which no child shares
		0o707: false, // world-writable is not the service group
	} {
		assert.Equalf(t, bindable, bindableByServiceGroup(mode), "mode %04o", mode)
	}
	assert.True(t, bindableByServiceGroup(os.ModeSticky|os.ModeDir|0o770),
		"the type and sticky bits are not permissions")

	err := &ErrSocketDirNotGroupWritable{Path: "/run/gatewayd", Mode: 0o750}
	assert.Contains(t, err.Error(), "0750")
	assert.Contains(t, err.Error(), "bind its control socket")
}

func TestStartService_RefusesAServiceWithNoProcessClass(t *testing.T) {
	supervisor, launcher, _ := newSupervisor(t, nil)
	var unplaced *ErrServiceUnplaced
	require.ErrorAs(t, supervisor.StartService(testContext(t), "invented"), &unplaced)
	assert.Zero(t, launcher.launchCount())
}

func TestStartService_ReportsALaunchFailure(t *testing.T) {
	supervisor, launcher, _ := newSupervisor(t, nil)
	launcher.failWith = errors.New("permission denied")

	err := supervisor.StartService(testContext(t), gateway.ServiceFirewall)
	var launchErr *ErrProcessLaunch
	require.ErrorAs(t, err, &launchErr)
	assert.Equal(t, "datapath", launchErr.Process)
}

func TestStartService_ReportsAChildThatDidNotActivateTheService(t *testing.T) {
	supervisor, launcher, _ := newSupervisor(t, func(c *Config) { c.ReadyTimeout = 200 * time.Millisecond })
	// The child comes up but its firewall never activates, and it says why.
	node := launcher.node("datapath", nil)
	node.services = []gateway.ServiceReport{
		{Name: gateway.ServiceFirewall, Active: false, Health: errors.New("bridge trusted0 not provisioned")},
	}

	err := supervisor.StartService(testContext(t), gateway.ServiceFirewall)
	var notActive *ErrServiceNotActiveInProcess
	require.ErrorAs(t, err, &notActive)
	assert.Equal(t, gateway.ServiceFirewall, notActive.Service)
	assert.Contains(t, notActive.Detail, "bridge trusted0 not provisioned")

	// A failed start leaves nothing running. The gateway's own rollback
	// unwinds only the handlers it already started, and the one that just
	// failed is not among them, so the supervisor has to stop the child it
	// launched — for the kernel class that child holds CAP_NET_ADMIN.
	child := launcher.lastChild()
	assert.Contains(t, child.signalled(), os.Signal(syscall.SIGTERM),
		"the child launched for a start that failed is stopped")
	supervisor.mu.Lock()
	proc := supervisor.processes["datapath"]
	wanted, live, client := len(proc.wanted), proc.child, proc.client
	supervisor.mu.Unlock()
	assert.Zero(t, wanted, "the service that failed to start is no longer wanted")
	assert.Nil(t, live)
	assert.Nil(t, client)

	launched := launcher.launchCount()
	assert.Never(t, func() bool { return launcher.launchCount() > launched }, 500*time.Millisecond, 50*time.Millisecond,
		"a process nobody wants is not restarted")
}

func TestStartService_AFailedStartLeavesTheProcessAnotherServiceStillWants(t *testing.T) {
	// firewall and nat share the datapath process. nat failing to come up
	// must not take firewall's process down with it.
	supervisor, launcher, _ := newSupervisor(t, func(c *Config) { c.ReadyTimeout = 200 * time.Millisecond })
	node := launcher.node("datapath", nil)
	node.services = []gateway.ServiceReport{
		{Name: gateway.ServiceFirewall, Active: true},
		{Name: gateway.ServiceNAT, Active: false, Health: errors.New("no nat table")},
	}
	ctx := testContext(t)
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceFirewall))

	var notActive *ErrServiceNotActiveInProcess
	require.ErrorAs(t, supervisor.StartService(ctx, gateway.ServiceNAT), &notActive)

	child := launcher.lastChild()
	assert.NotContains(t, child.signalled(), os.Signal(syscall.SIGTERM),
		"the process is still wanted by firewall")
	assert.True(t, supervisor.ServiceActive(gateway.ServiceFirewall))
	supervisor.mu.Lock()
	wanted := len(supervisor.processes["datapath"].wanted)
	supervisor.mu.Unlock()
	assert.Equal(t, 1, wanted, "only the service that failed is released")
}

func TestServiceHealthAndActive_FollowTheChildNotTheParent(t *testing.T) {
	supervisor, launcher, _ := newSupervisor(t, nil)
	ctx := testContext(t)
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceFirewall))

	launcher.node("datapath", nil).setHealth(gateway.ServiceFirewall, false, errors.New("flow install failed"))
	assert.False(t, supervisor.ServiceActive(gateway.ServiceFirewall))
	var notActive *ErrServiceNotActiveInProcess
	require.ErrorAs(t, supervisor.ServiceHealth(gateway.ServiceFirewall), &notActive)
	assert.Contains(t, notActive.Detail, "flow install failed")
}

func TestServiceHealth_ReportsAProcessThatWasNeverStarted(t *testing.T) {
	supervisor, _, _ := newSupervisor(t, nil)
	var down *ErrProcessDown
	require.ErrorAs(t, supervisor.ServiceHealth(gateway.ServiceProxy), &down)
	assert.False(t, supervisor.ServiceActive(gateway.ServiceProxy))
}

func TestStopService_StopsTheProcessOnlyWhenItsLastServiceGoes(t *testing.T) {
	supervisor, launcher, _ := newSupervisor(t, nil)
	ctx := testContext(t)
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceFirewall))
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceNAT))
	child := launcher.lastChild()

	require.NoError(t, supervisor.StopService(ctx, gateway.ServiceFirewall))
	assert.Empty(t, child.signalled(), "the process still hosts nat")
	assert.True(t, supervisor.ServiceActive(gateway.ServiceNAT))

	require.NoError(t, supervisor.StopService(ctx, gateway.ServiceNAT))
	assert.Contains(t, child.signalled(), os.Signal(unix.SIGTERM))
	assert.False(t, supervisor.ServiceActive(gateway.ServiceNAT))

	// Stopping a service of a process that was never started is a no-op,
	// not an error: Gateway.Stop walks every registered handler.
	require.NoError(t, supervisor.StopService(ctx, gateway.ServiceProxy))
}

func TestStopService_KillsAChildThatIgnoresTheGracefulStop(t *testing.T) {
	// A wedged service must not hold the daemon's shutdown open: SIGTERM
	// first, and SIGKILL once StopTimeout has passed.
	supervisor, launcher, _ := newSupervisor(t, func(c *Config) { c.StopTimeout = 50 * time.Millisecond })
	launcher.stubborn = true
	ctx := testContext(t)
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceProxy))

	child := launcher.lastChild()
	require.NoError(t, supervisor.StopService(ctx, gateway.ServiceProxy))
	assert.Equal(t, []os.Signal{syscall.SIGTERM, syscall.SIGKILL}, child.signalled(),
		"the graceful stop is tried first and the kill only after it")
	select {
	case <-child.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the killed child was never reaped")
	}
}

func TestStopService_SignalsBeforeItCancelsTheLaunchContext(t *testing.T) {
	// The launch context is what exec.CommandContext watches, and its default
	// cancellation is Process.Kill. Cancelling before SIGTERM would race an
	// immediate SIGKILL against every production stop and collapse the whole
	// StopTimeout window, so the child would never get to withdraw its flows,
	// tunnels or routes.
	supervisor, launcher, _ := newSupervisor(t, nil)
	ctx := testContext(t)
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceProxy))
	require.NoError(t, supervisor.StopService(ctx, gateway.ServiceProxy))

	require.Eventually(t, func() bool {
		log := launcher.eventLog()
		return slices.Contains(log, "cancel") && slices.Contains(log, "signal:terminated")
	}, 5*time.Second, 20*time.Millisecond, "the child is both signalled and its context released")

	log := launcher.eventLog()
	assert.Less(t, slices.Index(log, "signal:terminated"), slices.Index(log, "cancel"),
		"SIGTERM comes first; the cancel only releases the context once the child is reaped")
	assert.NotContains(t, log, "signal:killed", "a child that stops gracefully is never killed")
}

func TestExecLauncher_CancellingTheContextAsksTheChildToStopRatherThanKillingIt(t *testing.T) {
	// exec.CommandContext's default cancellation is Process.Kill. A gatewayd
	// child holds kernel state it withdraws on SIGTERM, so the launcher
	// overrides that; the trap proves which signal actually arrived.
	launcher := &ExecLauncher{Binary: "/bin/sh"}
	def, err := DefinitionByName("vpn")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	// `service run vpn ...` is the real argument shape, so the script reads
	// its own trap out of band: sh -c runs the string and ignores the rest.
	spec := Spec{Definition: def, Socket: "/tmp/unused.sock", CgroupFD: -1, SocketGID: -1}
	child, err := launcher.Launch(ctx, spec)
	require.NoError(t, err)
	cancel()
	waitErr := child.Wait()

	// /bin/sh with an unknown verb exits on its own; what must NOT appear is
	// a kill. The point of the assertion is the signal, so a child that had
	// already exited is fine and a killed one is not.
	if waitErr != nil {
		assert.NotContains(t, waitErr.Error(), "killed",
			"cancellation asks the child to stop, it does not shoot it")
	}
}

func TestRestart_KeepsTryingWhileTheBudgetHolds(t *testing.T) {
	// A transient launch failure must not end supervision. The watch
	// goroutine that would have tried again has already returned, so a single
	// attempt would leave still-wanted services down for good with the budget
	// untouched.
	supervisor, launcher, _ := newSupervisor(t, func(c *Config) {
		c.RestartBackoff = time.Millisecond
		c.RestartBudget = 10
	})
	ctx := testContext(t)
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceTransit))

	launcher.mu.Lock()
	launcher.failWith = errors.New("fork/exec: resource temporarily unavailable")
	launcher.mu.Unlock()
	launcher.lastChild().exit(errors.New("signal: killed"))

	// The transient failure clears, and the supervisor is still trying.
	require.Eventually(t, func() bool { return launcher.launchCount() >= 3 }, 5*time.Second, 10*time.Millisecond,
		"one failed relaunch does not end supervision")
	launcher.mu.Lock()
	launcher.failWith = nil
	launcher.mu.Unlock()

	assert.Eventually(t, func() bool { return supervisor.ServiceActive(gateway.ServiceTransit) },
		5*time.Second, 20*time.Millisecond, "the service comes back once the launcher recovers")
}

func TestRestart_AFailingLaunchSpendsTheBudgetInsteadOfSpinningForever(t *testing.T) {
	// The retry loop needs the same stop the crash loop has, or a process
	// that can never start retries at the backoff cap forever.
	supervisor, launcher, _ := newSupervisor(t, func(c *Config) {
		c.RestartBackoff = time.Millisecond
		c.RestartBudget = 2
	})
	ctx := testContext(t)
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceTransit))

	launcher.mu.Lock()
	launcher.failWith = errors.New("permission denied")
	launcher.mu.Unlock()
	launcher.lastChild().exit(errors.New("signal: killed"))

	// One launch for the start, then RestartBudget relaunch attempts.
	require.Eventually(t, func() bool { return launcher.launchCount() == 3 }, 5*time.Second, 10*time.Millisecond)
	assert.Never(t, func() bool { return launcher.launchCount() > 3 }, time.Second, 50*time.Millisecond,
		"the budget stops the retry loop the same way it stops the crash loop")

	var exhausted *ErrRestartBudgetExhausted
	require.ErrorAs(t, supervisor.ServiceHealth(gateway.ServiceTransit), &exhausted)
}

func TestRestart_AChildThatNeverServesIsNotAcceptedAsLive(t *testing.T) {
	// ipc.Dial is lazy — grpc.NewClient does not connect — so a relaunched
	// child that never listens would be published as live and its services
	// reported down with no further attempt. Readiness is what catches it.
	supervisor, launcher, _ := newSupervisor(t, func(c *Config) {
		c.RestartBackoff = time.Millisecond
		c.ReadyTimeout = 150 * time.Millisecond
		c.RestartBudget = 2
	})
	ctx := testContext(t)
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceTransit))

	launcher.mu.Lock()
	launcher.mute = true
	launcher.mu.Unlock()
	launcher.lastChild().exit(errors.New("signal: killed"))

	// Every relaunch starts a child that never answers, so each one is a
	// failed restart and the budget ends it.
	require.Eventually(t, func() bool { return launcher.launchCount() == 3 }, 10*time.Second, 20*time.Millisecond,
		"a child that never serves is a failed restart, not a live process")
	var exhausted *ErrRestartBudgetExhausted
	require.Eventually(t, func() bool {
		return errors.As(supervisor.ServiceHealth(gateway.ServiceTransit), &exhausted)
	}, 5*time.Second, 20*time.Millisecond)

	// And nothing was left running: each unserving child was stopped before
	// the next attempt.
	for _, child := range launcher.allChildren()[1:] {
		assert.Contains(t, child.signalled(), os.Signal(syscall.SIGTERM),
			"a child that never served is stopped, not left behind")
	}
}

func TestCrashedProcess_IsRestartedWithGrowingBackoff(t *testing.T) {
	supervisor, launcher, clock := newSupervisor(t, func(c *Config) {
		c.RestartBackoff = 100 * time.Millisecond
		c.RestartBackoffMax = time.Second
	})
	ctx := testContext(t)
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceFirewall))

	for i := 0; i < 2; i++ {
		launcher.lastChild().exit(errors.New("signal: killed"))
		require.Eventually(t, func() bool { return launcher.launchCount() == i+2 }, 20*time.Second, 10*time.Millisecond,
			"the supervisor relaunches a crashed process")
	}
	delays := clock.restartDelays(100 * time.Millisecond)
	require.GreaterOrEqual(t, len(delays), 2)
	assert.Equal(t, 100*time.Millisecond, delays[0])
	assert.Equal(t, 200*time.Millisecond, delays[1], "the backoff doubles")

	// The restarted child serves the same services, so the parent's view
	// recovers on its own.
	require.Eventually(t, func() bool { return supervisor.ServiceActive(gateway.ServiceFirewall) },
		20*time.Second, 10*time.Millisecond)
}

func TestCrashLoop_StopsAtTheRestartBudget(t *testing.T) {
	supervisor, launcher, _ := newSupervisor(t, func(c *Config) {
		c.RestartBackoff = time.Millisecond
		c.RestartBudget = 2
	})
	ctx := testContext(t)
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceTransit))

	// Three crashes against a budget of two: the third exhausts it.
	for i := 0; i < 3; i++ {
		child := launcher.lastChild()
		child.exit(errors.New("signal: killed"))
		if i < 2 {
			require.Eventually(t, func() bool { return launcher.launchCount() == i+2 }, 20*time.Second, 10*time.Millisecond)
		}
	}

	var exhausted *ErrRestartBudgetExhausted
	require.Eventually(t, func() bool {
		return errors.As(supervisor.ServiceHealth(gateway.ServiceTransit), &exhausted)
	}, 20*time.Second, 10*time.Millisecond, "the supervisor gives up and says so")
	assert.Equal(t, "routing", exhausted.Process)
	assert.Contains(t, exhausted.Error(), "restart budget")
	assert.Equal(t, 3, launcher.launchCount(), "no fourth launch after the budget is gone")
}

func TestLongUptime_ClearsTheCrashHistory(t *testing.T) {
	// A process that ran longer than the window before dying is not in a
	// crash loop: its backoff starts over rather than continuing to double.
	clockStub := &steppingClock{now: time.Now()}
	supervisor, launcher, _ := newSupervisor(t, func(c *Config) {
		c.Clock = clockStub
		c.RestartBackoff = 100 * time.Millisecond
		c.RestartWindow = time.Minute
	})
	ctx := testContext(t)
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceFirewall))

	launcher.lastChild().exit(errors.New("signal: killed"))
	require.Eventually(t, func() bool { return launcher.launchCount() == 2 }, 20*time.Second, 10*time.Millisecond)

	// Two hours pass, then the restarted child dies too.
	clockStub.advance(2 * time.Hour)
	launcher.lastChild().exit(errors.New("signal: killed"))
	require.Eventually(t, func() bool { return launcher.launchCount() == 3 }, 20*time.Second, 10*time.Millisecond)

	delays := clockStub.restartDelays(100 * time.Millisecond)
	require.Len(t, delays, 2)
	assert.Equal(t, delays[0], delays[1],
		"a crash after a long healthy run restarts at the first backoff, not a doubled one")
}

func TestApply_GoesToTheDatapathProcess(t *testing.T) {
	supervisor, launcher, _ := newSupervisor(t, nil)
	ctx := testContext(t)

	// With no kernel-class process there is nothing to apply to.
	var noDatapath *ErrNoDatapathProcess
	_, err := supervisor.Apply(ctx, &gwstate.DesiredConfig{GatewayID: "gw"})
	require.ErrorAs(t, err, &noDatapath)
	_, err = supervisor.Snapshot(ctx)
	require.ErrorAs(t, err, &noDatapath)

	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceTransit))
	_, err = supervisor.Apply(ctx, &gwstate.DesiredConfig{GatewayID: "gw"})
	require.ErrorAs(t, err, &noDatapath, "a parser process is not the datapath")

	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceNAT))
	node := launcher.node("datapath", nil)
	node.state = gwstate.DesiredConfigState{Version: "v9"}

	state, err := supervisor.Apply(ctx, &gwstate.DesiredConfig{GatewayID: "gw", Version: "v9"})
	require.NoError(t, err)
	assert.Equal(t, "v9", state.Version)
	node.mu.Lock()
	applied := node.applied
	node.mu.Unlock()
	require.NotNil(t, applied)
	assert.Equal(t, "v9", applied.Version)

	snap, err := supervisor.Snapshot(ctx)
	require.NoError(t, err)
	assert.Equal(t, "child", snap.GatewayID)
}

func TestApply_ReportsTheChildFailureWithItsState(t *testing.T) {
	supervisor, launcher, _ := newSupervisor(t, nil)
	ctx := testContext(t)
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceNAT))
	node := launcher.node("datapath", nil)
	node.applyErr = errors.New("load balancer not enabled")
	node.state = gwstate.DesiredConfigState{Version: "v1", LastError: "load balancer not enabled"}

	state, err := supervisor.Apply(ctx, &gwstate.DesiredConfig{GatewayID: "gw", Version: "v2"})
	var remote *ipc.ErrRemoteApply
	require.ErrorAs(t, err, &remote)
	assert.Equal(t, "v1", state.Version, "the child's state travels with its failure")
}

func TestShutdown_StopsEveryProcessAndRefusesLaterStarts(t *testing.T) {
	supervisor, launcher, _ := newSupervisor(t, nil)
	ctx := testContext(t)
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceFirewall))
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceTransit))

	require.NoError(t, supervisor.Shutdown(ctx))
	for _, child := range launcher.children {
		assert.Contains(t, child.signalled(), os.Signal(unix.SIGTERM))
	}
	require.NoError(t, supervisor.Shutdown(ctx), "shutdown is idempotent")

	var stopped *ErrSupervisorStopped
	require.ErrorAs(t, supervisor.StartService(ctx, gateway.ServiceNAT), &stopped)
}

// ---------------------------------------------------------------------------
// cgroups and settings
// ---------------------------------------------------------------------------

func TestCgroupManager_WritesTheClassLimitsIntoALeaf(t *testing.T) {
	root := t.TempDir()
	manager := &CgroupManager{Root: root, Parent: "gatewayd"}
	def, err := DefinitionByName("proxy")
	require.NoError(t, err)

	leaf, err := manager.Prepare(def)
	require.NoError(t, err)
	require.NotNil(t, leaf)
	t.Cleanup(func() { leaf.Close() })

	path := filepath.Join(root, "gatewayd", "proxy")
	memory, err := os.ReadFile(filepath.Join(path, "memory.max"))
	require.NoError(t, err)
	assert.Equal(t, strconv.FormatInt(def.MemoryMax, 10), string(memory))
	cpu, err := os.ReadFile(filepath.Join(path, "cpu.max"))
	require.NoError(t, err)
	assert.Equal(t, def.CPUMax, string(cpu))

	require.NoError(t, leaf.Close())
	// A real cgroup v2 leaf is removed with rmdir while its interface files
	// are still there — they are kernel-provided, not directory entries. On
	// a plain filesystem they are ordinary files, so the fixture clears them
	// before exercising the removal.
	require.NoError(t, os.Remove(filepath.Join(path, "memory.max")))
	require.NoError(t, os.Remove(filepath.Join(path, "cpu.max")))
	require.NoError(t, manager.Remove("proxy"))
	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err))
	require.NoError(t, manager.Remove("proxy"), "removing an absent leaf is not an error")
}

func TestCgroupManager_DisabledDoesNothing(t *testing.T) {
	var manager *CgroupManager
	assert.False(t, manager.Enabled())
	leaf, err := manager.Prepare(Definition{Name: "datapath"})
	require.NoError(t, err)
	assert.Nil(t, leaf)
	require.NoError(t, manager.Remove("datapath"))
}

func TestCgroupManager_ReportsAnUnwritableTree(t *testing.T) {
	root := t.TempDir()
	blocked := filepath.Join(root, "blocked")
	require.NoError(t, os.WriteFile(blocked, []byte("not a directory"), 0o600))

	manager := &CgroupManager{Root: root, Parent: "blocked"}
	_, err := manager.Prepare(Definition{Name: "datapath", MemoryMax: 1})
	var cgroupErr *ErrCgroup
	require.ErrorAs(t, err, &cgroupErr)
	assert.Equal(t, "create", cgroupErr.Op)
}

func TestSettings_ResolvesTheServiceAccountAndDefaults(t *testing.T) {
	// The current account always exists, so it stands in for the packaged
	// gatewayd account here.
	name := currentUserName(t)

	cfg, err := Settings{Enabled: true, User: name}.Config("/etc/gatewayd/config.yaml", nil)
	require.NoError(t, err)
	assert.Equal(t, DefaultRuntimeDir, cfg.RuntimeDir)
	assert.Equal(t, uint32(os.Getuid()), cfg.UID)
	assert.Equal(t, int(cfg.GID), cfg.SocketGID, "the socket group is the service account's")
	require.NotNil(t, cfg.Cgroups)
	assert.Equal(t, DefaultCgroupParent, cfg.Cgroups.Parent)
	assert.True(t, cfg.Cgroups.Enabled(), "an absent cgroup-parent takes the default")

	// An operator who writes an empty parent means it: no placement, no
	// limits, and the capability separation untouched.
	off := ""
	disabled, err := Settings{Enabled: true, User: name, CgroupParent: &off}.Config("", nil)
	require.NoError(t, err)
	assert.False(t, disabled.Cgroups.Enabled())
	assert.Equal(t, "/etc/gatewayd/config.yaml", cfg.ConfigFile)

	_, err = Settings{Enabled: true, User: "no-such-account-for-tests"}.Config("", nil)
	var unknown *ErrUserUnknown
	require.ErrorAs(t, err, &unknown)

	// An explicit group that does not exist is the same refusal: running a
	// parser under a group nobody defined is not a degraded mode.
	_, err = Settings{Enabled: true, User: name, Group: "no-such-group-for-tests"}.Config("", nil)
	require.ErrorAs(t, err, &unknown)
	assert.Equal(t, "no-such-group-for-tests", unknown.Name)
}

func TestConfig_DefaultsAreTheDocumentedOnes(t *testing.T) {
	// A Config with nothing set is what `process:` produces when an operator
	// turns the model on and tunes nothing, so the timings it runs with are
	// the Default* constants rather than zero — a zero ready timeout would
	// fail every start on the first poll.
	cfg := Config{}.withDefaults()
	assert.Equal(t, DefaultReadyTimeout, cfg.ReadyTimeout)
	assert.Equal(t, DefaultStopTimeout, cfg.StopTimeout)
	assert.Equal(t, DefaultRestartBackoff, cfg.RestartBackoff)
	assert.Equal(t, DefaultRestartBackoffMax, cfg.RestartBackoffMax)
	assert.Equal(t, DefaultRestartBudget, cfg.RestartBudget)
	assert.Equal(t, DefaultRestartWindow, cfg.RestartWindow)
	assert.IsType(t, &ExecLauncher{}, cfg.Launcher, "production launches real children")
	require.NotNil(t, cfg.Logger)
	require.NotNil(t, cfg.Clock)

	assert.WithinDuration(t, time.Now(), cfg.Clock.Now(), time.Minute)
	select {
	case <-cfg.Clock.After(time.Millisecond):
	case <-time.After(5 * time.Second):
		t.Fatal("the system clock never fired")
	}
}

func TestStartService_RefusesARuntimeDirectoryItCannotCreate(t *testing.T) {
	// The control sockets live in runtime-dir. A path that cannot hold them
	// is a refusal before anything is launched, not a child with nowhere to
	// listen.
	file := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	supervisor, launcher, _ := newSupervisor(t, func(c *Config) { c.RuntimeDir = filepath.Join(file, "run") })

	var dirErr *ErrSocketDir
	require.ErrorAs(t, supervisor.StartService(testContext(t), gateway.ServiceFirewall), &dirErr)
	assert.Equal(t, "create", dirErr.Op)
	assert.Zero(t, launcher.launchCount(), "nothing is launched without a socket directory")
}

func TestErrors_Messages(t *testing.T) {
	cases := []struct {
		err      error
		contains string
	}{
		{&ErrServiceUnplaced{Service: "x"}, `service "x" has no process class`},
		{&ErrUnknownProcess{Process: "p"}, `no process named "p"`},
		{&ErrProcessLaunch{Process: "p", Cause: errors.New("boom")}, "launching process"},
		{&ErrProcessUnreachable{Process: "p", Socket: "/s", Waited: time.Second, Cause: errors.New("x")}, "did not answer"},
		{&ErrServiceNotActiveInProcess{Service: "s", Process: "p"}, "did not activate"},
		{&ErrProcessDown{Process: "p", Service: "s"}, "is not running"},
		{&ErrProcessExited{Process: "p", Cause: errors.New("exit status 1")}, `process "p" exited: exit status 1`},
		{&ErrRestartBudgetExhausted{Process: "p", Restarts: 3, Window: time.Minute}, "restart budget"},
		{&ErrNoDatapathProcess{}, "no datapath process"},
		{&ErrSupervisorStopped{}, "stopped"},
		{&ErrCgroup{Path: "/p", Op: "create", Cause: errors.New("x")}, "cgroup create"},
		{&ErrHardening{Step: "drop uid", Cause: errors.New("x")}, "drop uid"},
		{&ErrLaunchAbandoned{Process: "p"}, "was released while it was starting"},
		{&ErrProcessNeverStarted{Process: "p"}, "has not been started"},
		{&ErrSocketDir{Path: "/run/gatewayd", Op: "create", Cause: errors.New("x")}, "control socket directory create"},
		{&ErrUserUnknown{Name: "gatewayd", Cause: errors.New("x")}, "does not exist"},
	}
	for _, c := range cases {
		assert.Contains(t, c.err.Error(), c.contains)
	}
	cause := errors.New("cause")
	for _, err := range []error{
		&ErrProcessLaunch{Cause: cause}, &ErrProcessUnreachable{Cause: cause},
		&ErrProcessDown{Cause: cause}, &ErrProcessExited{Cause: cause}, &ErrRestartBudgetExhausted{Last: cause},
		&ErrCgroup{Cause: cause}, &ErrHardening{Cause: cause}, &ErrUserUnknown{Cause: cause},
		&ErrSocketDir{Cause: cause},
	} {
		assert.ErrorIsf(t, err, cause, "%T must unwrap to its cause", err)
	}
}

// currentUserName is the account this test process runs as.
func currentUserName(t *testing.T) string {
	t.Helper()
	me, err := user.Current()
	require.NoError(t, err)
	return me.Username
}

func TestExecLauncher_PassesTheClassPrivilegeAndTheChildArguments(t *testing.T) {
	// /bin/true stands in for gatewayd: the launch has to be real enough to
	// prove the argument shape and the clone attributes, without running a
	// gateway.
	launcher := &ExecLauncher{Binary: "/bin/true"}
	def, err := DefinitionByName("routing")
	require.NoError(t, err)

	spec := Spec{
		Definition: def,
		Socket:     "/run/gatewayd/routing.sock",
		ConfigFile: "/etc/gatewayd/config.yaml",
		UID:        1001,
		GID:        1001,
		SocketGID:  1001,
		CgroupFD:   -1,
	}
	attr := sysProcAttr(spec)
	assert.Equal(t, []uintptr{unix.CAP_NET_BIND_SERVICE}, attr.AmbientCaps,
		"the class's capabilities are granted at clone time")
	assert.False(t, attr.UseCgroupFD, "a negative descriptor means no cgroup placement")
	assert.Equal(t, syscall.SIGTERM, attr.Pdeathsig,
		"a dead supervisor must not leave orphans behind")

	// Granting an ambient capability needs one to give, so the launch that
	// actually runs uses the class that asks for none. The capability path
	// is asserted above, on the attributes the kernel is handed.
	unprivileged, err := DefinitionByName("vpn")
	require.NoError(t, err)
	plainSpec := spec
	plainSpec.Definition = unprivileged
	child, err := launcher.Launch(context.Background(), plainSpec)
	require.NoError(t, err)
	assert.NotZero(t, child.PID())
	require.NoError(t, child.Wait())

	// A binary that is not there is a launch error naming the process.
	_, err = (&ExecLauncher{Binary: "/nonexistent/gatewayd"}).Launch(context.Background(), plainSpec)
	var launchErr *ErrProcessLaunch
	require.ErrorAs(t, err, &launchErr)
	assert.Equal(t, "vpn", launchErr.Process)
}

// recordingHardenOps records the privilege-dropping syscalls Harden makes
// instead of making them. The drop is irreversible, so recording is the only
// way to assert the ordering the kernel requires without the test binary
// losing its own capabilities for the rest of the run.
type recordingHardenOps struct {
	calls []string
	// bounding are the capabilities dropped from the bounding set.
	bounding []uintptr
	// ambient are the capabilities raised into the ambient set.
	ambient []uintptr
	// sets are the capability sets the class was rewritten to.
	sets [2]unix.CapUserData
	// groups is the supplementary group list the child was left with.
	groups []int
	// uid and gid are what the child dropped to; -1 means it did not.
	uid, gid int
	// ppid is what getppid reports; ppidAfter, when non-zero, is what it
	// reports from the second call on, so a test can put the supervisor's
	// death inside the window where the parent-death signal is disarmed.
	ppid, ppidAfter int
	ppidCalls       int
	// failAt makes the named call return failWith.
	failAt   string
	failWith error
}

func newRecordingHardenOps() *recordingHardenOps {
	return &recordingHardenOps{uid: -1, gid: -1, ppid: 4242}
}

func (o *recordingHardenOps) getppid() int {
	o.ppidCalls++
	if o.ppidCalls > 1 && o.ppidAfter != 0 {
		return o.ppidAfter
	}
	return o.ppid
}

// fail returns the scripted failure when this is the step under test.
func (o *recordingHardenOps) fail(name string) error {
	if o.failAt == name {
		return o.failWith
	}
	return nil
}

// record appends a step to the sequence and applies any scripted failure.
func (o *recordingHardenOps) record(name string) error {
	o.calls = append(o.calls, name)
	return o.fail(name)
}

// prctlName maps a prctl option to the step it performs, so the recorded
// sequence reads as the hardening plan rather than as numbers.
var prctlName = map[uintptr]string{
	unix.PR_SET_NO_NEW_PRIVS: "no_new_privs",
	unix.PR_CAPBSET_DROP:     "capbset_drop",
	unix.PR_SET_KEEPCAPS:     "keepcaps",
	unix.PR_CAP_AMBIENT:      "cap_ambient_raise",
	unix.PR_SET_PDEATHSIG:    "pdeathsig",
}

func (o *recordingHardenOps) prctl(option, arg2, arg3, _, _ uintptr) error {
	name, known := prctlName[option]
	if !known {
		return unix.EINVAL
	}
	switch option {
	case unix.PR_CAPBSET_DROP:
		o.bounding = append(o.bounding, arg2)
		// One call per capability. Recording all forty would bury the
		// ordering, so only the first enters the sequence.
		if len(o.bounding) > 1 {
			return o.fail(name)
		}
	case unix.PR_CAP_AMBIENT:
		o.ambient = append(o.ambient, arg3)
	case unix.PR_SET_KEEPCAPS:
		name = "keepcaps=" + strconv.Itoa(int(arg2))
	}
	return o.record(name)
}

func (o *recordingHardenOps) setgroups(gids []int) error {
	o.groups = append([]int(nil), gids...)
	return o.record("setgroups")
}

func (o *recordingHardenOps) setresgid(rgid, _, _ int) error {
	o.gid = rgid
	return o.record("setresgid")
}

func (o *recordingHardenOps) setresuid(ruid, _, _ int) error {
	o.uid = ruid
	return o.record("setresuid")
}

func (o *recordingHardenOps) capset(_ *unix.CapUserHeader, data *[2]unix.CapUserData) error {
	o.sets = *data
	return o.record("capset")
}

// index returns where a step appears in the recorded sequence, or -1.
func (o *recordingHardenOps) index(call string) int {
	for i, c := range o.calls {
		if c == call {
			return i
		}
	}
	return -1
}

func TestHarden_ReducesTheBoundingSetBeforeTheDropTakesCapSetpcapAway(t *testing.T) {
	// PR_CAPBSET_DROP needs CAP_SETPCAP in the effective set, and a parser
	// class keeps at most CAP_NET_BIND_SERVICE. A bounding reduction placed
	// after the uid drop therefore EPERMs and takes the whole child with it,
	// so every unprivileged process fails to start.
	def, err := DefinitionByName("routing")
	require.NoError(t, err)
	ops := newRecordingHardenOps()
	require.NoError(t, harden(def, 1001, 1002, ops))

	assert.Equal(t, []string{
		"no_new_privs", "capbset_drop", "setgroups", "keepcaps=1",
		"setresgid", "setresuid", "capset", "cap_ambient_raise", "keepcaps=0",
		"pdeathsig",
	}, ops.calls)
	assert.Greater(t, ops.index("pdeathsig"), ops.index("capset"),
		"commit_creds clears pdeath_signal on a credential or capability change, "+
			"so the re-arm has to come after the last of them")
	assert.Less(t, ops.index("capbset_drop"), ops.index("setresuid"),
		"the bounding set is reduced while the child still holds CAP_SETPCAP")
	assert.Less(t, ops.index("keepcaps=1"), ops.index("setresuid"),
		"keepcaps is set before the uid drop or the ambient capabilities go with it")
	assert.Less(t, ops.index("setresgid"), ops.index("setresuid"),
		"the gid drop needs the privilege the uid drop takes away")

	assert.Equal(t, def.BoundingDrops(), ops.bounding)
	assert.NotContains(t, ops.bounding, uintptr(unix.CAP_NET_BIND_SERVICE))
	assert.Equal(t, 1001, ops.uid)
	assert.Equal(t, 1002, ops.gid)
	assert.Equal(t, []uintptr{unix.CAP_NET_BIND_SERVICE}, ops.ambient)

	// The rewritten sets are exactly the class's capability, nothing else.
	assert.Equal(t, uint32(1<<uint(unix.CAP_NET_BIND_SERVICE)), ops.sets[0].Permitted)
	assert.Equal(t, ops.sets[0].Permitted, ops.sets[0].Effective)
	assert.Equal(t, ops.sets[0].Permitted, ops.sets[0].Inheritable)
	assert.Zero(t, ops.sets[1].Permitted)
}

func TestHarden_DropsTheSupervisorsSupplementaryGroups(t *testing.T) {
	// Linux keeps the inherited supplementary list across setresgid and
	// setresuid, so a parser would otherwise keep every extra group the
	// supervisor was in — file and socket access the class never asked for.
	def, err := DefinitionByName("proxy")
	require.NoError(t, err)
	ops := newRecordingHardenOps()
	require.NoError(t, harden(def, 1001, 1002, ops))

	assert.Equal(t, []int{1002}, ops.groups,
		"only the service group survives, and it is the group that owns the control sockets")
	assert.Less(t, ops.index("setgroups"), ops.index("setresuid"),
		"clearing groups needs the privilege the uid drop takes away")
}

func TestHarden_AClassWithNoCapabilitiesKeepsNoPermittedSet(t *testing.T) {
	// keepcaps carried the whole root permitted set across the uid drop. A
	// class that names no capability must still have it taken back, or the
	// VPN parser runs unprivileged while holding a permitted set it can
	// raise into effective whenever it likes.
	def, err := DefinitionByName("vpn")
	require.NoError(t, err)
	require.Empty(t, def.Capabilities)

	ops := newRecordingHardenOps()
	require.NoError(t, harden(def, 1001, 1002, ops))
	assert.Contains(t, ops.calls, "capset")
	assert.Zero(t, ops.sets[0].Permitted)
	assert.Zero(t, ops.sets[0].Effective)
	assert.Zero(t, ops.sets[0].Inheritable)
	assert.Zero(t, ops.sets[1].Permitted)
	assert.Empty(t, ops.ambient, "a class with no capability raises none")
	assert.Len(t, def.BoundingDrops(), int(unix.CAP_LAST_CAP+1),
		"a class with no capabilities drops every one of them")
}

func TestHarden_TheKernelClassStaysRootButKeepsOnlyItsOwnCapabilities(t *testing.T) {
	// The datapath programs the kernel, so it does not drop its uid. That is
	// the only thing it keeps: reducing the bounding set does NOT take a
	// capability out of the permitted or effective set, so without the
	// rewrite this child would still hold every capability root started with
	// — CAP_SYS_ADMIN, CAP_DAC_OVERRIDE, CAP_SYS_MODULE — while the class
	// table says it has two.
	def, err := DefinitionByName("datapath")
	require.NoError(t, err)
	ops := newRecordingHardenOps()
	require.NoError(t, harden(def, 1001, 1002, ops))

	assert.Equal(t, []string{
		"no_new_privs", "capbset_drop", "capset",
		"cap_ambient_raise", "cap_ambient_raise", "pdeathsig",
	}, ops.calls)
	assert.Equal(t, -1, ops.uid, "a kernel-class process does not drop its uid")
	assert.Equal(t, -1, ops.gid)
	assert.NotContains(t, ops.calls, "keepcaps=1", "there is no uid change to carry capabilities across")

	want := uint32(1<<uint(unix.CAP_NET_ADMIN)) | uint32(1<<uint(unix.CAP_NET_RAW))
	assert.Equal(t, want, ops.sets[0].Permitted, "exactly the class's two capabilities, and no others")
	assert.Equal(t, want, ops.sets[0].Effective)
	assert.Zero(t, ops.sets[1].Permitted)
	assert.ElementsMatch(t, []uintptr{unix.CAP_NET_ADMIN, unix.CAP_NET_RAW}, ops.ambient)

	assert.NotContains(t, ops.bounding, uintptr(unix.CAP_NET_ADMIN))
	assert.NotContains(t, ops.bounding, uintptr(unix.CAP_NET_RAW))
	assert.Contains(t, ops.bounding, uintptr(unix.CAP_SYS_MODULE))
}

func TestHarden_RefusesWhenTheSupervisorDiedDuringTheDrop(t *testing.T) {
	// The privilege drop clears the parent-death signal the parent armed at
	// clone time. A supervisor that exits inside that window leaves a child
	// the kernel will never signal, so the child refuses rather than becoming
	// the orphan the signal exists to prevent.
	def, err := DefinitionByName("routing")
	require.NoError(t, err)
	ops := newRecordingHardenOps()
	ops.ppid, ops.ppidAfter = 4242, 1

	err = harden(def, 1001, 1002, ops)
	var hardening *ErrHardening
	require.ErrorAs(t, err, &hardening)
	var gone *ErrSupervisorExited
	require.ErrorAs(t, err, &gone)
	assert.Equal(t, 4242, gone.Parent)
	assert.Equal(t, 1, gone.Now)
	assert.Contains(t, ops.calls, "pdeathsig", "the re-arm is attempted before the check")
}

func TestHarden_ReportsTheStepThatFailed(t *testing.T) {
	def, err := DefinitionByName("routing")
	require.NoError(t, err)
	for _, tc := range []struct {
		call string
		step string
	}{
		{"no_new_privs", "set no_new_privs"},
		{"capbset_drop", "drop bounding capability"},
		{"setgroups", "drop supplementary groups"},
		{"keepcaps=1", "keep capabilities across the uid drop"},
		{"setresgid", "drop gid"},
		{"setresuid", "drop uid"},
		{"capset", "set the class capabilities after the uid drop"},
		{"cap_ambient_raise", "raise ambient capability"},
		{"keepcaps=0", "clear keepcaps"},
	} {
		ops := newRecordingHardenOps()
		ops.failAt, ops.failWith = tc.call, unix.EPERM
		err := harden(def, 1001, 1002, ops)
		var hardening *ErrHardening
		require.ErrorAsf(t, err, &hardening, "failing %s must be fatal", tc.call)
		assert.Equal(t, tc.step, hardening.Step)
		assert.ErrorIs(t, err, unix.EPERM)
	}
}

func TestHarden_ToleratesACapabilityThisKernelDoesNotKnow(t *testing.T) {
	// A capability the running kernel has never heard of is not in its
	// bounding set either, so EINVAL from the drop is the expected answer
	// on an older kernel, not a reason to refuse to start.
	def, err := DefinitionByName("routing")
	require.NoError(t, err)
	ops := newRecordingHardenOps()
	ops.failAt, ops.failWith = "capbset_drop", unix.EINVAL
	require.NoError(t, harden(def, 1001, 1002, ops))

	ops = newRecordingHardenOps()
	ops.failAt, ops.failWith = "capbset_drop", unix.EPERM
	require.Error(t, harden(def, 1001, 1002, ops), "EPERM is a real failure")
}

// steppingClock is a testClock whose Now can be moved forward, so a long
// healthy run is expressed without one.
type steppingClock struct {
	testClock

	mu  sync.Mutex
	now time.Time
}

func (c *steppingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *steppingClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func TestStopDuringACrash_DoesNotLeaveARestartedOrphan(t *testing.T) {
	// The child dies at the moment the last service is released. The
	// supervisor must not restart it into a process nobody is waiting for.
	supervisor, launcher, _ := newSupervisor(t, func(c *Config) { c.RestartBackoff = 50 * time.Millisecond })
	ctx := testContext(t)
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceTransit))

	child := launcher.lastChild()
	child.exit(errors.New("signal: killed"))
	require.NoError(t, supervisor.StopService(ctx, gateway.ServiceTransit))

	launched := launcher.launchCount()
	assert.Never(t, func() bool { return launcher.launchCount() > launched }, time.Second, 50*time.Millisecond,
		"a released process is not relaunched by the crash that raced its stop")
}

func TestStartService_ConcurrentStartsOfOneProcessLaunchItOnce(t *testing.T) {
	// firewall and nat live in the same process. Two callers starting them
	// at once must not both launch it: a second launch would overwrite the
	// child, its client and its done channel, leaving the first child
	// running with nothing watching it and nothing able to stop it — an
	// orphan holding CAP_NET_ADMIN.
	supervisor, launcher, _ := newSupervisor(t, nil)
	ctx := testContext(t)

	services := []string{gateway.ServiceFirewall, gateway.ServiceNAT, gateway.ServiceLoadBalancer, gateway.ServiceHostFW}
	errs := make(chan error, len(services))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, service := range services {
		wg.Add(1)
		go func(service string) {
			defer wg.Done()
			<-start
			errs <- supervisor.StartService(ctx, service)
		}(service)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	assert.Equal(t, 1, launcher.launchCount(), "one process, one launch")
	for _, service := range services {
		assert.Truef(t, supervisor.ServiceActive(service), "%s is active in the one child", service)
	}

	// And the one child is the one the supervisor can still stop: releasing
	// every service leaves nothing running.
	for _, service := range services {
		require.NoError(t, supervisor.StopService(ctx, service))
	}
	assert.Contains(t, launcher.lastChild().signalled(), os.Signal(unix.SIGTERM))
}

func TestApply_RefusesWhenTwoKernelProcessesAreRunning(t *testing.T) {
	// The class table has one kernel-class process today, but it is data,
	// not a type. A second one must be a loud refusal rather than an
	// arbitrary routing decision made by map iteration order.
	supervisor, _, _ := newSupervisor(t, nil)
	ctx := testContext(t)
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceFirewall))

	supervisor.mu.Lock()
	live := supervisor.processes["datapath"]
	second := &supervised{
		def:    Definition{Name: "datapath-2", Class: ClassKernel},
		wanted: map[string]bool{},
		client: live.client,
	}
	supervisor.processes[second.def.Name] = second
	supervisor.mu.Unlock()

	_, err := supervisor.Apply(ctx, &gwstate.DesiredConfig{GatewayID: "gw"})
	var ambiguous *ErrAmbiguousDatapath
	require.ErrorAs(t, err, &ambiguous)
	assert.Equal(t, []string{"datapath", "datapath-2"}, ambiguous.Processes, "named in a stable order")
	assert.Contains(t, ambiguous.Error(), "no single owner")

	_, err = supervisor.Snapshot(ctx)
	require.ErrorAs(t, err, &ambiguous, "the snapshot walks the same set")
}

func TestStopService_CleansUpAProcessThatAlreadyExited(t *testing.T) {
	// A child whose restart budget ran out leaves no child to signal. The
	// rest of the teardown still has to happen: the cgroup leaf outlives
	// the child that was born into it, and a leaked leaf is host-visible
	// state that accumulates over stop/start cycles.
	root := t.TempDir()
	supervisor, launcher, _ := newSupervisor(t, func(c *Config) {
		c.Cgroups = &CgroupManager{Root: root, Parent: "gatewayd"}
		c.RestartBackoff = time.Millisecond
		c.RestartBudget = 1
	})
	ctx := testContext(t)
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceTransit))

	leaf := filepath.Join(root, "gatewayd", "routing")
	_, err := os.Stat(leaf)
	require.NoError(t, err, "the leaf exists while the process runs")

	// Crash past the budget: the supervisor gives up and no child remains.
	for i := 0; i < 2; i++ {
		launcher.lastChild().exit(errors.New("signal: killed"))
		if i == 0 {
			require.Eventually(t, func() bool { return launcher.launchCount() == 2 }, 20*time.Second, 10*time.Millisecond)
		}
	}
	var exhausted *ErrRestartBudgetExhausted
	require.Eventually(t, func() bool {
		return errors.As(supervisor.ServiceHealth(gateway.ServiceTransit), &exhausted)
	}, 20*time.Second, 10*time.Millisecond)

	// The interface files are the fixture's, not the kernel's, so clear them
	// the way TestCgroupManager does before asserting the rmdir.
	for _, name := range []string{"memory.max", "cpu.max"} {
		if err := os.Remove(filepath.Join(leaf, name)); err != nil && !os.IsNotExist(err) {
			t.Fatalf("clear %s: %v", name, err)
		}
	}
	require.NoError(t, supervisor.StopService(ctx, gateway.ServiceTransit))

	_, err = os.Stat(leaf)
	assert.True(t, os.IsNotExist(err), "the cgroup leaf is removed even with no child to signal")

	// The crash history goes with it: a later start is not judged by the
	// budget the previous run exhausted.
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceTransit))
	assert.NoError(t, supervisor.ServiceHealth(gateway.ServiceTransit))
}

func TestServiceHealth_ANeverStartedProcessIsNotAStoppedSupervisor(t *testing.T) {
	supervisor, _, _ := newSupervisor(t, nil)

	var down *ErrProcessDown
	err := supervisor.ServiceHealth(gateway.ServiceProxy)
	require.ErrorAs(t, err, &down)
	var never *ErrProcessNeverStarted
	require.ErrorAs(t, err, &never, "a process nobody started is not a shutdown")
	assert.Equal(t, "proxy", never.Process)

	// After Shutdown the cause is the shutdown, which is a different thing
	// for an operator reading a health report.
	require.NoError(t, supervisor.Shutdown(testContext(t)))
	var stopped *ErrSupervisorStopped
	require.ErrorAs(t, supervisor.StartService(testContext(t), gateway.ServiceProxy), &stopped)
}

func TestLaunchRacingAStop_StopsTheChildInsteadOfPublishingIt(t *testing.T) {
	// The launch runs unlocked, because it execs. A stop that releases the
	// process's last service while a child is starting finds no child to
	// signal — this one is not published yet — tears the process down and
	// returns success. Publishing afterwards would leave a live child, with
	// a watch goroutine, for a service nobody wants; for the kernel class
	// that child holds CAP_NET_ADMIN.
	supervisor, launcher, _ := newSupervisor(t, nil)
	ctx := testContext(t)

	launcher.mu.Lock()
	launcher.gate = make(chan struct{})
	launcher.launched = make(chan struct{})
	gate, launched := launcher.gate, launcher.launched
	launcher.mu.Unlock()

	startErr := make(chan error, 1)
	go func() { startErr <- supervisor.StartService(ctx, gateway.ServiceFirewall) }()

	// The launch is in flight and holding the gate.
	select {
	case <-launched:
	case <-time.After(20 * time.Second):
		t.Fatal("the launcher was never entered")
	}
	require.NoError(t, supervisor.StopService(ctx, gateway.ServiceFirewall))
	close(gate)

	var abandoned *ErrLaunchAbandoned
	select {
	case err := <-startErr:
		require.ErrorAs(t, err, &abandoned, "a start that loses to a stop is a failed start")
		assert.Equal(t, "datapath", abandoned.Process)
	case <-time.After(20 * time.Second):
		t.Fatal("StartService never returned")
	}

	// The child the launcher handed back was stopped, not published: the
	// supervisor holds nothing for the process and the child got its signal.
	assert.False(t, supervisor.ServiceActive(gateway.ServiceFirewall))
	supervisor.mu.Lock()
	proc := supervisor.processes["datapath"]
	child, client := proc.child, proc.client
	supervisor.mu.Unlock()
	assert.Nil(t, child, "no child is published for a released process")
	assert.Nil(t, client)
	assert.Contains(t, launcher.lastChild().signalled(), os.Signal(unix.SIGTERM))
}
