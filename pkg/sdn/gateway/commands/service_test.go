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

package commands

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/process"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/proxysvc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

func TestLoadServeConfig_ProcessSection(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader(
		"process:\n  enabled: true\n  user: gatewayd\n  ready-timeout: 5s\n  cgroup-parent: \"\"\n")))

	cfg, err := LoadServeConfig(v)
	require.NoError(t, err)
	require.NotNil(t, cfg.Process)
	assert.True(t, cfg.Process.Enabled)
	assert.Equal(t, "gatewayd", cfg.Process.User)
	assert.Equal(t, 5*time.Second, cfg.Process.ReadyTimeout)
	require.NotNil(t, cfg.Process.CgroupParent, "an explicit empty cgroup-parent is kept")
	assert.Empty(t, *cfg.Process.CgroupParent)
}

func TestLoadServeConfig_ProcessSectionDecodeError(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("process:\n  enabled: maybe\n")))

	_, err := LoadServeConfig(v)
	var section *ErrConfigSection
	require.ErrorAs(t, err, &section)
	assert.Equal(t, "process", section.Section)
}

// supervisorSettings enables the process model as the user running the test,
// without cgroup placement, so building the supervisor touches nothing.
func supervisorSettings(t *testing.T) *process.Settings {
	t.Helper()
	current, err := user.Current()
	require.NoError(t, err)
	noCgroups := ""
	return &process.Settings{Enabled: true, User: current.Username, CgroupParent: &noCgroups}
}

func TestBuildSupervisor_AttachesTheSupervisorToTheGateway(t *testing.T) {
	cfg := &ServeConfig{Gateway: &gateway.GatewayConfig{Enabled: true}, Process: supervisorSettings(t)}

	supervisor, err := BuildSupervisor(cfg, process.Inherited{ConfigFile: "/etc/gatewayd/config.yaml"}, testLogger())
	require.NoError(t, err)
	require.NotNil(t, supervisor)
	assert.True(t, cfg.Gateway.Supervisor == gateway.ServiceSupervisor(supervisor),
		"BuildGateway must see the supervisor it will hand services to")
	assert.True(t, cfg.Gateway.Supervisor.Supervises(gateway.ServiceTransit))
	assert.True(t, cfg.Gateway.Supervisor.Supervises(gateway.ServiceProxy))
}

func TestBuildSupervisor_NothingToSupervise(t *testing.T) {
	tests := map[string]*ServeConfig{
		"no process section": {Gateway: &gateway.GatewayConfig{Enabled: true}},
		"process model disabled": {
			Gateway: &gateway.GatewayConfig{Enabled: true},
			Process: &process.Settings{Enabled: false},
		},
		"no gateway section": {Process: &process.Settings{Enabled: true}},
	}
	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			supervisor, err := BuildSupervisor(cfg, process.Inherited{ConfigFile: "$!1"}, testLogger())
			require.NoError(t, err)
			assert.Nil(t, supervisor)
			if cfg.Gateway != nil {
				assert.Nil(t, cfg.Gateway.Supervisor, "every service stays in this process")
			}
		})
	}
}

func TestBuildSupervisor_Errors(t *testing.T) {
	t.Run("no configuration", func(t *testing.T) {
		_, err := BuildSupervisor(nil, process.Inherited{}, testLogger())
		require.ErrorIs(t, err, ErrConfigLoadFailed)
	})
	t.Run("an unknown service account", func(t *testing.T) {
		settings := supervisorSettings(t)
		settings.User = "gatewayd-no-such-account-557"
		cfg := &ServeConfig{Gateway: &gateway.GatewayConfig{Enabled: true}, Process: settings}

		_, err := BuildSupervisor(cfg, process.Inherited{ConfigFile: "$!1"}, testLogger())
		var section *ErrConfigSection
		require.ErrorAs(t, err, &section)
		assert.Equal(t, "process", section.Section)
		var unknown *process.ErrUserUnknown
		require.ErrorAs(t, err, &unknown)
		assert.Nil(t, cfg.Gateway.Supervisor, "a supervisor that failed to build is not attached")
	})
}

// parseChildCommandLine parses a supervised child's argv the way gatewayd's
// root command does, so the test reads the configuration the child would
// resolve. The flags are global, so they are put back afterwards.
func parseChildCommandLine(t *testing.T, args []string) *viper.Viper {
	t.Helper()
	cmd, rest, err := rootCmd.Find(args)
	require.NoError(t, err)
	require.Equal(t, serviceRunCmd, cmd, "the child runs `service run`")
	t.Cleanup(func() {
		cmd.Flags().VisitAll(func(f *pflag.Flag) {
			if err := f.Value.Set(f.DefValue); err != nil {
				t.Errorf("reset --%s: %v", f.Name, err)
			}
			f.Changed = false
		})
	})
	require.NoError(t, cmd.ParseFlags(rest))
	return viper.GetViper()
}

func TestChildInheritance_TheProxyChildOpensTheSupervisorsPinStore(t *testing.T) {
	// A supervisor run with a custom --data-dir captured a TOFU pin. Its
	// proxy child must resolve the same directory and read that pin, not
	// fall back to /var/lib/gatewayd and trust the peer afresh.
	dataDir := t.TempDir()
	parentStore, err := newGatewayTOFUPinStore(dataDir)
	require.NoError(t, err)
	pin := &trust.TOFUPin{
		Host:       "bmc.example",
		Port:       443,
		SPKISHA256: strings.Repeat("ab", 32),
		FirstSeen:  time.Now().UTC(),
		Source:     "tofu",
	}
	require.NoError(t, parentStore.Put(context.Background(), pin))

	def, err := process.DefinitionByName("proxy")
	require.NoError(t, err)
	spec := process.Spec{
		Definition: def,
		Socket:     filepath.Join(t.TempDir(), "proxy.sock"),
		SocketGID:  -1,
		Inherited:  childInheritance(&ServeConfig{DataDir: dataDir}, ""),
	}

	cfg, err := LoadServeConfig(parseChildCommandLine(t, spec.Args()))
	require.NoError(t, err)
	assert.Equal(t, dataDir, cfg.DataDir, "the child resolves the supervisor's state directory")

	childStore, err := newGatewayTOFUPinStore(cfg.DataDir)
	require.NoError(t, err)
	got, err := childStore.Get(context.Background(), pin.Host, pin.Port)
	require.NoError(t, err, "the child reads the pin the supervisor captured")
	assert.Equal(t, pin.SPKISHA256, got.SPKISHA256)
}

func TestChildInheritance_AnUnsetStateDirectoryKeepsTheDefault(t *testing.T) {
	// Nothing to inherit is not an empty flag: the child resolves the same
	// default the supervisor did, and the log settings still travel.
	origFormat, origDebug := logFormat, debugMode
	t.Cleanup(func() { logFormat, debugMode = origFormat, origDebug })
	logFormat, debugMode = "text", true

	inherited := childInheritance(&ServeConfig{}, "")
	assert.Equal(t, process.Inherited{LogFormat: "text", Debug: true}, inherited)

	def, err := process.DefinitionByName("proxy")
	require.NoError(t, err)
	args := process.Spec{Definition: def, Socket: "/s", SocketGID: -1, Inherited: inherited}.Args()
	assert.NotContains(t, args, "--data-dir")
	cfg, err := LoadServeConfig(parseChildCommandLine(t, args))
	require.NoError(t, err)
	assert.Equal(t, "/var/lib/gatewayd", cfg.DataDir)
}

type fakeShutdowner struct {
	err         error
	hadDeadline bool
}

func (f *fakeShutdowner) Shutdown(ctx context.Context) error {
	_, f.hadDeadline = ctx.Deadline()
	return f.err
}

func TestShutdownSupervisor_StopsTheChildrenWithinTheShutdownTimeout(t *testing.T) {
	var logged bytes.Buffer
	supervisor := &fakeShutdowner{}

	shutdownSupervisor(supervisor, slog.New(slog.NewTextHandler(&logged, nil)))

	assert.True(t, supervisor.hadDeadline, "a hung child must not hold the daemon's exit forever")
	assert.Empty(t, logged.String())
}

func TestShutdownSupervisor_LogsAFailure(t *testing.T) {
	var logged bytes.Buffer
	supervisor := &fakeShutdowner{err: context.DeadlineExceeded}

	shutdownSupervisor(supervisor, slog.New(slog.NewTextHandler(&logged, nil)))

	assert.Contains(t, logged.String(), "Process supervisor shutdown failed")
	assert.Contains(t, logged.String(), context.DeadlineExceeded.Error())
}

func TestServicePolicy_OnlyTheDatapathProcessAdmitsTheServiceAccount(t *testing.T) {
	opts := serviceOptions{supervisorUID: 0, uid: 1001, gid: 1001}
	routing, err := process.DefinitionByName("routing")
	require.NoError(t, err)
	datapath, err := process.DefinitionByName("datapath")
	require.NoError(t, err)

	parser := servicePolicy(routing, opts, nil)
	assert.Equal(t, []uint32{0}, parser.ControlUIDs)
	assert.Empty(t, parser.DatapathUIDs, "one parser must not reach another parser's surface")

	kernel := servicePolicy(datapath, opts, nil)
	assert.Equal(t, []uint32{0}, kernel.ControlUIDs)
	assert.Equal(t, []uint32{1001}, kernel.DatapathUIDs)
	assert.Empty(t, kernel.PlatformUIDs)
}

func TestServicePolicy_OnlyTheDatapathProcessAdmitsPlatformd(t *testing.T) {
	opts := serviceOptions{supervisorUID: 0, uid: 1001, gid: 1001}
	settings := &process.Settings{PlatformUIDs: []uint32{2002}}
	routing, err := process.DefinitionByName("routing")
	require.NoError(t, err)
	datapath, err := process.DefinitionByName("datapath")
	require.NoError(t, err)

	assert.Empty(t, servicePolicy(routing, opts, settings).PlatformUIDs,
		"a parser hosts no live service platformd reads")
	assert.Equal(t, []uint32{2002}, servicePolicy(datapath, opts, settings).PlatformUIDs)
}

// constructOnlyOVS satisfies the runtime OVS client for a test that only
// constructs the perf service; any call on it panics.
type constructOnlyOVS struct{ ovs.ClientInterface }

func TestDatapathServices_TheDatapathChildServesTheGatewayAndPerf(t *testing.T) {
	datapath, err := process.DefinitionByName("datapath")
	require.NoError(t, err)
	gw, err := gateway.NewGateway(&gateway.GatewayConfig{Enabled: true, ID: "gw-test",
		Runtime: &gateway.GatewayRuntime{OVS: constructOnlyOVS{}, Bridge: "br-test"}})
	require.NoError(t, err)

	services, err := datapathServices(datapath, gw)
	require.NoError(t, err)
	assert.Same(t, gw, services.LoadBalancer)
	assert.Same(t, gw, services.NAT64)
	assert.NotNil(t, services.Perf, "a runtime OVS client must give the child its perf service")
}

func TestDatapathServices_NoRuntimeOVSServesNoPerf(t *testing.T) {
	datapath, err := process.DefinitionByName("datapath")
	require.NoError(t, err)
	gw, err := gateway.NewGateway(&gateway.GatewayConfig{Enabled: true, ID: "gw-test", Runtime: &gateway.GatewayRuntime{}})
	require.NoError(t, err)

	services, err := datapathServices(datapath, gw)
	require.NoError(t, err)
	assert.Same(t, gw, services.LoadBalancer)
	assert.Nil(t, services.Perf, "perf without an OVS client must refuse, not panic")
}

func TestDatapathServices_AParserServesNothing(t *testing.T) {
	routing, err := process.DefinitionByName("routing")
	require.NoError(t, err)
	gw, err := gateway.NewGateway(&gateway.GatewayConfig{Enabled: true, ID: "gw-test"})
	require.NoError(t, err)

	services, err := datapathServices(routing, gw)
	require.NoError(t, err)
	assert.Equal(t, ipc.Services{}, services)
}

func TestCloseGatewayRuntime_NoRuntimeIsANoOp(t *testing.T) {
	var logged bytes.Buffer
	gw, err := gateway.NewGateway(&gateway.GatewayConfig{Enabled: true, ID: "gw-test"})
	require.NoError(t, err)

	closeGatewayRuntime(gw, slog.New(slog.NewTextHandler(&logged, nil)))

	assert.Empty(t, logged.String())
}

func TestCloseGatewayRuntime_ARuntimeWithoutOVSClosesCleanly(t *testing.T) {
	var logged bytes.Buffer
	gw, err := gateway.NewGateway(&gateway.GatewayConfig{Enabled: true, ID: "gw-test", Runtime: &gateway.GatewayRuntime{}})
	require.NoError(t, err)

	closeGatewayRuntime(gw, slog.New(slog.NewTextHandler(&logged, nil)))

	assert.Empty(t, logged.String())
}

// fakeServiceHandler stands in for the service a supervised process hosts.
type fakeServiceHandler struct {
	name     string
	startErr error
	active   atomic.Bool
	stopped  atomic.Bool
}

func (h *fakeServiceHandler) Name() string { return h.name }

func (h *fakeServiceHandler) Start(context.Context) error {
	if h.startErr != nil {
		return h.startErr
	}
	h.active.Store(true)
	return nil
}

func (h *fakeServiceHandler) Stop(context.Context) error {
	h.active.Store(false)
	h.stopped.Store(true)
	return nil
}

func (h *fakeServiceHandler) IsActive() bool { return h.active.Load() }

func (h *fakeServiceHandler) Health() error { return nil }

// serviceRun records what serveProcess handed its collaborators.
type serviceRun struct {
	hardened    []process.Definition
	built       *ServeConfig
	handler     *fakeServiceHandler
	readErr     error
	loadErr     error
	buildErr    error
	hardenErr   error
	loaded      *ServeConfig
	readCalls   int
	hardenedUID uint32
	hardenedGID uint32
	// leaseGateways are the gateways the vpn lease record was asked for.
	leaseGateways []*gateway.Gateway
	leaseErr      error
	// gatewayConfig, when set, is the gateway built in place of the one
	// hosting the fake handler, given the services serveProcess chose.
	gatewayConfig *gateway.GatewayConfig
	// leaseControl and journal, when set, are the lease record handed out.
	leaseControl gateway.VPNLeaseControl
	journal      *gateway.RevocationJournal
}

func newServiceRun() *serviceRun {
	return &serviceRun{
		handler: &fakeServiceHandler{name: gateway.ServiceTransit},
		loaded: &ServeConfig{Gateway: &gateway.GatewayConfig{
			Enabled: true,
			Transit: &gateway.TransitServiceConfig{Enabled: true},
			DHCP:    &gateway.DHCPServiceConfig{Enabled: true},
		}},
	}
}

func (r *serviceRun) deps() serviceDeps {
	return serviceDeps{
		enterHardened: func(def process.Definition, uid, gid uint32) error {
			r.hardened = append(r.hardened, def)
			r.hardenedUID, r.hardenedGID = uid, gid
			return r.hardenErr
		},
		readConfig: func() error {
			r.readCalls++
			return r.readErr
		},
		loadConfig: func() (*ServeConfig, error) { return r.loaded, r.loadErr },
		buildGateway: func(_ context.Context, cfg *ServeConfig, _ *slog.Logger) (*gateway.Gateway, error) {
			r.built = cfg
			if r.buildErr != nil {
				return nil, r.buildErr
			}
			gwCfg := &gateway.GatewayConfig{Enabled: true, ID: "gw-test"}
			if r.gatewayConfig != nil {
				gwCfg = r.gatewayConfig
				gwCfg.HostedServices = cfg.Gateway.HostedServices
			}
			gw, err := gateway.NewGateway(gwCfg)
			if err != nil {
				return nil, err
			}
			// Admit the node at its own minimums, as BuildGateway does.
			gwCfg = gw.GetConfig()
			gw.SetNodeMetrics(gwCfg.MinReputation, time.Duration(gwCfg.MinAgeDays)*24*time.Hour, gwCfg.MinUptimePct)
			if r.gatewayConfig != nil {
				return gw, nil
			}
			if err := gw.RegisterServiceHandler(r.handler); err != nil {
				return nil, err
			}
			return gw, nil
		},
		vpnLeaseControl: func(_ context.Context, _ *ServeConfig, gw *gateway.Gateway, _ *slog.Logger) (gateway.VPNLeaseControl, *gateway.RevocationJournal, error) {
			r.leaseGateways = append(r.leaseGateways, gw)
			if r.leaseErr != nil {
				return nil, nil, r.leaseErr
			}
			if r.leaseControl != nil {
				return r.leaseControl, r.journal, nil
			}
			return fakeLeaseControl{}, nil, nil
		},
	}
}

// fakeLeaseControl stands in for the control plane's lease record; serveProcess
// only hands it to the gateway, so none of its methods is called.
type fakeLeaseControl struct{ gateway.VPNLeaseControl }

// newVPNServiceRun is a run whose configuration enables the management VPN,
// hosted by the vpn process.
func newVPNServiceRun() *serviceRun {
	run := newServiceRun()
	run.handler = &fakeServiceHandler{name: gateway.ServiceManagementVPN}
	run.loaded.Gateway.ManagementVPN = &gateway.ManagementVPNServiceConfig{Enabled: true}
	return run
}

// serviceTestOptions puts the control socket in a test directory and admits
// the test's own uid as the supervisor.
func serviceTestOptions(t *testing.T) serviceOptions {
	t.Helper()
	return serviceOptions{
		socket:        filepath.Join(t.TempDir(), "routing.sock"),
		socketGroup:   -1,
		supervisorUID: uint32(os.Getuid()),
		uid:           4242,
		gid:           4343,
	}
}

// startServiceProcess runs serveProcess until the returned cancel is called.
func startServiceProcess(t *testing.T, name string, run *serviceRun, opts serviceOptions) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveProcess(ctx, name, opts, run.deps(), testLogger()) }()
	t.Cleanup(cancel)
	return cancel, done
}

// processStatus asks the child's control service for its status, as the
// supervisor does.
func processStatus(t *testing.T, socket string) (startError string, active map[string]bool, ok bool) {
	t.Helper()
	client, err := ipc.Dial(socket)
	if err != nil {
		return "", nil, false
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	status, err := client.Status(ctx)
	if err != nil {
		return "", nil, false
	}
	active = map[string]bool{}
	for _, svc := range status.GetServices() {
		active[svc.GetName()] = svc.GetActive()
	}
	return status.GetStartError(), active, true
}

func TestServeProcess_HostsItsOwnServicesAndServesTheSupervisor(t *testing.T) {
	run := newServiceRun()
	opts := serviceTestOptions(t)

	cancel, done := startServiceProcess(t, "routing", run, opts)
	require.Eventually(t, func() bool {
		_, active, ok := processStatus(t, opts.socket)
		return ok && active[gateway.ServiceTransit]
	}, 5*time.Second, 10*time.Millisecond, "the supervisor must see the hosted service active")

	cancel()
	require.NoError(t, <-done)
	assert.True(t, run.handler.stopped.Load(), "a stopping child stops its services")

	require.Len(t, run.hardened, 1)
	assert.Equal(t, "routing", run.hardened[0].Name)
	assert.Equal(t, uint32(4242), run.hardenedUID)
	assert.Equal(t, uint32(4343), run.hardenedGID)
	assert.Equal(t, 1, run.readCalls, "the configuration is read after the drop")
	assert.Equal(t, []string{gateway.ServiceTransit}, run.built.Gateway.HostedServices,
		"DHCP is enabled but belongs to another process")
	assert.Nil(t, run.built.Gateway.Supervisor)
	assert.Empty(t, run.leaseGateways, "only the process hosting the VPN builds its lease record")
}

func TestServeProcess_TheVPNProcessWiresItsLeaseRecord(t *testing.T) {
	run := newVPNServiceRun()
	opts := serviceTestOptions(t)

	cancel, done := startServiceProcess(t, "vpn", run, opts)
	require.Eventually(t, func() bool {
		_, active, ok := processStatus(t, opts.socket)
		return ok && active[gateway.ServiceManagementVPN]
	}, 5*time.Second, 10*time.Millisecond, "the supervisor must see the VPN active")

	cancel()
	require.NoError(t, <-done)
	assert.Equal(t, []string{gateway.ServiceManagementVPN}, run.built.Gateway.HostedServices)
	require.Len(t, run.leaseGateways, 1, "the vpn child builds its own lease record")
	assert.NotNil(t, run.leaseGateways[0])
}

// recordingLeaseControl is a control plane holding no VPN leases that counts
// the fetches of its record.
type recordingLeaseControl struct {
	gateway.VPNLeaseControl
	fetches atomic.Int32
}

func (c *recordingLeaseControl) FetchDesiredConfig(context.Context) (*gwstate.DesiredConfig, error) {
	c.fetches.Add(1)
	return &gwstate.DesiredConfig{}, nil
}

// idleVPNPlane is a MASQUE plane that starts and stops; the tests admit no
// client, so no peer is installed on it.
type idleVPNPlane struct{ vpn.ManagedDataPlane }

func (idleVPNPlane) Kind() vpn.DataPlaneKind     { return vpn.DataPlaneMASQUE }
func (idleVPNPlane) Start(context.Context) error { return nil }
func (idleVPNPlane) Stop(context.Context) error  { return nil }

// The admission dependencies are reached only when a client connects, which
// these tests never do.
type (
	unusedVPNIdentity struct{ vpn.IdentityPolicy }
	unusedVPNVerifier struct{ vpn.Verifier }
	unusedVPNPosture  struct{ vpn.PostureEvaluator }
	unusedVPNFactors  struct{ vpn.FactorVerifier }
	unusedVPNAudit    struct{ calleradmission.Auditor }
)

// vpnGatewayConfig is a gateway that builds the real management VPN, its
// admission listener on a free loopback port.
func vpnGatewayConfig(t *testing.T) *gateway.GatewayConfig {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	bundle := testutil.GenerateTestTLSBundle(t)
	return &gateway.GatewayConfig{
		Enabled:       true,
		ID:            "gw-vpn-test",
		MinReputation: gateway.MinReputation,
		MinAgeDays:    gateway.MinAgeDays,
		MinUptimePct:  gateway.MinUptimePct,
		ManagementVPN: &gateway.ManagementVPNServiceConfig{Enabled: true, Config: vpn.Config{
			Pool:     "remote-access",
			AllowTo:  []string{"management"},
			Listener: vpn.ListenerConfig{BindHost: "127.0.0.1", Port: port},
			MASQUE: vpn.MASQUESettings{
				Template: "https://gw.example:4433/.well-known/masque/ip/",
				Routes:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			},
		}},
		Runtime: &gateway.GatewayRuntime{VPN: &gateway.VPNRuntime{
			Identity: unusedVPNIdentity{},
			Verifier: unusedVPNVerifier{},
			Posture:  unusedVPNPosture{},
			Factors:  unusedVPNFactors{},
			IPAM:     backends.NewMemoryBackend(),
			DataPlanes: map[vpn.DataPlaneKind]gateway.VPNDataPlaneFactory{
				vpn.DataPlaneMASQUE: func(*slog.Logger) (vpn.ManagedDataPlane, error) { return idleVPNPlane{}, nil },
			},
			Audit:    unusedVPNAudit{},
			Listener: vpn.ListenerDeps{Certificate: bundle.ServerCert, ClientCAs: fileAnchor(t, bundle.CACertPEM)},
		}},
	}
}

// TestServeProcess_TheVPNStartsFromItsLeaseRecord: the vpn child's real
// management VPN rebuilds its leases from the control plane's record it was
// handed before it serves.
func TestServeProcess_TheVPNStartsFromItsLeaseRecord(t *testing.T) {
	run := newVPNServiceRun()
	run.gatewayConfig = vpnGatewayConfig(t)
	control := &recordingLeaseControl{}
	run.leaseControl = control
	run.journal = gateway.NewRevocationJournal(filepath.Join(t.TempDir(), "vpn-revocations.json"))
	opts := serviceTestOptions(t)

	cancel, done := startServiceProcess(t, "vpn", run, opts)
	require.Eventually(t, func() bool {
		_, active, ok := processStatus(t, opts.socket)
		return ok && active[gateway.ServiceManagementVPN]
	}, 5*time.Second, 10*time.Millisecond, "the supervisor must see the VPN active")

	cancel()
	require.NoError(t, <-done)
	assert.Equal(t, int32(1), control.fetches.Load(), "the VPN fetches its lease record once, at start")
}

// TestServeProcess_TheVPNReadsTheJournalItWasHanded: a journal the child
// cannot parse refuses the VPN's start, named in the start error the
// supervisor reads, so the journal handed to the child is the one it uses.
func TestServeProcess_TheVPNReadsTheJournalItWasHanded(t *testing.T) {
	run := newVPNServiceRun()
	run.gatewayConfig = vpnGatewayConfig(t)
	run.leaseControl = &recordingLeaseControl{}
	journalPath := filepath.Join(t.TempDir(), "vpn-revocations.json")
	require.NoError(t, os.WriteFile(journalPath, []byte("not json"), 0o600))
	run.journal = gateway.NewRevocationJournal(journalPath)
	opts := serviceTestOptions(t)

	cancel, done := startServiceProcess(t, "vpn", run, opts)
	var startErr string
	require.Eventually(t, func() bool {
		var ok bool
		startErr, _, ok = processStatus(t, opts.socket)
		return ok && startErr != ""
	}, 5*time.Second, 10*time.Millisecond, "the start error must be readable over the control service")

	cancel()
	require.NoError(t, <-done)
	assert.Contains(t, startErr, journalPath)
	assert.Contains(t, startErr, "parse")
}

func TestServeProcess_TheProxyProcessHostsOnlyTheProxy(t *testing.T) {
	run := newServiceRun()
	run.handler = &fakeServiceHandler{name: gateway.ServiceProxy}
	run.loaded.Proxy = &proxysvc.Config{Enabled: true}
	opts := serviceTestOptions(t)

	cancel, done := startServiceProcess(t, "proxy", run, opts)
	require.Eventually(t, func() bool {
		_, active, ok := processStatus(t, opts.socket)
		return ok && active[gateway.ServiceProxy]
	}, 5*time.Second, 10*time.Millisecond, "the supervisor must see the proxy active")

	cancel()
	require.NoError(t, <-done)
	require.Len(t, run.hardened, 1)
	assert.Equal(t, "proxy", run.hardened[0].Name)
	assert.Equal(t, []string{gateway.ServiceProxy}, run.built.Gateway.HostedServices,
		"transit and DHCP are enabled but belong to other processes")
}

func TestServeProcess_TheProxyProcessRefusesADisabledProxy(t *testing.T) {
	run := newServiceRun()
	run.loaded.Proxy = &proxysvc.Config{Enabled: false}

	err := serveProcess(context.Background(), "proxy", serviceTestOptions(t), run.deps(), testLogger())

	var nothing *ErrProcessHostsNothing
	require.ErrorAs(t, err, &nothing)
	assert.Equal(t, "proxy", nothing.Process)
	assert.Nil(t, run.built, "an empty host list would host every service")
}

func TestServeProcess_TheProvisioningProcessHostsOnlyItsSections(t *testing.T) {
	run := newServiceRun()
	run.handler = &fakeServiceHandler{name: gateway.ServiceDHCP}
	run.loaded.Gateway.PXE = &gateway.PXEServiceConfig{Enabled: true, HTTPPort: 8080}
	opts := serviceTestOptions(t)

	cancel, done := startServiceProcess(t, "provisioning", run, opts)
	require.Eventually(t, func() bool {
		_, active, ok := processStatus(t, opts.socket)
		return ok && active[gateway.ServiceDHCP]
	}, 5*time.Second, 10*time.Millisecond, "the supervisor must see DHCP active")

	cancel()
	require.NoError(t, <-done)
	require.Len(t, run.hardened, 1)
	assert.Equal(t, "provisioning", run.hardened[0].Name)
	assert.Equal(t, []string{gateway.ServiceDHCP, gateway.ServicePXE}, run.built.Gateway.HostedServices,
		"transit is enabled but belongs to the routing process; edge is not enabled")
	assert.Nil(t, run.built.Gateway.Supervisor, "a child supervises nothing")
}

func TestServeProcess_AStartFailureReachesTheSupervisor(t *testing.T) {
	run := newServiceRun()
	run.handler.startErr = &gateway.ErrNilServiceHandler{}
	opts := serviceTestOptions(t)

	cancel, done := startServiceProcess(t, "routing", run, opts)
	require.Eventually(t, func() bool {
		startErr, _, ok := processStatus(t, opts.socket)
		return ok && strings.Contains(startErr, gateway.ServiceTransit)
	}, 5*time.Second, 10*time.Millisecond, "the start error must be readable over the control service")

	cancel()
	require.NoError(t, <-done)
	assert.False(t, run.handler.active.Load())
}

func TestServeProcess_RefusesBeforeServing(t *testing.T) {
	failure := errors.New("injected")
	tests := []struct {
		name    string
		process string
		setup   func(run *serviceRun, opts *serviceOptions)
		check   func(t *testing.T, err error, run *serviceRun)
	}{
		{
			name:    "an unknown process",
			process: "no-such-process",
			check: func(t *testing.T, err error, run *serviceRun) {
				var unknown *process.ErrUnknownProcess
				require.ErrorAs(t, err, &unknown)
				assert.Empty(t, run.hardened)
			},
		},
		{
			name:    "the drop fails",
			process: "routing",
			setup:   func(run *serviceRun, _ *serviceOptions) { run.hardenErr = failure },
			check: func(t *testing.T, err error, run *serviceRun) {
				require.ErrorIs(t, err, failure)
				assert.Zero(t, run.readCalls, "nothing is read with privileges the class does not keep")
			},
		},
		{
			name:    "the configuration is unreadable as the service account",
			process: "routing",
			setup:   func(run *serviceRun, _ *serviceOptions) { run.readErr = os.ErrPermission },
			check: func(t *testing.T, err error, run *serviceRun) {
				var unreadable *ErrServiceConfigUnreadable
				require.ErrorAs(t, err, &unreadable)
				assert.Equal(t, "routing", unreadable.Process)
				require.ErrorIs(t, err, os.ErrPermission)
				assert.Nil(t, run.built)
			},
		},
		{
			name:    "the configuration does not load",
			process: "routing",
			setup:   func(run *serviceRun, _ *serviceOptions) { run.loadErr = failure },
			check: func(t *testing.T, err error, run *serviceRun) {
				require.ErrorIs(t, err, failure)
				assert.Nil(t, run.built)
			},
		},
		{
			name:    "no gateway section",
			process: "routing",
			setup:   func(run *serviceRun, _ *serviceOptions) { run.loaded = &ServeConfig{} },
			check: func(t *testing.T, err error, run *serviceRun) {
				var nothing *ErrProcessHostsNothing
				require.ErrorAs(t, err, &nothing)
				assert.Nil(t, run.built)
			},
		},
		{
			name:    "none of the process's services is enabled",
			process: "routing",
			setup: func(run *serviceRun, _ *serviceOptions) {
				run.loaded.Gateway.Transit = nil
			},
			check: func(t *testing.T, err error, run *serviceRun) {
				var nothing *ErrProcessHostsNothing
				require.ErrorAs(t, err, &nothing)
				assert.Nil(t, run.built, "an empty host list would host every service")
			},
		},
		{
			name:    "the gateway does not assemble",
			process: "routing",
			setup:   func(run *serviceRun, _ *serviceOptions) { run.buildErr = failure },
			check: func(t *testing.T, err error, _ *serviceRun) {
				require.ErrorIs(t, err, failure)
			},
		},
		{
			name:    "the control socket cannot be created",
			process: "routing",
			setup: func(_ *serviceRun, opts *serviceOptions) {
				opts.socket = filepath.Join(opts.socket, "missing-dir", "routing.sock")
			},
			check: func(t *testing.T, err error, run *serviceRun) {
				var socketErr *ipc.ErrSocketPath
				require.ErrorAs(t, err, &socketErr)
				assert.False(t, run.handler.active.Load(), "no service starts without the supervisor's socket")
			},
		},
		{
			name:    "the vpn lease record does not assemble",
			process: "vpn",
			setup: func(run *serviceRun, _ *serviceOptions) {
				vpnRun := newVPNServiceRun()
				run.handler, run.loaded = vpnRun.handler, vpnRun.loaded
				run.leaseErr = failure
			},
			check: func(t *testing.T, err error, run *serviceRun) {
				require.ErrorIs(t, err, failure)
				require.Len(t, run.leaseGateways, 1)
				assert.False(t, run.handler.active.Load(), "the VPN does not start without its lease record")
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			run := newServiceRun()
			opts := serviceTestOptions(t)
			if tc.setup != nil {
				tc.setup(run, &opts)
			}
			err := serveProcess(context.Background(), tc.process, opts, run.deps(), testLogger())
			tc.check(t, err, run)
		})
	}
}

func TestServiceErrors_NameTheProcessAndWrapTheCause(t *testing.T) {
	unreadable := &ErrServiceConfigUnreadable{Process: "routing", Cause: os.ErrPermission}
	assert.Contains(t, unreadable.Error(), "routing")
	assert.ErrorIs(t, unreadable, os.ErrPermission)

	ipcFailed := &ErrServiceIPCFailed{Process: "routing", Cause: net.ErrClosed}
	assert.Contains(t, ipcFailed.Error(), "control service stopped")
	assert.ErrorIs(t, ipcFailed, net.ErrClosed)

	nothing := &ErrProcessHostsNothing{Process: "routing"}
	assert.Contains(t, nothing.Error(), "enables none of its services")
}
