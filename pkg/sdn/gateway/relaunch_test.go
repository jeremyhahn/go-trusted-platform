package gateway_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/process"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// gatewayChild is a supervised child that is a real gateway, in this
// process: a fresh one per launch, the way a relaunched gatewayd starts
// with nothing applied.
type gatewayChild struct {
	gw     *gateway.Gateway
	server *ipc.Server
	once   sync.Once
	done   chan struct{}
	err    error
}

func (c *gatewayChild) PID() int { return os.Getpid() }

func (c *gatewayChild) Wait() error {
	<-c.done
	return c.err
}

func (c *gatewayChild) Signal(os.Signal) error {
	c.exit(nil)
	return nil
}

// exit ends the child, as a crash or a stop does.
func (c *gatewayChild) exit(err error) {
	c.once.Do(func() {
		c.err = err
		c.server.Stop()
		if stopErr := c.gw.Stop(context.Background()); stopErr != nil {
			c.err = errors.Join(c.err, stopErr)
		}
		close(c.done)
	})
}

// kill ends the child as SIGKILL does: its socket goes, but its gateway
// never stops, so everything it programmed stays on the bridge. The gateway
// is stopped only once the test is over, to end its goroutines.
func (c *gatewayChild) kill(t *testing.T) {
	c.once.Do(func() {
		c.err = errors.New("signal: killed")
		c.server.Stop()
		close(c.done)
	})
	t.Cleanup(func() {
		if err := c.gw.Stop(context.Background()); err != nil {
			t.Logf("the killed child's gateway, stopped after the test: %v", err)
		}
	})
}

type gatewayLauncher struct {
	t *testing.T
	// runtime builds each child's datapath runtime; nil gives every child
	// its own fake one.
	runtime func() *gateway.GatewayRuntime

	mu       sync.Mutex
	children []*gatewayChild
}

func (l *gatewayLauncher) Launch(_ context.Context, spec process.Spec) (process.Child, error) {
	config := relaunchGatewayConfig()
	if l.runtime != nil {
		config.Runtime = l.runtime()
	}
	gw, err := gateway.NewGateway(config)
	if err != nil {
		return nil, err
	}
	cfg := gw.GetConfig()
	gw.SetNodeMetrics(cfg.MinReputation, time.Duration(cfg.MinAgeDays)*24*time.Hour, cfg.MinUptimePct)
	if err := gw.Start(context.Background()); err != nil {
		return nil, err
	}
	uid := uint32(os.Getuid())
	server := ipc.NewServer(gw, ipc.Policy{ControlUIDs: []uint32{uid}, DatapathUIDs: []uint32{uid}})
	if err := server.Listen(spec.Socket, 0o600, -1); err != nil {
		return nil, err
	}
	child := &gatewayChild{gw: gw, server: server, done: make(chan struct{})}
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

func (l *gatewayLauncher) child(n int) *gatewayChild {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.children) < n {
		return nil
	}
	return l.children[n-1]
}

// relaunchGatewayConfig is the datapath child's own configuration: a load
// balancer with one VIP and NAT, the desired document adding the rest.
func relaunchGatewayConfig() *gateway.GatewayConfig {
	return &gateway.GatewayConfig{
		Enabled:       true,
		ID:            "relaunch-gw",
		MinReputation: gateway.MinReputation,
		MinAgeDays:    gateway.MinAgeDays,
		MinUptimePct:  gateway.MinUptimePct,
		Uplinks:       []gateway.UplinkConfig{{Name: "eth0", MTU: 1500}},
		LoadBalancer: &gateway.LoadBalancerConfig{
			Enabled:             true,
			Algorithm:           "hash",
			HealthCheckInterval: time.Hour,
			HealthCheckTimeout:  time.Second,
			MaxBackends:         8,
			VIPs: []gateway.VIPConfig{{
				Address: "10.100.0.10", Port: 443, Protocol: "tcp",
				Backends: []gateway.BackendConfig{{Address: "10.0.1.5", Port: 8443}},
			}},
		},
		NAT: &gateway.NATConfig{
			Enabled:        true,
			ExternalIP:     "203.0.113.10",
			PortRangeStart: 1024,
			PortRangeEnd:   65535,
			MaxSessions:    1000,
			InternalCIDR:   "10.0.100.0/24",
		},
		Runtime: gateway.NewTestRuntime(),
	}
}

// heldVIPs and heldDNAT read what a child gateway holds.
func heldVIPs(gw *gateway.Gateway) []string {
	svc, ok := gw.LBService()
	if !ok {
		return nil
	}
	var out []string
	for _, s := range svc.ListVIPs() {
		out = append(out, netip.AddrPortFrom(s.VIP.Address, s.VIP.Port).String())
	}
	return out
}

func heldDNAT(gw *gateway.Gateway) []string {
	nat, ok := gw.NATService()
	if !ok {
		return nil
	}
	var out []string
	for _, rule := range nat.DNATRules() {
		out = append(out, rule.Internal.String())
	}
	return out
}

// startRelaunchSupervisor supervises the datapath child launcher builds,
// with its load balancer and NAT started and the relaunch document applied,
// and returns the first child.
func startRelaunchSupervisor(t *testing.T, ctx context.Context, launcher *gatewayLauncher) (*process.Supervisor, *gatewayChild) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "gwrl")
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove runtime dir: %v", err)
		}
	})
	supervisor := process.New(process.Config{
		Launcher:       launcher,
		RuntimeDir:     dir,
		Inherited:      process.Inherited{ConfigFile: filepath.Join(dir, "config.yaml")},
		SocketGID:      -1,
		ReadyTimeout:   5 * time.Second,
		StopTimeout:    2 * time.Second,
		RestartBackoff: time.Millisecond,
		RestartWindow:  time.Minute,
	})
	t.Cleanup(func() {
		if err := supervisor.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	})

	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceLoadBalancer))
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceNAT))
	desired := &gwstate.DesiredConfig{
		GatewayID: "relaunch-gw",
		Version:   "rev-1",
		LoadBalancer: &gwstate.DesiredLoadBalancer{VIPs: []gwstate.DesiredVIP{
			{Address: "10.100.0.20", Port: 80, Protocol: "tcp",
				Backends: []gwstate.DesiredBackend{{Address: "10.0.1.7", Port: 8080}}},
		}},
		NAT: &gwstate.DesiredNAT{
			SNATInternalCIDR: "10.0.100.0/24",
			DNAT:             []gwstate.DesiredDNAT{{Protocol: "tcp", External: "203.0.113.10:2222", Internal: "10.0.100.5:22"}},
		},
	}
	_, err = supervisor.Apply(ctx, desired)
	require.NoError(t, err)
	first := launcher.child(1)
	require.NotNil(t, first)
	return supervisor, first
}

// awaitRelaunch waits until the supervisor reports the relaunched child up,
// which it does only once the child holds its document again, and returns
// that child.
func awaitRelaunch(t *testing.T, supervisor *process.Supervisor, launcher *gatewayLauncher) *gatewayChild {
	t.Helper()
	require.Eventually(t, func() bool {
		return launcher.child(2) != nil &&
			supervisor.ServiceHealth(gateway.ServiceLoadBalancer) == nil &&
			supervisor.ServiceHealth(gateway.ServiceNAT) == nil
	}, 15*time.Second, 10*time.Millisecond, "the relaunched child is reported up once it holds its document")
	return launcher.child(2)
}

func TestSupervisedRelaunch_TheNewChildHoldsTheDesiredVIPsAndDNATRules(t *testing.T) {
	// A relaunched datapath child sweeps its predecessor's flows on Start,
	// and the parent still holds the document's version, so without the
	// supervisor's re-send the desired VIP and DNAT rule would stay missing
	// until the document changed (#557).
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	launcher := &gatewayLauncher{t: t}
	supervisor, first := startRelaunchSupervisor(t, ctx, launcher)
	assert.ElementsMatch(t, []string{"10.100.0.20:80"}, heldVIPs(first.gw))
	assert.Equal(t, []string{"10.0.100.5:22"}, heldDNAT(first.gw))

	first.exit(errors.New("signal: killed"))

	second := awaitRelaunch(t, supervisor, launcher)
	assert.ElementsMatch(t, []string{"10.100.0.20:80"}, heldVIPs(second.gw),
		"the desired VIP is back on the relaunched child")
	assert.Equal(t, []string{"10.0.100.5:22"}, heldDNAT(second.gw),
		"the desired DNAT rule is back on the relaunched child")
	assert.Equal(t, "rev-1", second.gw.DesiredConfigState().Version)
}

func TestSupervisedRelaunch_AKilledChildsSuccessorReconcilesTheBridgeItLeft(t *testing.T) {
	// SIGKILL runs no Stop, so the killed child's flows and groups are still
	// on the bridge when its successor starts there. The successor gets the
	// desired document again and must end holding exactly the flows the
	// first child held, every one under its own generation: a stale
	// generation left behind is a flow no process owns (#557).
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	bridge := gateway.NewTestBridge()
	launcher := &gatewayLauncher{t: t, runtime: func() *gateway.GatewayRuntime { return gateway.NewTestRuntimeOn(bridge) }}
	supervisor, first := startRelaunchSupervisor(t, ctx, launcher)

	before := bridge.State()
	require.NotEmpty(t, before)
	firstGenerations := bridge.Generations()
	require.Len(t, firstGenerations, 2, "the load balancer and NAT each stamp their flows")

	first.kill(t)
	require.Equal(t, before, bridge.State(), "a killed child withdraws nothing")

	awaitRelaunch(t, supervisor, launcher)
	assert.Equal(t, before, bridge.State(), "the successor holds what the killed child held")
	generations := bridge.Generations()
	require.Len(t, generations, len(firstGenerations))
	for owner, held := range generations {
		require.Len(t, held, 1, "owner 0x%x keeps one generation, the successor's", owner)
		assert.NotEqual(t, firstGenerations[owner], held, "owner 0x%x carries the successor's generation", owner)
	}
}
