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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/process"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/perf"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// serviceSocketMode lets the socket's group — the service account — connect;
// the control service's peer-credential policy decides what each caller may
// do once connected.
const serviceSocketMode = 0o660

var (
	serviceIPCSocket     string
	serviceSocketGroup   int
	serviceSupervisorUID uint32
	serviceUID           uint32
	serviceGID           uint32
)

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Supervised gatewayd processes",
	Long: `Commands for the supervised process model (the process: section).

The supervisor in gatewayd serve starts each child with service run; an
operator does not run it by hand.`,
}

var serviceRunCmd = &cobra.Command{
	Use:   "run <process>",
	Short: "Run one supervised process (started by gatewayd serve)",
	Long: `Runs one process of the supervised model: drops to the process's
privilege class, reads the configuration as the service account, starts the
services the process hosts and serves the supervisor on --ipc-socket.`,
	Args: cobra.ExactArgs(1),
	RunE: runService,
}

func init() {
	flags := serviceRunCmd.Flags()
	flags.StringVar(&serviceIPCSocket, "ipc-socket", "", "control socket the supervisor connects to")
	flags.IntVar(&serviceSocketGroup, "socket-group", -1, "group owning the control socket (-1 leaves it)")
	flags.Uint32Var(&serviceSupervisorUID, "supervisor-uid", 0, "uid admitted to the control service")
	flags.Uint32Var(&serviceUID, "uid", 0, "uid an unprivileged process drops to")
	flags.Uint32Var(&serviceGID, "gid", 0, "gid an unprivileged process drops to")
	serviceCmd.AddCommand(serviceRunCmd)
}

// serviceOptions are the service run flags the supervisor passes.
type serviceOptions struct {
	socket        string
	socketGroup   int
	supervisorUID uint32
	uid, gid      uint32
}

// serviceDeps are the steps of serveProcess that touch the operating system
// or the configuration, so the sequence is a unit test.
type serviceDeps struct {
	enterHardened   func(def process.Definition, uid, gid uint32) error
	readConfig      func() error
	loadConfig      func() (*ServeConfig, error)
	buildGateway    func(ctx context.Context, cfg *ServeConfig, logger *slog.Logger) (*gateway.Gateway, error)
	vpnLeaseControl func(ctx context.Context, cfg *ServeConfig, gw *gateway.Gateway, logger *slog.Logger) (gateway.VPNLeaseControl, *gateway.RevocationJournal, error)
	// vpnDataPlanes builds the VPN data planes the wireguard child hosts
	// for VPNPlaneService. Nil, or no planes, leaves every
	// InstallVPNPeer refused.
	vpnDataPlanes func(cfg *ServeConfig, hubKey *vpnHubKey, logger *slog.Logger) ([]vpn.ManagedDataPlane, error)
	// removeStaleVPNHub removes the WireGuard hub device a killed
	// predecessor left, with its peers. The wireguard child calls it at
	// start, before any fallible step, whether or not it hosts a plane
	// (#1698). Nil does nothing.
	removeStaleVPNHub func(logger *slog.Logger) error
	// resolveVPNHubKey resolves the WireGuard hub's key before
	// EnterHardened, for vpnDataPlanes. Nil, or a nil key, builds no hub.
	resolveVPNHubKey func(ctx context.Context, cfg *ServeConfig, logger *slog.Logger) *vpnHubKey
}

// vpnHubKey is the WireGuard hub's private key, resolved before
// EnterHardened and held in memory for the hub as its tunnel.KeyProvider.
// A resolution failure is held too, so the plane's start reports it as it
// did when the hub resolved the key itself.
type vpnHubKey struct {
	ref string
	key []byte
	err error
}

// Key returns a copy of the held key for its own reference.
func (k *vpnHubKey) Key(_ context.Context, ref string) ([]byte, error) {
	if k.err != nil {
		return nil, k.err
	}
	if ref != k.ref {
		return nil, fmt.Errorf("the hub holds the key of %q, not %q", k.ref, ref)
	}
	return append([]byte(nil), k.key...), nil
}

// loadServiceConfig reads and loads a child's configuration. The root
// command read it too, but treats a read error as a warning; a child
// without its configuration must not start.
func loadServiceConfig(def process.Definition, deps serviceDeps) (*ServeConfig, error) {
	if err := deps.readConfig(); err != nil {
		return nil, &ErrServiceConfigUnreadable{Process: def.Name, Cause: err}
	}
	return deps.loadConfig()
}

func runService(cmd *cobra.Command, args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	opts := serviceOptions{
		socket:        serviceIPCSocket,
		socketGroup:   serviceSocketGroup,
		supervisorUID: serviceSupervisorUID,
		uid:           serviceUID,
		gid:           serviceGID,
	}
	deps := serviceDeps{
		enterHardened:     process.EnterHardened,
		readConfig:        viper.ReadInConfig,
		loadConfig:        func() (*ServeConfig, error) { return LoadServeConfig(viper.GetViper()) },
		buildGateway:      BuildGateway,
		vpnLeaseControl:   vpnLeaseControl,
		vpnDataPlanes:     vpnDataPlanes,
		removeStaleVPNHub: removeStaleVPNHub,
		resolveVPNHubKey:  resolveVPNHubKey,
	}
	return serveProcess(ctx, args[0], opts, deps, buildServeLogger())
}

// serveProcess runs one supervised process until ctx ends. It drops to the
// process's class before it reads the configuration, hosts only the enabled
// services the process owns, and serves the supervisor before starting them,
// so a start failure reaches the supervisor as the process's start error
// rather than as a socket that never appears.
func serveProcess(ctx context.Context, name string, opts serviceOptions, deps serviceDeps, logger *slog.Logger) error {
	def, err := process.DefinitionByName(name)
	if err != nil {
		return err
	}
	// The wireguard child's hub key comes from the secret store, which is
	// reached over the network: EnterHardened's filter admits AF_UNIX and
	// AF_NETLINK only, so the key is resolved before it and held in memory
	// for the hub (Codex #2029 round 1). Only this child reads its
	// configuration before the drop; every other class reads it after.
	var cfg *ServeConfig
	var hubKey *vpnHubKey
	if def.Name == process.WireGuardProcess {
		// A freshly started wireguard child owns no hub yet, so a hub device
		// of its name is a killed predecessor's: its peers would otherwise
		// pass traffic past their leases through every startup step below
		// that can fail, so it goes before configuration, the key or
		// assembly (Codex #1717 round 2).
		if deps.removeStaleVPNHub != nil {
			if err := deps.removeStaleVPNHub(logger); err != nil {
				return err
			}
		}
		if cfg, err = loadServiceConfig(def, deps); err != nil {
			return err
		}
		if deps.resolveVPNHubKey != nil {
			hubKey = deps.resolveVPNHubKey(ctx, cfg, logger)
		}
	}
	if err := deps.enterHardened(def, opts.uid, opts.gid); err != nil {
		return err
	}
	if cfg == nil {
		if cfg, err = loadServiceConfig(def, deps); err != nil {
			return err
		}
	}
	if cfg.Gateway == nil {
		return &ErrProcessHostsNothing{Process: def.Name}
	}
	hosted := def.ServicesFor(enabledServices(cfg))
	// An empty HostedServices means every service, so a process with
	// nothing to host stops here rather than hosting everything.
	if len(hosted) == 0 {
		return &ErrProcessHostsNothing{Process: def.Name}
	}
	cfg.Gateway.HostedServices = hosted
	// A child supervises nothing: it hosts its services itself.
	cfg.Gateway.Supervisor = nil

	gw, err := deps.buildGateway(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer closeGatewayRuntime(gw, logger)

	// The management VPN's leases live in this child's gateway, so the
	// control plane's record of them and the revocation journal are wired
	// here: the parent's reporter reaches only the parent's gateway.
	if slices.Contains(hosted, gateway.ServiceManagementVPN) {
		control, journal, err := deps.vpnLeaseControl(ctx, cfg, gw, logger)
		if err != nil {
			return err
		}
		if control != nil {
			gw.SetVPNLeaseControl(control, journal)
		}
	}

	services, err := datapathServices(def, gw)
	if err != nil {
		return err
	}
	vpnPlanes, err := deps.datapathVPNPlanes(def, cfg, hubKey, logger)
	if err != nil {
		return err
	}
	server := ipc.NewServer(gw, servicePolicy(def, opts, cfg.Process))
	server.SetServices(services)
	// The planes start with the child and before the socket is bound, so
	// the first peer RPC finds them up; one that fails to start is reported
	// to the supervisor with the services.
	var planesErr error
	if vpnPlanes != nil {
		if planesErr = vpnPlanes.Start(ctx); planesErr == nil {
			server.SetVPNPlanes(vpnPlanes)
		} else {
			server.SetVPNPlanesFailed(planesErr)
			vpnPlanes = nil
		}
	}
	// Hardened already, so the kernel-class child holds no CAP_CHOWN and is
	// not in the socket group: its socket takes the group from the
	// supervisor's setgid runtime directory, and Listen only verifies it.
	if err := server.Listen(opts.socket, serviceSocketMode, opts.socketGroup); err != nil {
		return errors.Join(err, stopVPNPlanes(vpnPlanes))
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve() }()

	// A plane that failed to start keeps the hosted services down: the
	// supervisor accepts an active service before it reads the start
	// error, so a started gateway would report ready with no plane.
	startErr := planesErr
	if startErr == nil {
		startErr = gw.Start(ctx)
	}
	stopKeepAlive := func() {}
	if err := startErr; err != nil {
		// The process keeps serving so the supervisor reads why; it stops
		// the process when it gives up on the service.
		server.SetStartError(err)
		logger.Error("Supervised services failed to start",
			slog.String("process", def.Name), slog.Any("error", err))
		// The STATUS= text names the process only: the error reaches the
		// supervisor over the control socket, never through the notify one.
		notifySupervisor(logger, def.Name, "STATUS="+def.Name+": services failed to start")
	} else {
		logger.Info("Supervised services started",
			slog.String("process", def.Name), slog.Any("services", hosted))
		notifySupervisor(logger, def.Name, "READY=1")
		// Keep-alives run only after READY=1: the supervisor arms the watchdog
		// at readiness, and a child that failed to start has nothing to keep.
		stopKeepAlive = startWatchdogKeepAlive(ctx, logger, def.Name)
	}

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-served:
		// Serve returns nil only after Stop, which nothing has called.
		if serveErr == nil {
			serveErr = net.ErrClosed
		}
	}

	stopKeepAlive()
	notifySupervisor(logger, def.Name, "STOPPING=1")
	stopCtx, stopCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer stopCancel()
	stopErr := gw.Stop(stopCtx)
	server.Stop()
	stopErr = errors.Join(stopErr, stopVPNPlanes(vpnPlanes))
	if serveErr != nil {
		return errors.Join(&ErrServiceIPCFailed{Process: def.Name, Cause: serveErr}, stopErr)
	}
	if err := <-served; err != nil {
		logger.Warn("Control service exited with error",
			slog.String("process", def.Name), slog.Any("error", err))
	}
	return stopErr
}

// notifySupervisor sends state to the supervisor's notify socket, which
// NOTIFY_SOCKET names (nothing when it is unset). A failed notification is
// logged and never fails the process: the supervisor still reads the
// process's state over the control socket.
func notifySupervisor(logger *slog.Logger, name, state string) {
	if err := process.Notify(state); err != nil {
		logger.Warn("Supervisor notification failed",
			slog.String("process", name), slog.Any("error", err))
	}
}

// newKeepAliveTicker makes the keep-alive's ticker of period d: its channel
// and its stop. A variable so tests drive the ticks and see the period
// (Codex P1 #1928 round 4).
var newKeepAliveTicker = func(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// startWatchdogKeepAlive sends WATCHDOG=1 every half of the supervisor's
// WATCHDOG_USEC (docs/gateway/supervisor.md) until ctx ends or the returned
// stop is called; stop waits for the sender, so no keep-alive follows it.
// A missing, zero or malformed WATCHDOG_USEC sends nothing.
func startWatchdogKeepAlive(ctx context.Context, logger *slog.Logger, name string) (stop func()) {
	usec, err := strconv.ParseInt(os.Getenv(process.WatchdogUsecEnv), 10, 64)
	if err != nil || usec <= 0 {
		return func() {}
	}
	usec = min(usec, int64(math.MaxInt64/time.Microsecond))
	period := time.Duration(usec) * time.Microsecond / 2
	if period <= 0 {
		period = time.Microsecond
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticks, stopTicker := newKeepAliveTicker(period)
		defer stopTicker()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticks:
				notifySupervisor(logger, name, "WATCHDOG=1")
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// vpnLeaseControl is the management VPN's lease record for the vpn child:
// the control plane, reached through the reporter BuildReporter assembles
// from the `control-plane:` section, and the revocation journal under
// --data-dir. Without an enabled section there is no record, as in serve:
// the leases are then held in memory only.
func vpnLeaseControl(ctx context.Context, cfg *ServeConfig, gw *gateway.Gateway, logger *slog.Logger) (gateway.VPNLeaseControl, *gateway.RevocationJournal, error) {
	reporter, err := BuildReporter(ctx, cfg, gw, logger)
	if err != nil {
		return nil, nil, err
	}
	// A nil *Reporter in the interface would read as a control plane.
	if reporter == nil {
		return nil, nil, nil
	}
	return reporter, vpnRevocationJournal(cfg.DataDir), nil
}

// servicePolicy admits the supervisor to the control service. Only the
// datapath process also admits the service account, through which the
// parser processes reach the kernel state they may not program themselves;
// a parser process admits no other parser.
func servicePolicy(def process.Definition, opts serviceOptions, settings *process.Settings) ipc.Policy {
	// Only the wireguard child's socket admits VPNPlaneService (ruling 942).
	policy := ipc.Policy{ControlUIDs: []uint32{opts.supervisorUID}, VPNPlane: def.Name == process.WireGuardProcess}
	if def.Class == process.ClassKernel {
		policy.DatapathUIDs = []uint32{opts.uid}
		if settings != nil {
			policy.PlatformUIDs = settings.PlatformUIDs
		}
	}
	return policy
}

// datapathServices is what the datapath child serves platformd live on
// GatewayServicesService (#660): the gateway's load balancer and NAT64, and
// a perf service on the runtime's OVS client. Every other process serves
// none, so those calls refuse with ErrServiceNotActive.
func datapathServices(def process.Definition, gw *gateway.Gateway) (ipc.Services, error) {
	if def.Class != process.ClassKernel {
		return ipc.Services{}, nil
	}
	services := ipc.Services{LoadBalancer: gw, NAT64: gw}
	rt := gw.GetConfig().Runtime
	if rt == nil || rt.OVS == nil {
		return services, nil
	}
	deps := perf.Deps{OVS: rt.OVS, Bridge: rt.Bridge}
	if runner, ok := rt.OVS.(ovs.AppCtlRunner); ok {
		deps.AppCtl = runner
	}
	perfService, err := perf.New(deps)
	if err != nil {
		return ipc.Services{}, err
	}
	services.Perf = perfService
	return services, nil
}

// datapathVPNPlanes is the plane host the wireguard child serves
// VPNPlaneService from (#1698): the planes the factory builds, wrapped in a
// vpn.PlaneHost. Only the wireguard row hosts planes, and only while the
// management VPN is enabled; the datapath child hosts none. Otherwise, or
// when the factory builds none, it returns nil and every InstallVPNPeer
// keeps its refusal. A killed predecessor's hub is not removed here:
// serveProcess removes it at wireguard-child start, before any fallible
// step, and the supervisor's OnChildExit hook removes it when the child
// exits.
func (d serviceDeps) datapathVPNPlanes(def process.Definition, cfg *ServeConfig, hubKey *vpnHubKey, logger *slog.Logger) (*vpn.PlaneHost, error) {
	if def.Name != process.WireGuardProcess {
		return nil, nil
	}
	var planes []vpn.ManagedDataPlane
	if d.vpnDataPlanes != nil && cfg.Gateway != nil && cfg.Gateway.ManagementVPN != nil && cfg.Gateway.ManagementVPN.Enabled {
		var err error
		if planes, err = d.vpnDataPlanes(cfg, hubKey, logger); err != nil {
			return nil, err
		}
	}
	if len(planes) == 0 {
		return nil, nil
	}
	return vpn.NewPlaneHost(planes...)
}

// stopVPNPlanes stops the hosted planes, if any, within the shutdown
// timeout.
func stopVPNPlanes(host *vpn.PlaneHost) error {
	if host == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return host.Stop(ctx)
}

// closeGatewayRuntime releases the OVS runtime a gateway holds, if any.
func closeGatewayRuntime(gw *gateway.Gateway, logger *slog.Logger) {
	rt := gw.GetConfig().Runtime
	if rt == nil {
		return
	}
	if err := rt.Close(); err != nil {
		logger.Warn("OVS runtime close failed", slog.Any("error", err))
	}
}
