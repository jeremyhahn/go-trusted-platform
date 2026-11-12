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
	"log/slog"
	"net"
	"os/signal"
	"slices"
	"syscall"

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
	// vpnDataPlanes builds the VPN data planes the datapath child hosts
	// for the vpn process's peer RPCs. Nil, or no planes, leaves every
	// InstallVPNPeer refused.
	vpnDataPlanes func(cfg *ServeConfig, gw *gateway.Gateway, logger *slog.Logger) ([]vpn.ManagedDataPlane, error)
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
		enterHardened:   process.EnterHardened,
		readConfig:      viper.ReadInConfig,
		loadConfig:      func() (*ServeConfig, error) { return LoadServeConfig(viper.GetViper()) },
		buildGateway:    BuildGateway,
		vpnLeaseControl: vpnLeaseControl,
		vpnDataPlanes:   vpnDataPlanes,
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
	if err := deps.enterHardened(def, opts.uid, opts.gid); err != nil {
		return err
	}
	// The root command read the configuration too, but treats a read error
	// as a warning; a child without its configuration must not start.
	if err := deps.readConfig(); err != nil {
		return &ErrServiceConfigUnreadable{Process: def.Name, Cause: err}
	}
	cfg, err := deps.loadConfig()
	if err != nil {
		return err
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
	vpnPlanes, err := deps.datapathVPNPlanes(def, cfg, gw, logger)
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

	if err := errors.Join(planesErr, gw.Start(ctx)); err != nil {
		// The process keeps serving so the supervisor reads why; it stops
		// the process when it gives up on the service.
		server.SetStartError(err)
		logger.Error("Supervised services failed to start",
			slog.String("process", def.Name), slog.Any("error", err))
	} else {
		logger.Info("Supervised services started",
			slog.String("process", def.Name), slog.Any("services", hosted))
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
	policy := ipc.Policy{ControlUIDs: []uint32{opts.supervisorUID}}
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

// datapathVPNPlanes is the plane host the datapath child serves the vpn
// process's peer RPCs from (#1698): the planes the factory builds, wrapped
// in a vpn.PlaneHost. Only the kernel-class child, which holds
// CAP_NET_ADMIN, hosts planes, and only while the management VPN is
// enabled; otherwise, or when the factory builds none, it returns nil and
// every InstallVPNPeer keeps its refusal.
func (d serviceDeps) datapathVPNPlanes(def process.Definition, cfg *ServeConfig, gw *gateway.Gateway, logger *slog.Logger) (*vpn.PlaneHost, error) {
	if def.Class != process.ClassKernel || d.vpnDataPlanes == nil {
		return nil, nil
	}
	if cfg.Gateway == nil || cfg.Gateway.ManagementVPN == nil || !cfg.Gateway.ManagementVPN.Enabled {
		return nil, nil
	}
	planes, err := d.vpnDataPlanes(cfg, gw, logger)
	if err != nil {
		return nil, err
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

// vpnDataPlanes is gatewayd's plane factory. The configuration does not yet
// name what a kernel plane needs beyond its listen port (the WireGuard
// hub's device key reference and its pool gateway address), so it builds
// none and says so: the vpn process's peer RPCs keep their refusal.
func vpnDataPlanes(cfg *ServeConfig, _ *gateway.Gateway, logger *slog.Logger) ([]vpn.ManagedDataPlane, error) {
	offered := cfg.Gateway.ManagementVPN.Config.WithDefaults().DataPlanes
	logger.Warn("The datapath hosts no VPN data plane: the configuration does not name the plane's key and address",
		slog.Any("data_planes", offered))
	return nil, nil
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
