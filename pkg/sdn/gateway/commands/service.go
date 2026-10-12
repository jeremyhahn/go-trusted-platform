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
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/process"
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
	enterHardened func(def process.Definition, uid, gid uint32) error
	readConfig    func() error
	loadConfig    func() (*ServeConfig, error)
	buildGateway  func(ctx context.Context, cfg *ServeConfig, logger *slog.Logger) (*gateway.Gateway, error)
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
		enterHardened: process.EnterHardened,
		readConfig:    viper.ReadInConfig,
		loadConfig:    func() (*ServeConfig, error) { return LoadServeConfig(viper.GetViper()) },
		buildGateway:  BuildGateway,
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
	hosted := def.ServicesFor(cfg.Gateway.EnabledServices())
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

	server := ipc.NewServer(gw, servicePolicy(def, opts))
	if err := server.Listen(opts.socket, serviceSocketMode, opts.socketGroup); err != nil {
		return err
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve() }()

	if err := gw.Start(ctx); err != nil {
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
	if serveErr != nil {
		return errors.Join(&ErrServiceIPCFailed{Process: def.Name, Cause: serveErr}, stopErr)
	}
	if err := <-served; err != nil {
		logger.Warn("Control service exited with error",
			slog.String("process", def.Name), slog.Any("error", err))
	}
	return stopErr
}

// servicePolicy admits the supervisor to the control service. Only the
// datapath process also admits the service account, through which the
// parser processes reach the kernel state they may not program themselves;
// a parser process admits no other parser.
func servicePolicy(def process.Definition, opts serviceOptions) ipc.Policy {
	policy := ipc.Policy{ControlUIDs: []uint32{opts.supervisorUID}}
	if def.Class == process.ClassKernel {
		policy.DatapathUIDs = []uint32{opts.uid}
	}
	return policy
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
