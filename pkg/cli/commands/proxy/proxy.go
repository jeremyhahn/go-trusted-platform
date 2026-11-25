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

// Package proxy provides CLI commands for reverse-proxy configuration
// management: routes, backend pools, config status/reload and the SDN
// zone matrix.
package proxy

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	proxysvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/proxy"
)

// defaultCLITimeout is the context deadline for all proxy CLI operations.
const defaultCLITimeout = 30 * time.Second

// newCLIContext returns a context with the default CLI timeout and its
// cancel function. Callers must defer cancel().
func newCLIContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), defaultCLITimeout)
}

// clientFactory builds a proxy service client from the common CLI flags.
// Tests replace it with a fake to exercise command wiring without a daemon.
type clientFactory func(flags *cli.CommonFlags) (proxyClient, func() error, error)

// newProxyClient is the production client factory. It honors the global
// --protocol/--endpoint flags via cli.NewBaseCommand.
var newProxyClient clientFactory = func(flags *cli.CommonFlags) (proxyClient, func() error, error) {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return nil, nil, err
	}
	return proxysvc.NewClientFromGRPC(base.Client().Proxy()), base.Close, nil
}

// outputFunc renders a command result. Tests replace it to capture output.
type outputFunc func(flags *cli.CommonFlags, v any) error

// output is the production output renderer.
var output outputFunc = func(flags *cli.CommonFlags, v any) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()
	return base.Output(v)
}

// NewCommand creates the root proxy command.
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Reverse-proxy configuration management",
		Long: `Manage the platform's reverse-proxy configuration.

platformd is the source of truth for proxy routes and backend pools;
gatewayd instances sync this configuration and run the proxy engine.

Examples:
  # Route operations
  platformctl proxy route add --id web --path-prefix / --pool web-pool --auth-mode public
  platformctl proxy route list
  platformctl proxy route get web
  platformctl proxy route delete web

  # Pool operations
  platformctl proxy pool add --id web-pool --backend https://10.0.0.10:8443 --backend https://10.0.0.11:8443
  platformctl proxy pool list

  # Configuration lifecycle
  platformctl proxy status
  platformctl proxy reload

  # Zone matrix
  platformctl proxy zone-matrix`,
	}

	cmd.AddCommand(NewRouteCommand(getFlags))
	cmd.AddCommand(NewPoolCommand(getFlags))
	cmd.AddCommand(newStatusCommand(getFlags))
	cmd.AddCommand(newReloadCommand(getFlags))
	cmd.AddCommand(newZoneMatrixCommand(getFlags))

	return cmd
}

// newStatusCommand creates the proxy status subcommand.
func newStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show proxy configuration store status",
		Long: `Show the proxy configuration store status: config version,
route/pool counts, and the time of the last mutation.

Examples:
  platformctl proxy status
  platformctl proxy status -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(getFlags())
		},
	}
}

func runStatus(flags *cli.CommonFlags) error {
	client, closeFn, err := newProxyClient(flags)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := newCLIContext()
	defer cancel()

	status, err := client.Status(ctx)
	if err != nil {
		return &WrappedError{Msg: "failed to get proxy status", Err: err}
	}
	return output(flags, status)
}

// newReloadCommand creates the proxy reload subcommand.
func newReloadCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: "Bump the proxy config version",
		Long: `Bump the proxy configuration version so syncing gatewayd
instances re-fetch the current route/pool configuration.

Examples:
  platformctl proxy reload`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReload(getFlags())
		},
	}
}

func runReload(flags *cli.CommonFlags) error {
	client, closeFn, err := newProxyClient(flags)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := newCLIContext()
	defer cancel()

	version, err := client.Reload(ctx)
	if err != nil {
		return &WrappedError{Msg: "failed to reload proxy config", Err: err}
	}
	return output(flags, map[string]any{"version": version})
}

// newZoneMatrixCommand creates the proxy zone-matrix subcommand.
func newZoneMatrixCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "zone-matrix",
		Short: "Show the SDN zone matrix",
		Long: `Show the SDN zone names and the compiled allowed (from, to)
traffic pairs used to validate route zone requirements.

Examples:
  platformctl proxy zone-matrix
  platformctl proxy zone-matrix -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runZoneMatrix(getFlags())
		},
	}
}

func runZoneMatrix(flags *cli.CommonFlags) error {
	client, closeFn, err := newProxyClient(flags)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := newCLIContext()
	defer cancel()

	matrix, err := client.ZoneMatrix(ctx)
	if err != nil {
		return &WrappedError{Msg: "failed to get proxy zone matrix", Err: err}
	}
	return output(flags, matrix)
}
