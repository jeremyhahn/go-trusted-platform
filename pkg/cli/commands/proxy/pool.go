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

package proxy

import (
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// poolFlags collects the flag values shared by pool add and update.
type poolFlags struct {
	id              string
	backends        []string
	balancer        string
	trustClass      string
	mtlsClientCert  bool
	maxIdlePerHost  int
	idleConnTimeout time.Duration
}

// register binds the pool flags onto cmd.
func (f *poolFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.id, "id", "", "Pool identifier (required)")
	cmd.Flags().StringSliceVar(&f.backends, "backend", nil, "Backend URL, optionally with weight as URL=WEIGHT (repeatable, required)")
	cmd.Flags().StringVar(&f.balancer, "balancer", "", "Balancer name (empty defaults to round-robin)")
	cmd.Flags().StringVar(&f.trustClass, "trust-class", "", "What backend TLS is verified against: platform (a platform-issued service) or bmc")
	cmd.Flags().BoolVar(&f.mtlsClientCert, "mtls-client-cert", false, "Present a client certificate to backends")
	cmd.Flags().IntVar(&f.maxIdlePerHost, "max-idle-conns-per-host", 0, "Maximum idle connections per backend host")
	cmd.Flags().DurationVar(&f.idleConnTimeout, "idle-conn-timeout", 0, "Idle connection timeout (e.g. 90s)")
}

// validate checks the required pool flags.
func (f *poolFlags) validate() error {
	if f.id == "" {
		return &MessageError{Msg: "--id is required"}
	}
	if len(f.backends) == 0 {
		return &MessageError{Msg: "at least one --backend is required"}
	}
	return nil
}

// toProto builds the platform.v1 ProxyPool from the flag values. Backend
// entries use the form URL or URL=WEIGHT.
func (f *poolFlags) toProto() (*platformv1.ProxyPool, error) {
	backends := make([]*platformv1.ProxyBackend, 0, len(f.backends))
	for _, entry := range f.backends {
		backend, err := parseBackend(entry)
		if err != nil {
			return nil, err
		}
		backends = append(backends, backend)
	}
	return &platformv1.ProxyPool{
		Id:       f.id,
		Backends: backends,
		Balancer: f.balancer,
		Tls: &platformv1.ProxyBackendTLS{
			TrustClass:     f.trustClass,
			MtlsClientCert: f.mtlsClientCert,
		},
		MaxIdleConnsPerHost:  int32(f.maxIdlePerHost),
		IdleConnTimeoutNanos: int64(f.idleConnTimeout),
	}, nil
}

// parseBackend parses a --backend entry of the form URL or URL=WEIGHT.
// The weight separator is the LAST '=' so URLs containing query strings
// with '=' still parse when no weight is given (weights require the URL
// itself to be free of a trailing =N ambiguity, which holds for the
// http/https backend URLs the engine accepts).
func parseBackend(entry string) (*platformv1.ProxyBackend, error) {
	if entry == "" {
		return nil, &MessageError{Msg: "backend entry must not be empty"}
	}
	if idx := strings.LastIndex(entry, "="); idx > 0 {
		weightStr := entry[idx+1:]
		if weight, err := strconv.Atoi(weightStr); err == nil {
			if weight < 0 {
				return nil, &MessageError{Msg: "backend weight must not be negative: " + entry}
			}
			return &platformv1.ProxyBackend{
				Url:    entry[:idx],
				Weight: int32(weight),
			}, nil
		}
	}
	return &platformv1.ProxyBackend{Url: entry}, nil
}

// NewPoolCommand creates the pool subcommand for managing backend pools.
func NewPoolCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pool",
		Short: "Proxy backend pool operations",
		Long: `Manage reverse-proxy backend pools.

A pool is a set of backends sharing one pooled transport. Pools that are
referenced by routes cannot be deleted.

Examples:
  # Add a pool with two weighted backends
  platformctl proxy pool add --id web-pool \
    --backend https://10.0.0.10:8443=2 --backend https://10.0.0.11:8443=1

  # Add a pool with platform trust-class TLS
  platformctl proxy pool add --id api-pool --backend https://api-1:8443 \
    --trust-class platform --mtls-client-cert

  # Inspect, update, delete
  platformctl proxy pool get web-pool
  platformctl proxy pool update --id web-pool --backend https://10.0.0.12:8443
  platformctl proxy pool delete web-pool
  platformctl proxy pool list`,
	}

	cmd.AddCommand(newPoolAddCommand(getFlags))
	cmd.AddCommand(newPoolGetCommand(getFlags))
	cmd.AddCommand(newPoolUpdateCommand(getFlags))
	cmd.AddCommand(newPoolDeleteCommand(getFlags))
	cmd.AddCommand(newPoolListCommand(getFlags))

	return cmd
}

func newPoolAddCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags poolFlags
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a backend pool",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPoolAdd(getFlags(), &flags)
		},
	}
	flags.register(cmd)
	return cmd
}

func runPoolAdd(common *cli.CommonFlags, flags *poolFlags) error {
	if err := flags.validate(); err != nil {
		return err
	}
	pool, err := flags.toProto()
	if err != nil {
		return err
	}
	client, closeFn, err := newProxyClient(common)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := newCLIContext()
	defer cancel()

	created, version, err := client.CreatePool(ctx, pool)
	if err != nil {
		return &WrappedError{Msg: "failed to create proxy pool", Err: err}
	}
	return output(common, map[string]any{"pool": created, "version": version})
}

func newPoolGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Get a backend pool by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPoolGet(getFlags(), args[0])
		},
	}
}

func runPoolGet(common *cli.CommonFlags, id string) error {
	client, closeFn, err := newProxyClient(common)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := newCLIContext()
	defer cancel()

	pool, err := client.GetPool(ctx, id)
	if err != nil {
		return &WrappedError{Msg: "failed to get proxy pool", Err: err}
	}
	return output(common, pool)
}

func newPoolUpdateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags poolFlags
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a backend pool",
		Long: `Replace an existing backend pool. All definition flags describe
the full new pool state (this is a replace, not a patch).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPoolUpdate(getFlags(), &flags)
		},
	}
	flags.register(cmd)
	return cmd
}

func runPoolUpdate(common *cli.CommonFlags, flags *poolFlags) error {
	if err := flags.validate(); err != nil {
		return err
	}
	pool, err := flags.toProto()
	if err != nil {
		return err
	}
	client, closeFn, err := newProxyClient(common)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := newCLIContext()
	defer cancel()

	updated, version, err := client.UpdatePool(ctx, pool)
	if err != nil {
		return &WrappedError{Msg: "failed to update proxy pool", Err: err}
	}
	return output(common, map[string]any{"pool": updated, "version": version})
}

func newPoolDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a backend pool by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPoolDelete(getFlags(), args[0])
		},
	}
}

func runPoolDelete(common *cli.CommonFlags, id string) error {
	client, closeFn, err := newProxyClient(common)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := newCLIContext()
	defer cancel()

	version, err := client.DeletePool(ctx, id)
	if err != nil {
		return &WrappedError{Msg: "failed to delete proxy pool", Err: err}
	}
	return output(common, map[string]any{"deleted": id, "version": version})
}

func newPoolListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List backend pools",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPoolList(getFlags())
		},
	}
}

func runPoolList(common *cli.CommonFlags) error {
	client, closeFn, err := newProxyClient(common)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := newCLIContext()
	defer cancel()

	pools, version, err := client.ListPools(ctx)
	if err != nil {
		return &WrappedError{Msg: "failed to list proxy pools", Err: err}
	}
	return output(common, map[string]any{"pools": pools, "version": version})
}
