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
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// routeFlags collects the flag values shared by route add and update.
type routeFlags struct {
	id                string
	hosts             []string
	pathPrefix        string
	pool              string
	authMode          string
	requireIDevID     bool
	allowedZones      []string
	backendZone       string
	requireAttest     bool
	attestationMaxAge time.Duration
	requiredRoles     []string
	requiredScopes    []string
	opaPolicy         string
	stripPrefix       bool
	preserveHost      bool
}

// register binds the route flags onto cmd.
func (f *routeFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.id, "id", "", "Route identifier (required)")
	cmd.Flags().StringSliceVar(&f.hosts, "host", nil, "Exact host to match (repeatable; empty matches any host)")
	cmd.Flags().StringVar(&f.pathPrefix, "path-prefix", "/", "Path prefix to match (must start with /)")
	cmd.Flags().StringVar(&f.pool, "pool", "", "Backend pool ID (required)")
	cmd.Flags().StringVar(&f.authMode, "auth-mode", "", "Auth mode: public, mtls, token, mtls-or-token (required)")
	cmd.Flags().BoolVar(&f.requireIDevID, "require-idevid", false, "Require an IDevID-backed client certificate")
	cmd.Flags().StringSliceVar(&f.allowedZones, "allowed-zone", nil, "SDN zone allowed to reach this route (repeatable)")
	cmd.Flags().StringVar(&f.backendZone, "backend-zone", "", "SDN zone the backend pool lives in")
	cmd.Flags().BoolVar(&f.requireAttest, "require-attestation", false, "Require fresh workload attestation")
	cmd.Flags().DurationVar(&f.attestationMaxAge, "attestation-max-age", 0, "Maximum accepted attestation age (e.g. 5m)")
	cmd.Flags().StringSliceVar(&f.requiredRoles, "required-role", nil, "Role required on the caller (repeatable)")
	cmd.Flags().StringSliceVar(&f.requiredScopes, "required-scope", nil, "Token scope required on the caller (repeatable)")
	cmd.Flags().StringVar(&f.opaPolicy, "opa-policy", "", "OPA policy reference evaluated for this route")
	cmd.Flags().BoolVar(&f.stripPrefix, "strip-prefix", false, "Strip the matched path prefix before forwarding")
	cmd.Flags().BoolVar(&f.preserveHost, "preserve-host", false, "Preserve the inbound Host header")
}

// toProto builds the platform.v1 ProxyRoute from the flag values.
func (f *routeFlags) toProto() *platformv1.ProxyRoute {
	return &platformv1.ProxyRoute{
		Id:         f.id,
		Hosts:      f.hosts,
		PathPrefix: f.pathPrefix,
		PoolId:     f.pool,
		Auth: &platformv1.ProxyAuthRequirements{
			Mode:                   f.authMode,
			RequireIdevid:          f.requireIDevID,
			AllowedZones:           f.allowedZones,
			BackendZone:            f.backendZone,
			RequireAttestation:     f.requireAttest,
			AttestationMaxAgeNanos: int64(f.attestationMaxAge),
			RequiredRoles:          f.requiredRoles,
			RequiredScopes:         f.requiredScopes,
			OpaPolicy:              f.opaPolicy,
		},
		StripPrefix:  f.stripPrefix,
		PreserveHost: f.preserveHost,
	}
}

// validate checks the required route flags.
func (f *routeFlags) validate() error {
	if f.id == "" {
		return &MessageError{Msg: "--id is required"}
	}
	if f.pool == "" {
		return &MessageError{Msg: "--pool is required"}
	}
	if f.authMode == "" {
		return &MessageError{Msg: "--auth-mode is required (public, mtls, token, mtls-or-token)"}
	}
	return nil
}

// NewRouteCommand creates the route subcommand for managing proxy routes.
func NewRouteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "route",
		Short: "Proxy route operations",
		Long: `Manage reverse-proxy routes.

Routes map inbound host/path pairs to a backend pool with per-route
authentication requirements. Every mutation re-validates the full
configuration and bumps the config version.

Examples:
  # Add a public route
  platformctl proxy route add --id web --path-prefix / --pool web-pool --auth-mode public

  # Add an mTLS route restricted to the trusted zone
  platformctl proxy route add --id api --host api.example.com --path-prefix /api \
    --pool api-pool --auth-mode mtls --allowed-zone trusted --strip-prefix

  # Inspect, update, delete
  platformctl proxy route get api
  platformctl proxy route update --id api --pool api-pool-v2 --auth-mode mtls
  platformctl proxy route delete api
  platformctl proxy route list`,
	}

	cmd.AddCommand(newRouteAddCommand(getFlags))
	cmd.AddCommand(newRouteGetCommand(getFlags))
	cmd.AddCommand(newRouteUpdateCommand(getFlags))
	cmd.AddCommand(newRouteDeleteCommand(getFlags))
	cmd.AddCommand(newRouteListCommand(getFlags))

	return cmd
}

func newRouteAddCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags routeFlags
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a proxy route",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRouteAdd(getFlags(), &flags)
		},
	}
	flags.register(cmd)
	return cmd
}

func runRouteAdd(common *cli.CommonFlags, flags *routeFlags) error {
	if err := flags.validate(); err != nil {
		return err
	}
	client, closeFn, err := newProxyClient(common)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := newCLIContext()
	defer cancel()

	route, version, err := client.CreateRoute(ctx, flags.toProto())
	if err != nil {
		return &WrappedError{Msg: "failed to create proxy route", Err: err}
	}
	return output(common, map[string]any{"route": route, "version": version})
}

func newRouteGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Get a proxy route by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRouteGet(getFlags(), args[0])
		},
	}
}

func runRouteGet(common *cli.CommonFlags, id string) error {
	client, closeFn, err := newProxyClient(common)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := newCLIContext()
	defer cancel()

	route, err := client.GetRoute(ctx, id)
	if err != nil {
		return &WrappedError{Msg: "failed to get proxy route", Err: err}
	}
	return output(common, route)
}

func newRouteUpdateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags routeFlags
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a proxy route",
		Long: `Replace an existing proxy route. All definition flags describe
the full new route state (this is a replace, not a patch).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRouteUpdate(getFlags(), &flags)
		},
	}
	flags.register(cmd)
	return cmd
}

func runRouteUpdate(common *cli.CommonFlags, flags *routeFlags) error {
	if err := flags.validate(); err != nil {
		return err
	}
	client, closeFn, err := newProxyClient(common)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := newCLIContext()
	defer cancel()

	route, version, err := client.UpdateRoute(ctx, flags.toProto())
	if err != nil {
		return &WrappedError{Msg: "failed to update proxy route", Err: err}
	}
	return output(common, map[string]any{"route": route, "version": version})
}

func newRouteDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a proxy route by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRouteDelete(getFlags(), args[0])
		},
	}
}

func runRouteDelete(common *cli.CommonFlags, id string) error {
	client, closeFn, err := newProxyClient(common)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := newCLIContext()
	defer cancel()

	version, err := client.DeleteRoute(ctx, id)
	if err != nil {
		return &WrappedError{Msg: "failed to delete proxy route", Err: err}
	}
	return output(common, map[string]any{"deleted": id, "version": version})
}

func newRouteListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List proxy routes",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRouteList(getFlags())
		},
	}
}

func runRouteList(common *cli.CommonFlags) error {
	client, closeFn, err := newProxyClient(common)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := newCLIContext()
	defer cancel()

	routes, version, err := client.ListRoutes(ctx)
	if err != nil {
		return &WrappedError{Msg: "failed to list proxy routes", Err: err}
	}
	return output(common, map[string]any{"routes": routes, "version": version})
}
