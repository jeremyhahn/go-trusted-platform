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

package sdn

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gateway"
)

// ErrInvalidBackendSpec is returned when a --backend flag value is not in
// the addr:port[:weight] form.
type ErrInvalidBackendSpec struct {
	Spec string
}

// Error implements the error interface.
func (e *ErrInvalidBackendSpec) Error() string {
	return fmt.Sprintf("invalid backend %q: expected address:port[:weight]", e.Spec)
}

// newGatewayLBCommand creates the load balancer subcommand tree.
func newGatewayLBCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lb",
		Short: "Load balancer operations",
		Long: `Manage the OVS-native L4 load balancer.

VIP traffic is distributed across backends with an OpenFlow select group
(hash-based selection, per-connection sticky via conntrack) and DNAT
applied in the datapath.

Examples:
  # Show load balancer health
  platformctl sdn gateway lb status

  # Add a VIP with two weighted backends
  platformctl sdn gateway lb vip add --protocol tcp --address 10.100.0.10 --port 443 \
    --backend 10.0.1.5:8443:2 --backend 10.0.1.6:8443

  # List, inspect, and remove VIPs
  platformctl sdn gateway lb vip list
  platformctl sdn gateway lb vip get --protocol tcp --address 10.100.0.10 --port 443
  platformctl sdn gateway lb vip remove --protocol tcp --address 10.100.0.10 --port 443`,
	}

	cmd.AddCommand(newGatewayLBStatusCommand(getFlags))
	cmd.AddCommand(newGatewayLBVIPCommand(getFlags))

	return cmd
}

// newGatewayLBStatusCommand creates the "lb status" command.
func newGatewayLBStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Get load balancer status",
		Long: `Display the load balancer service health.

Shows the active state, VIP count, and healthy/total backend counts.

Examples:
  platformctl sdn gateway lb status
  platformctl sdn gateway lb status -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLBStatus(getFlags())
		},
	}
}

// vipTargetFlags binds the shared --protocol/--address/--port flags.
type vipTargetFlags struct {
	protocol string
	address  string
	port     uint16
}

// register adds the target flags to a command and marks them required.
func (f *vipTargetFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.protocol, "protocol", "tcp", "VIP protocol: tcp or udp")
	cmd.Flags().StringVar(&f.address, "address", "", "Virtual IPv4 address (required)")
	cmd.Flags().Uint16Var(&f.port, "port", 0, "Virtual L4 port (required)")
	requireFlag(cmd, "address")
	requireFlag(cmd, "port")
}

// requireFlag marks a flag the command just registered as required. Cobra
// fails only when no flag of that name exists, which is a programming error
// in the command tree, so it panics while the tree is being built rather
// than shipping a command whose required flag is silently optional.
func requireFlag(cmd *cobra.Command, name string) {
	if err := cmd.MarkFlagRequired(name); err != nil {
		panic(fmt.Sprintf("failed to mark %s flag required on %q: %v", name, cmd.Name(), err))
	}
}

// newGatewayLBVIPCommand creates the "lb vip" command tree.
func newGatewayLBVIPCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vip",
		Short: "VIP management",
		Long:  "Add, remove, list, and inspect load-balanced virtual IPs",
	}

	// vip add
	addTarget := &vipTargetFlags{}
	var algorithm string
	var addBackends []string
	addCmd := &cobra.Command{
		Use:   "add",
		Short: "Add a VIP",
		Long: `Install a load-balanced virtual IP.

Backends are given as address:port or address:port:weight (weight defaults
to 1). Selection is hash-based ("hash" and "round-robin" both map to
select-group dp_hash balancing); "least-conn" is not supported by the OVS
datapath.

Examples:
  platformctl sdn gateway lb vip add --protocol tcp --address 10.100.0.10 --port 443 \
    --backend 10.0.1.5:8443:2 --backend 10.0.1.6:8443`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLBVIPAdd(getFlags(), addTarget, algorithm, addBackends)
		},
	}
	addTarget.register(addCmd)
	addCmd.Flags().StringVar(&algorithm, "algorithm", "", "Balancing algorithm: hash or round-robin (default: service algorithm)")
	addCmd.Flags().StringArrayVar(&addBackends, "backend", nil, "Backend as address:port[:weight]; repeatable (required)")
	requireFlag(addCmd, "backend")

	// vip remove
	removeTarget := &vipTargetFlags{}
	removeCmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a VIP",
		Long: `Tear down a load-balanced virtual IP.

Examples:
  platformctl sdn gateway lb vip remove --protocol tcp --address 10.100.0.10 --port 443`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLBVIPRemove(getFlags(), removeTarget)
		},
	}
	removeTarget.register(removeCmd)

	// vip get
	getTarget := &vipTargetFlags{}
	getCmd := &cobra.Command{
		Use:   "get",
		Short: "Get a VIP",
		Long: `Display one VIP's status including per-backend health.

Examples:
  platformctl sdn gateway lb vip get --protocol tcp --address 10.100.0.10 --port 443`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLBVIPGet(getFlags(), getTarget)
		},
	}
	getTarget.register(getCmd)

	// vip list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List VIPs",
		Long: `List every load-balanced virtual IP.

Examples:
  platformctl sdn gateway lb vip list
  platformctl sdn gateway lb vip list -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLBVIPList(getFlags())
		},
	}

	// vip set-backends
	setTarget := &vipTargetFlags{}
	var setBackends []string
	setCmd := &cobra.Command{
		Use:   "set-backends",
		Short: "Replace a VIP's backends",
		Long: `Replace the backend set of a load-balanced virtual IP.

Examples:
  platformctl sdn gateway lb vip set-backends --protocol tcp --address 10.100.0.10 --port 443 \
    --backend 10.0.1.7:8443 --backend 10.0.1.8:8443:3`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLBVIPSetBackends(getFlags(), setTarget, setBackends)
		},
	}
	setTarget.register(setCmd)
	setCmd.Flags().StringArrayVar(&setBackends, "backend", nil, "Backend as address:port[:weight]; repeatable (required)")
	requireFlag(setCmd, "backend")

	cmd.AddCommand(addCmd, removeCmd, getCmd, listCmd, setCmd)
	return cmd
}

// parseBackendSpecs converts --backend flag values (address:port[:weight])
// into proto backends.
func parseBackendSpecs(specs []string) ([]*platformv1.VIPBackend, error) {
	backends := make([]*platformv1.VIPBackend, 0, len(specs))
	for _, spec := range specs {
		parts := strings.Split(spec, ":")
		if len(parts) < 2 || len(parts) > 3 {
			return nil, &ErrInvalidBackendSpec{Spec: spec}
		}
		port, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil || port == 0 {
			return nil, &ErrInvalidBackendSpec{Spec: spec}
		}
		backend := &platformv1.VIPBackend{
			Address: parts[0],
			Port:    uint32(port),
		}
		if len(parts) == 3 {
			weight, err := strconv.ParseUint(parts[2], 10, 16)
			if err != nil {
				return nil, &ErrInvalidBackendSpec{Spec: spec}
			}
			backend.Weight = uint32(weight)
		}
		backends = append(backends, backend)
	}
	return backends, nil
}

// runLBStatus fetches and prints the load balancer health.
func runLBStatus(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := gatewayClient.GetLBStatus(ctx)
	if err != nil {
		return &WrappedError{Msg: "failed to get load balancer status", Err: err}
	}

	return base.Output(resp)
}

// runLBVIPAdd installs a VIP.
func runLBVIPAdd(flags *cli.CommonFlags, target *vipTargetFlags, algorithm string, backendSpecs []string) error {
	backends, err := parseBackendSpecs(backendSpecs)
	if err != nil {
		return err
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := gatewayClient.AddVIP(ctx, &platformv1.VIPConfig{
		Address:   target.address,
		Port:      uint32(target.port),
		Protocol:  target.protocol,
		Algorithm: algorithm,
		Backends:  backends,
	})
	if err != nil {
		return &WrappedError{Msg: "failed to add VIP", Err: err}
	}

	return base.Output(resp)
}

// runLBVIPRemove tears down a VIP.
func runLBVIPRemove(flags *cli.CommonFlags, target *vipTargetFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	if err := gatewayClient.RemoveVIP(ctx, target.protocol, target.address, uint32(target.port)); err != nil {
		return &WrappedError{Msg: "failed to remove VIP", Err: err}
	}

	fmt.Printf("VIP %s/%s:%d removed successfully\n", target.protocol, target.address, target.port)
	return nil
}

// runLBVIPGet fetches one VIP.
func runLBVIPGet(flags *cli.CommonFlags, target *vipTargetFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := gatewayClient.GetVIP(ctx, target.protocol, target.address, uint32(target.port))
	if err != nil {
		return &WrappedError{Msg: "failed to get VIP", Err: err}
	}

	return base.Output(resp)
}

// runLBVIPList lists every VIP.
func runLBVIPList(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := gatewayClient.ListVIPs(ctx)
	if err != nil {
		return &WrappedError{Msg: "failed to list VIPs", Err: err}
	}

	return base.Output(resp)
}

// runLBVIPSetBackends replaces a VIP's backend set.
func runLBVIPSetBackends(flags *cli.CommonFlags, target *vipTargetFlags, backendSpecs []string) error {
	backends, err := parseBackendSpecs(backendSpecs)
	if err != nil {
		return err
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := gatewayClient.SetVIPBackends(ctx, target.protocol, target.address, uint32(target.port), backends)
	if err != nil {
		return &WrappedError{Msg: "failed to set VIP backends", Err: err}
	}

	return base.Output(resp)
}
