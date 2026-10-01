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
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdnsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/sdn"
)

// NewZoneCommand creates the zone subcommand for managing the underlay
// zones of the reference network.
func NewZoneCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "zone",
		Short: "Network zone operations",
		Long: `Manage the underlay zones of the reference network.

Every environment has nine built-in zones at fixed offsets (transit,
fabric, management, hypervisor, quarantine, provisioning, control-plane,
storage, backup). Their policy can be tuned; their numbering cannot.
Owner-defined zones take offsets 9-99 and join the gateway and/or
hypervisor port class. Overlays (platform, tenant, public) are not zones.

Every mutation re-validates the whole zone set and its numbering, and
reports restart_required: the network plan is derived at daemon startup.

Examples:
  # List all zones with their VLAN and subnets
  platformctl sdn zone list

  # Create an owner-defined zone at offset 9 on the hypervisor trunk
  platformctl sdn zone create --name lab --offset 9 --port-class hypervisor --isolate

  # Tune a built-in zone's policy
  platformctl sdn zone update --name storage --isolate --allow-to storage:nvme-tcp

  # Delete an owner-defined zone (or omit an optional built-in)
  platformctl sdn zone delete --name lab`,
	}

	cmd.AddCommand(newZoneListCommand(getFlags))
	cmd.AddCommand(newZoneCreateCommand(getFlags))
	cmd.AddCommand(newZoneUpdateCommand(getFlags))
	cmd.AddCommand(newZoneDeleteCommand(getFlags))

	return cmd
}

// ErrInvalidAllowTo is returned when an --allow-to value is not
// "zone" or "zone:service[,service...]".
type ErrInvalidAllowTo struct {
	// Value is the rejected flag value.
	Value string
}

// Error implements the error interface.
func (e *ErrInvalidAllowTo) Error() string {
	return fmt.Sprintf("invalid --allow-to %q: want zone or zone:service[,service...]", e.Value)
}

// ErrIncompletePrivilegedAccess is returned when only one of --reason and
// --approved-by is set.
type ErrIncompletePrivilegedAccess struct{}

// Error implements the error interface.
func (e *ErrIncompletePrivilegedAccess) Error() string {
	return "--reason and --approved-by must be set together (privileged_access)"
}

// zoneFlags holds the zone fields shared by create and update.
type zoneFlags struct {
	name            string
	offset          uint8
	portClasses     []string
	internetIngress bool
	isolateFrom     []string
	allowTo         []string
	services        []string
	isolate         bool
	oob             bool
	lifecycleRole   string
	reason          string
	approvedBy      string
}

// register adds the zone flags to cmd.
func (f *zoneFlags) register(cmd *cobra.Command, nameHelp string) {
	cmd.Flags().StringVar(&f.name, "name", "", nameHelp)
	cmd.Flags().Uint8Var(&f.offset, "offset", 0, "Offset in the environment block (owner-defined zones: 9-99; built-in offsets are fixed)")
	cmd.Flags().StringSliceVar(&f.portClasses, "port-class", nil, "Port class carrying the zone, repeatable (owner-defined zones: gateway, hypervisor)")
	cmd.Flags().BoolVar(&f.internetIngress, "internet-ingress", false, "Zone accepts internet ingress traffic")
	cmd.Flags().StringSliceVar(&f.isolateFrom, "isolate-from", nil, "Zone this zone never sends to, repeatable")
	cmd.Flags().StringArrayVar(&f.allowTo, "allow-to", nil, "Allowed path, repeatable: zone or zone:service[,service...]")
	cmd.Flags().StringSliceVar(&f.services, "service", nil, "Service permitted inside the zone, repeatable")
	cmd.Flags().BoolVar(&f.isolate, "isolate", false, "Deny all traffic except the --allow-to paths")
	cmd.Flags().BoolVar(&f.oob, "oob", false, "Out-of-band management zone (built-in management only)")
	cmd.Flags().StringVar(&f.lifecycleRole, "lifecycle-role", "", "Lifecycle role (built-in provisioning and quarantine only)")
	cmd.Flags().StringVar(&f.reason, "reason", "", "privileged_access reason: why a path into control-plane or management is needed")
	cmd.Flags().StringVar(&f.approvedBy, "approved-by", "", "privileged_access approver")
	cmd.MarkFlagRequired("name")
}

// config builds the proto zone config from the flags.
func (f *zoneFlags) config() (*platformv1.NetworkZoneConfig, error) {
	cfg := &platformv1.NetworkZoneConfig{
		Name:            f.name,
		Offset:          uint32(f.offset),
		PortClasses:     f.portClasses,
		InternetIngress: f.internetIngress,
		IsolateFrom:     f.isolateFrom,
		Services:        f.services,
		Isolate:         f.isolate,
		Oob:             f.oob,
		LifecycleRole:   f.lifecycleRole,
	}
	for _, v := range f.allowTo {
		path, err := parseAllowTo(v)
		if err != nil {
			return nil, err
		}
		cfg.AllowTo = append(cfg.AllowTo, path)
	}
	switch {
	case f.reason != "" && f.approvedBy != "":
		cfg.PrivilegedAccess = &platformv1.NetworkZonePrivilegedAccess{Reason: f.reason, ApprovedBy: f.approvedBy}
	case f.reason != "" || f.approvedBy != "":
		return nil, &ErrIncompletePrivilegedAccess{}
	}
	return cfg, nil
}

// parseAllowTo parses "zone" or "zone:service[,service...]". --allow-to is
// a string array (not comma split), so each flag value is one path.
func parseAllowTo(v string) (*platformv1.NetworkZonePath, error) {
	zone, services, hasServices := strings.Cut(v, ":")
	zone = strings.TrimSpace(zone)
	if zone == "" {
		return nil, &ErrInvalidAllowTo{Value: v}
	}
	path := &platformv1.NetworkZonePath{Zone: zone}
	if !hasServices {
		return path, nil
	}
	for _, s := range strings.Split(services, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, &ErrInvalidAllowTo{Value: v}
		}
		path.Services = append(path.Services, s)
	}
	return path, nil
}

func newZoneListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var lifecycleRole string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List network zones",
		Long: `List the underlay zones with their policy and, when the node has an
sdn.environment, their derived numbering (VLAN, IPv4 and IPv6 subnets,
gateway).

Examples:
  platformctl sdn zone list
  platformctl sdn zone list --lifecycle-role provisioning
  platformctl sdn zone list -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runZoneList(getFlags(), lifecycleRole)
		},
	}

	cmd.Flags().StringVar(&lifecycleRole, "lifecycle-role", "", "Filter by lifecycle role (provisioning, quarantine)")

	return cmd
}

func newZoneCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var f zoneFlags

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an owner-defined zone",
		Long: `Create an owner-defined underlay zone at offset 9-99.

The zone gets its own VLAN, /24 and ULA /64, derived from its offset. A
path into control-plane or management needs --reason and --approved-by
(an audited privileged_access override).

Examples:
  platformctl sdn zone create --name lab --offset 9 --port-class hypervisor --isolate
  platformctl sdn zone create --name lab --offset 9 --port-class gateway \
    --allow-to control-plane:dns --reason "lab resolver" --approved-by owner`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runZoneCreate(getFlags(), &f)
		},
	}

	f.register(cmd, "Zone name (required)")
	return cmd
}

func newZoneUpdateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var f zoneFlags

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a network zone",
		Long: `Tune a built-in zone's policy or replace an owner-defined zone.

The flags replace the zone's policy as a whole. A built-in keeps its
offset, port classes, lifecycle role and OOB flag; changing them is refused.

Examples:
  platformctl sdn zone update --name storage --isolate --allow-to storage:nvme-tcp
  platformctl sdn zone update --name lab --offset 20 --port-class hypervisor`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runZoneUpdate(getFlags(), &f)
		},
	}

	f.register(cmd, "Zone name to update (required)")
	return cmd
}

func newZoneDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var name string

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a network zone",
		Long: `Delete an owner-defined zone, or omit an optional built-in zone.

fabric, provisioning, quarantine and control-plane cannot be removed.

Examples:
  platformctl sdn zone delete --name lab`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runZoneDelete(getFlags(), name)
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Zone name to delete (required)")
	cmd.MarkFlagRequired("name")

	return cmd
}

// Implementation functions

func runZoneList(flags *cli.CommonFlags, lifecycleRole string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdnClient := sdnsvc.NewClientFromGRPC(base.Client().SDN())

	ctx, cancel := newCLIContext()
	defer cancel()

	zones, err := sdnClient.ListNetworkZones(ctx, lifecycleRole)
	if err != nil {
		return &WrappedError{Msg: "failed to list network zones", Err: err}
	}

	return base.Output(zones)
}

func runZoneCreate(flags *cli.CommonFlags, f *zoneFlags) error {
	cfg, err := f.config()
	if err != nil {
		return err
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdnClient := sdnsvc.NewClientFromGRPC(base.Client().SDN())

	ctx, cancel := newCLIContext()
	defer cancel()

	z, err := sdnClient.CreateNetworkZone(ctx, &platformv1.CreateNetworkZoneRequest{Config: cfg})
	if err != nil {
		return &WrappedError{Msg: "failed to create network zone", Err: err}
	}

	return base.Output(z)
}

func runZoneUpdate(flags *cli.CommonFlags, f *zoneFlags) error {
	cfg, err := f.config()
	if err != nil {
		return err
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdnClient := sdnsvc.NewClientFromGRPC(base.Client().SDN())

	ctx, cancel := newCLIContext()
	defer cancel()

	z, err := sdnClient.UpdateNetworkZone(ctx, &platformv1.UpdateNetworkZoneRequest{Name: f.name, Config: cfg})
	if err != nil {
		return &WrappedError{Msg: "failed to update network zone", Err: err}
	}

	return base.Output(z)
}

func runZoneDelete(flags *cli.CommonFlags, name string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdnClient := sdnsvc.NewClientFromGRPC(base.Client().SDN())

	ctx, cancel := newCLIContext()
	defer cancel()

	restartRequired, err := sdnClient.DeleteNetworkZone(ctx, name)
	if err != nil {
		return &WrappedError{Msg: "failed to delete network zone", Err: err}
	}

	if restartRequired {
		fmt.Printf("Network zone %q deleted. Daemon restart required to re-derive the network plan.\n", name)
	} else {
		fmt.Printf("Network zone %q deleted successfully.\n", name)
	}
	return nil
}
