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

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdnsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/sdn"
)

// NewZoneCommand creates the zone subcommand for managing SDN network trust zones.
func NewZoneCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "zone",
		Short: "Network zone operations",
		Long: `Manage SDN network trust zones.

Zones define trust and exposure classes for network segments.
Every mutation re-validates the full zone set; lifecycle-role holders
(provisioning, quarantine) cannot be deleted without a replacement.

Examples:
  # List all zones
  platformctl sdn zone list

  # Create a zone
  platformctl sdn zone create --name dmz --internet-ingress --isolate

  # Update a zone
  platformctl sdn zone update --name dmz --isolate-per-tenant

  # Delete a zone
  platformctl sdn zone delete --name dmz

  # Assign a network to a zone
  platformctl sdn zone assign --network corp-lan --zone trusted`,
	}

	cmd.AddCommand(newZoneListCommand(getFlags))
	cmd.AddCommand(newZoneCreateCommand(getFlags))
	cmd.AddCommand(newZoneUpdateCommand(getFlags))
	cmd.AddCommand(newZoneDeleteCommand(getFlags))
	cmd.AddCommand(newZoneAssignCommand(getFlags))

	return cmd
}

func newZoneListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var lifecycleRole string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List network zones",
		Long: `List all SDN network trust zones.

Optionally filter by lifecycle role.

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
	var (
		name             string
		internetIngress  bool
		isolate          bool
		isolatePerTenant bool
		oob              bool
		lifecycleRole    string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a network zone",
		Long: `Create a new SDN network trust zone.

Every zone create re-validates the full zone set. Duplicate names are rejected.

Examples:
  platformctl sdn zone create --name dmz --internet-ingress
  platformctl sdn zone create --name iot --isolate --isolate-per-tenant
  platformctl sdn zone create --name staging --lifecycle-role provisioning`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runZoneCreate(getFlags(), name, internetIngress, isolate, isolatePerTenant, oob, lifecycleRole)
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Zone name (required)")
	cmd.Flags().BoolVar(&internetIngress, "internet-ingress", false, "Zone accepts internet ingress traffic")
	cmd.Flags().BoolVar(&isolate, "isolate", false, "Fully isolate zone from all others")
	cmd.Flags().BoolVar(&isolatePerTenant, "isolate-per-tenant", false, "Isolate tenants within the zone from each other")
	cmd.Flags().BoolVar(&oob, "oob", false, "Out-of-band management zone")
	cmd.Flags().StringVar(&lifecycleRole, "lifecycle-role", "", "Lifecycle role (provisioning, quarantine)")
	cmd.MarkFlagRequired("name")

	return cmd
}

func newZoneUpdateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		name             string
		internetIngress  bool
		isolate          bool
		isolatePerTenant bool
		oob              bool
		lifecycleRole    string
	)

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a network zone",
		Long: `Update the policy settings of an existing SDN network trust zone.

Policy-relevant changes (isolate, oob, allow_to, isolate_from) set restart_required
in the response because the flow matrix must be rebuilt.

Examples:
  platformctl sdn zone update --name dmz --isolate-per-tenant
  platformctl sdn zone update --name mgmt --oob`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runZoneUpdate(getFlags(), name, internetIngress, isolate, isolatePerTenant, oob, lifecycleRole)
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Zone name to update (required)")
	cmd.Flags().BoolVar(&internetIngress, "internet-ingress", false, "Zone accepts internet ingress traffic")
	cmd.Flags().BoolVar(&isolate, "isolate", false, "Fully isolate zone from all others")
	cmd.Flags().BoolVar(&isolatePerTenant, "isolate-per-tenant", false, "Isolate tenants within the zone from each other")
	cmd.Flags().BoolVar(&oob, "oob", false, "Out-of-band management zone")
	cmd.Flags().StringVar(&lifecycleRole, "lifecycle-role", "", "Lifecycle role (provisioning, quarantine)")
	cmd.MarkFlagRequired("name")

	return cmd
}

func newZoneDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var name string

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a network zone",
		Long: `Delete a network trust zone by name.

Deletion fails if the zone is the sole holder of a required lifecycle role
(provisioning or quarantine) and no replacement has been created.

Examples:
  platformctl sdn zone delete --name dmz`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runZoneDelete(getFlags(), name)
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Zone name to delete (required)")
	cmd.MarkFlagRequired("name")

	return cmd
}

func newZoneAssignCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var network, zoneName string

	cmd := &cobra.Command{
		Use:   "assign",
		Short: "Assign a network to a zone",
		Long: `Assign a named network segment to a trust zone.

Returns restart_required=true when the flow matrix must be rebuilt.

Examples:
  platformctl sdn zone assign --network corp-lan --zone trusted
  platformctl sdn zone assign --network dev-wifi --zone tenant`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runZoneAssign(getFlags(), network, zoneName)
		},
	}

	cmd.Flags().StringVar(&network, "network", "", "Network segment name (required)")
	cmd.Flags().StringVar(&zoneName, "zone", "", "Target trust zone name (required)")
	cmd.MarkFlagRequired("network")
	cmd.MarkFlagRequired("zone")

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

func runZoneCreate(flags *cli.CommonFlags, name string, internetIngress, isolate, isolatePerTenant, oob bool, lifecycleRole string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdnClient := sdnsvc.NewClientFromGRPC(base.Client().SDN())

	ctx, cancel := newCLIContext()
	defer cancel()

	req := &platformv1.CreateNetworkZoneRequest{
		Config: &platformv1.NetworkZoneConfig{
			Name:             name,
			InternetIngress:  internetIngress,
			Isolate:          isolate,
			IsolatePerTenant: isolatePerTenant,
			Oob:              oob,
			LifecycleRole:    lifecycleRole,
		},
	}

	z, err := sdnClient.CreateNetworkZone(ctx, req)
	if err != nil {
		return &WrappedError{Msg: "failed to create network zone", Err: err}
	}

	return base.Output(z)
}

func runZoneUpdate(flags *cli.CommonFlags, name string, internetIngress, isolate, isolatePerTenant, oob bool, lifecycleRole string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdnClient := sdnsvc.NewClientFromGRPC(base.Client().SDN())

	ctx, cancel := newCLIContext()
	defer cancel()

	req := &platformv1.UpdateNetworkZoneRequest{
		Name: name,
		Config: &platformv1.NetworkZoneConfig{
			Name:             name,
			InternetIngress:  internetIngress,
			Isolate:          isolate,
			IsolatePerTenant: isolatePerTenant,
			Oob:              oob,
			LifecycleRole:    lifecycleRole,
		},
	}

	z, err := sdnClient.UpdateNetworkZone(ctx, req)
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
		fmt.Printf("Network zone %q deleted. Daemon restart required to rebuild flow matrix.\n", name)
	} else {
		fmt.Printf("Network zone %q deleted successfully.\n", name)
	}
	return nil
}

func runZoneAssign(flags *cli.CommonFlags, network, zoneName string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdnClient := sdnsvc.NewClientFromGRPC(base.Client().SDN())

	ctx, cancel := newCLIContext()
	defer cancel()

	restartRequired, err := sdnClient.AssignNetworkZone(ctx, network, zoneName)
	if err != nil {
		return &WrappedError{Msg: "failed to assign network zone", Err: err}
	}

	if restartRequired {
		fmt.Printf("Network %q assigned to zone %q. Daemon restart required to rebuild flow matrix.\n", network, zoneName)
	} else {
		fmt.Printf("Network %q assigned to zone %q successfully.\n", network, zoneName)
	}
	return nil
}
