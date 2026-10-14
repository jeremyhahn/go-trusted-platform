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

// Package vpn implements `platformctl vpn`, the operator commands of the
// management-VPN control plane: peer enrolment, gateway session status and
// tenant posture policies. Every command goes through the SDK VPN client, so
// it runs over whichever protocol the global --protocol flag selects.
package vpn

import (
	"context"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	vpnsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/vpn"
)

// defaultCLITimeout bounds every VPN RPC issued by the CLI.
const defaultCLITimeout = 30 * time.Second

// newCLIContext returns a context bounded by defaultCLITimeout.
func newCLIContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), defaultCLITimeout)
}

// vpnClient is the SDK VPN client surface the commands use. It is satisfied
// by *vpnsvc.Client and by test fakes.
type vpnClient interface {
	EnrolPeer(ctx context.Context, tenantID, deviceID string, zones []string) (*platformv1.VPNPeer, error)
	ListPeers(ctx context.Context, tenantID string) ([]*platformv1.VPNPeer, error)
	RevokePeer(ctx context.Context, tenantID, deviceID string) error
	Status(ctx context.Context, gatewayID string) ([]*platformv1.VPNGatewayStatus, error)
	GetPosturePolicy(ctx context.Context, tenantID, name string) (*platformv1.VPNPosturePolicy, error)
	SetPosturePolicy(ctx context.Context, tenantID, name, module string) (*platformv1.VPNPosturePolicy, error)
	DeletePosturePolicy(ctx context.Context, tenantID, name string) error
	ListPosturePolicies(ctx context.Context, tenantID string) ([]*platformv1.VPNPosturePolicy, error)
}

// clientFactory builds a VPN client and its cleanup function from the
// global flags.
type clientFactory func(flags *cli.CommonFlags) (vpnClient, func() error, error)

// newVPNClient is the production factory; tests replace it.
var newVPNClient clientFactory = func(flags *cli.CommonFlags) (vpnClient, func() error, error) {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return nil, nil, err
	}
	return vpnsvc.NewClientFromGRPC(base.Client().VPN()), base.Close, nil
}

// outputFunc renders a command result in the selected output format.
type outputFunc func(flags *cli.CommonFlags, v any) error

// output is the production renderer; tests replace it.
var output outputFunc = func(flags *cli.CommonFlags, v any) error {
	return render(os.Stdout, flags, v)
}

// render writes v to w in the selected output format. Printing needs no
// daemon connection, so it does not open one.
func render(w io.Writer, flags *cli.CommonFlags, v any) error {
	return cli.NewPrinterWithWriter(flags.OutputFormat, flags.NoColor, w).Print(v)
}

// NewCommand creates the `platformctl vpn` command tree.
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vpn",
		Short: "Management VPN: connect this device, or administer peers, posture policies and sessions",
		Long: `Connect this device to the management VPN that platform gateways serve, or
administer it.

A device reaches the management network only after it is enrolled as a peer
of its tenant, passes the tenant's posture policies, and presents a valid
platform credential. Enrolment and posture policies are stored by platformd
and reach every gateway in its desired configuration. connect, disconnect
and lease are the client verbs: they talk to a gateway's admission listener,
not to platformd.

Examples:
  # Connect this device, then show its lease
  platformctl vpn connect --gateway gw.example.com:4433 --factor fido2
  platformctl vpn lease

  # Enrol a device, limited to the management zone
  platformctl vpn peer enrol laptop-1 --tenant acme --zone management

  # Enrolled peers and live sessions
  platformctl vpn peer list --tenant acme
  platformctl vpn status

  # Install a posture policy (a Rego module in package vpn.posture)
  platformctl vpn posture-policy set corp --tenant acme --file corp.rego

  # Revoke a device; its sessions end when the gateways apply the change
  platformctl vpn peer revoke laptop-1 --tenant acme`,
	}

	cmd.AddCommand(newPeerCommand(getFlags))
	cmd.AddCommand(newStatusCommand(getFlags))
	cmd.AddCommand(newPosturePolicyCommand(getFlags))
	cmd.AddCommand(newConnectCommand(getFlags))
	cmd.AddCommand(newDisconnectCommand(getFlags))
	cmd.AddCommand(newLeaseCommand(getFlags))
	cmd.AddCommand(newPostureCommand(getFlags))
	cmd.AddCommand(newRenewCommand(getFlags))

	return cmd
}

// newPeerCommand creates `platformctl vpn peer`.
func newPeerCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "peer",
		Short: "Enrol, list and revoke VPN peers",
	}

	var enrolTenant string
	var zones []string
	enrol := &cobra.Command{
		Use:   "enrol <device-id>",
		Short: "Enrol a device as a VPN peer, or replace its zones",
		Long: `Enrol a device as a VPN peer of a tenant. Enrolling an enrolled device
replaces its zones. Without --zone the peer may reach every zone the gateway
allows.

Examples:
  platformctl vpn peer enrol laptop-1 --tenant acme
  platformctl vpn peer enrol laptop-1 --tenant acme --zone management --zone storage`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnrolPeer(getFlags(), enrolTenant, args[0], zones)
		},
	}
	enrol.Flags().StringVar(&enrolTenant, "tenant", "", "tenant the device belongs to (required)")
	enrol.Flags().StringSliceVar(&zones, "zone", nil, "zone the peer may reach (repeatable; default every allowed zone)")
	markRequired(enrol, "tenant")

	var listTenant string
	list := &cobra.Command{
		Use:   "list",
		Short: "List enrolled VPN peers",
		Long: `List the enrolled peers of one tenant, or of every tenant without --tenant.

Examples:
  platformctl vpn peer list
  platformctl vpn peer list --tenant acme -o json`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runListPeers(getFlags(), listTenant)
		},
	}
	list.Flags().StringVar(&listTenant, "tenant", "", "list only this tenant's peers")

	var revokeTenant string
	revoke := &cobra.Command{
		Use:   "revoke <device-id>",
		Short: "Revoke a VPN peer",
		Long: `Remove a device's enrolment. Gateways revoke the device's leases when the
change reaches them.

Examples:
  platformctl vpn peer revoke laptop-1 --tenant acme`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRevokePeer(getFlags(), revokeTenant, args[0])
		},
	}
	revoke.Flags().StringVar(&revokeTenant, "tenant", "", "tenant the device belongs to (required)")
	markRequired(revoke, "tenant")

	cmd.AddCommand(enrol, list, revoke)
	return cmd
}

// newStatusCommand creates `platformctl vpn status`.
func newStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var gateway string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the VPN session state the gateways last reported",
		Long: `Show each gateway's VPN service state, enrolled peer count, live leases,
admission and refusal counters, and posture policies it could not load.
Structured output (-o json|yaml) includes every lease.

Examples:
  platformctl vpn status
  platformctl vpn status --gateway gw-1 -o json`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(getFlags(), gateway)
		},
	}
	cmd.Flags().StringVar(&gateway, "gateway", "", "show only this gateway")
	return cmd
}

// newPosturePolicyCommand creates `platformctl vpn posture-policy`.
func newPosturePolicyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "posture-policy",
		Short: "Manage tenant posture policies",
		Long: `Manage the Rego posture policies a device must pass before a gateway
admits it. A module must compile as package vpn.posture; an invalid module is
refused and nothing is stored.`,
	}

	var listTenant string
	list := &cobra.Command{
		Use:          "list",
		Short:        "List posture policies",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runListPosturePolicies(getFlags(), listTenant)
		},
	}
	list.Flags().StringVar(&listTenant, "tenant", "", "list only this tenant's policies")

	var getTenant string
	get := &cobra.Command{
		Use:          "get <name>",
		Short:        "Show a posture policy and its module",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGetPosturePolicy(getFlags(), getTenant, args[0])
		},
	}
	get.Flags().StringVar(&getTenant, "tenant", "", "tenant that owns the policy (required)")
	markRequired(get, "tenant")

	var setTenant, file string
	set := &cobra.Command{
		Use:   "set <name>",
		Short: "Create or replace a posture policy",
		Long: `Create or replace a tenant posture policy from a Rego module file.

Examples:
  platformctl vpn posture-policy set corp --tenant acme --file corp.rego`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSetPosturePolicy(getFlags(), setTenant, args[0], file)
		},
	}
	set.Flags().StringVar(&setTenant, "tenant", "", "tenant that owns the policy (required)")
	set.Flags().StringVar(&file, "file", "", "Rego module in package vpn.posture (required)")
	markRequired(set, "tenant")
	markRequired(set, "file")

	var deleteTenant string
	del := &cobra.Command{
		Use:          "delete <name>",
		Short:        "Delete a posture policy",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDeletePosturePolicy(getFlags(), deleteTenant, args[0])
		},
	}
	del.Flags().StringVar(&deleteTenant, "tenant", "", "tenant that owns the policy (required)")
	markRequired(del, "tenant")

	cmd.AddCommand(list, get, set, del)
	return cmd
}

// markRequired marks a flag the command just defined as required. It can
// only fail for an undefined flag, which is a programming error.
func markRequired(cmd *cobra.Command, name string) {
	if err := cmd.MarkFlagRequired(name); err != nil {
		panic(err)
	}
}

// withClient runs call against a VPN client bounded by the CLI timeout.
func withClient(flags *cli.CommonFlags, call func(context.Context, vpnClient) error) error {
	client, closeFn, err := newVPNClient(flags)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := newCLIContext()
	defer cancel()
	return call(ctx, client)
}

// runEnrolPeer enrols a device and shows the stored enrolment.
func runEnrolPeer(flags *cli.CommonFlags, tenantID, deviceID string, zones []string) error {
	return withClient(flags, func(ctx context.Context, client vpnClient) error {
		peer, err := client.EnrolPeer(ctx, tenantID, deviceID, zones)
		if err != nil {
			return &WrappedError{Msg: "failed to enrol VPN peer", Err: err}
		}
		if isStructuredOutput(flags) {
			return output(flags, peer)
		}
		return output(flags, peersTable([]*platformv1.VPNPeer{peer}))
	})
}

// runListPeers lists enrolled peers.
func runListPeers(flags *cli.CommonFlags, tenantID string) error {
	return withClient(flags, func(ctx context.Context, client vpnClient) error {
		peers, err := client.ListPeers(ctx, tenantID)
		if err != nil {
			return &WrappedError{Msg: "failed to list VPN peers", Err: err}
		}
		if isStructuredOutput(flags) {
			return output(flags, peers)
		}
		return output(flags, peersTable(peers))
	})
}

// runRevokePeer revokes a peer and confirms it.
func runRevokePeer(flags *cli.CommonFlags, tenantID, deviceID string) error {
	return withClient(flags, func(ctx context.Context, client vpnClient) error {
		if err := client.RevokePeer(ctx, tenantID, deviceID); err != nil {
			return &WrappedError{Msg: "failed to revoke VPN peer", Err: err}
		}
		if isStructuredOutput(flags) {
			return output(flags, map[string]string{"tenant_id": tenantID, "device_id": deviceID, "revoked": "true"})
		}
		table := cli.NewTableData("TENANT", "DEVICE", "STATUS")
		table.AddRow(tenantID, deviceID, "revoked")
		return output(flags, *table)
	})
}

// runStatus shows the gateways' reported session state.
func runStatus(flags *cli.CommonFlags, gatewayID string) error {
	return withClient(flags, func(ctx context.Context, client vpnClient) error {
		gateways, err := client.Status(ctx, gatewayID)
		if err != nil {
			return &WrappedError{Msg: "failed to get VPN status", Err: err}
		}
		if isStructuredOutput(flags) {
			return output(flags, gateways)
		}
		return output(flags, statusTable(gateways))
	})
}

// runListPosturePolicies lists posture policies.
func runListPosturePolicies(flags *cli.CommonFlags, tenantID string) error {
	return withClient(flags, func(ctx context.Context, client vpnClient) error {
		policies, err := client.ListPosturePolicies(ctx, tenantID)
		if err != nil {
			return &WrappedError{Msg: "failed to list VPN posture policies", Err: err}
		}
		if isStructuredOutput(flags) {
			return output(flags, policies)
		}
		return output(flags, policiesTable(policies))
	})
}

// runGetPosturePolicy shows one posture policy, module included.
func runGetPosturePolicy(flags *cli.CommonFlags, tenantID, name string) error {
	return withClient(flags, func(ctx context.Context, client vpnClient) error {
		policy, err := client.GetPosturePolicy(ctx, tenantID, name)
		if err != nil {
			return &WrappedError{Msg: "failed to get VPN posture policy", Err: err}
		}
		if isStructuredOutput(flags) {
			return output(flags, policy)
		}
		// A Rego module does not fit a table cell: the table names the
		// policy, and --output yaml|json carries the module.
		return output(flags, policiesTable([]*platformv1.VPNPosturePolicy{policy}))
	})
}

// runSetPosturePolicy stores the module read from file as a posture policy.
func runSetPosturePolicy(flags *cli.CommonFlags, tenantID, name, file string) error {
	module, err := os.ReadFile(file)
	if err != nil {
		return &WrappedError{Msg: "failed to read posture policy module", Err: err}
	}
	return withClient(flags, func(ctx context.Context, client vpnClient) error {
		policy, err := client.SetPosturePolicy(ctx, tenantID, name, string(module))
		if err != nil {
			return &WrappedError{Msg: "failed to set VPN posture policy", Err: err}
		}
		if isStructuredOutput(flags) {
			return output(flags, policy)
		}
		return output(flags, policiesTable([]*platformv1.VPNPosturePolicy{policy}))
	})
}

// runDeletePosturePolicy deletes a posture policy and confirms it.
func runDeletePosturePolicy(flags *cli.CommonFlags, tenantID, name string) error {
	return withClient(flags, func(ctx context.Context, client vpnClient) error {
		if err := client.DeletePosturePolicy(ctx, tenantID, name); err != nil {
			return &WrappedError{Msg: "failed to delete VPN posture policy", Err: err}
		}
		if isStructuredOutput(flags) {
			return output(flags, map[string]string{"tenant_id": tenantID, "name": name, "deleted": "true"})
		}
		table := cli.NewTableData("TENANT", "NAME", "STATUS")
		table.AddRow(tenantID, name, "deleted")
		return output(flags, *table)
	})
}

// isStructuredOutput reports whether the caller asked for JSON or YAML, in
// which case the raw messages are emitted instead of a table.
func isStructuredOutput(flags *cli.CommonFlags) bool {
	if flags == nil {
		return false
	}
	return flags.OutputFormat == cli.OutputFormatJSON || flags.OutputFormat == cli.OutputFormatYAML
}

// peersTable renders enrolled peers.
func peersTable(peers []*platformv1.VPNPeer) cli.TableData {
	table := cli.NewTableData("TENANT", "DEVICE", "ZONES", "ENROLLED")
	for _, peer := range peers {
		zones := "all allowed"
		if len(peer.GetZones()) > 0 {
			zones = strings.Join(peer.GetZones(), ",")
		}
		table.AddRow(peer.GetTenantId(), peer.GetDeviceId(), zones, formatUnix(peer.GetEnrolledAtUnix()))
	}
	return *table
}

// statusTable renders one row per gateway.
func statusTable(gateways []*platformv1.VPNGatewayStatus) cli.TableData {
	table := cli.NewTableData("GATEWAY", "VPN", "REPORTED", "PEERS", "LEASES", "ADMITTED", "REFUSED", "LAST REFUSAL", "POLICY ERRORS", "REJECTED PEERS")
	for _, gw := range gateways {
		table.AddRow(
			gw.GetGatewayId(),
			serviceState(gw),
			formatUnix(gw.GetReportedAtUnix()),
			strconv.FormatUint(uint64(gw.GetEnrolledPeers()), 10),
			strconv.Itoa(len(gw.GetLeases())),
			strconv.FormatUint(gw.GetAdmissions(), 10),
			strconv.FormatUint(gw.GetRefusals(), 10),
			gw.GetLastRefusal(),
			strconv.Itoa(len(gw.GetPosturePolicyErrors())),
			rejectedPeers(gw.GetRejectedPeers()),
		)
	}
	return *table
}

// rejectedPeers names each peer a gateway refused to enrol, with the reason.
func rejectedPeers(peers []*platformv1.VPNRejectedPeer) string {
	names := make([]string, 0, len(peers))
	for _, peer := range peers {
		names = append(names, peer.GetTenantId()+"/"+peer.GetDeviceId()+": "+peer.GetReason())
	}
	return strings.Join(names, "; ")
}

// serviceState names a gateway's VPN service state.
func serviceState(gw *platformv1.VPNGatewayStatus) string {
	switch {
	case !gw.GetReporting():
		return "not configured"
	case gw.GetRunning():
		return "running"
	default:
		return "stopped"
	}
}

// policiesTable renders posture policies without their modules.
func policiesTable(policies []*platformv1.VPNPosturePolicy) cli.TableData {
	table := cli.NewTableData("TENANT", "NAME", "UPDATED")
	for _, policy := range policies {
		table.AddRow(policy.GetTenantId(), policy.GetName(), formatUnix(policy.GetUpdatedAtUnix()))
	}
	return *table
}

// formatUnix renders a Unix timestamp as RFC 3339, or "never" for zero.
func formatUnix(seconds int64) string {
	if seconds <= 0 {
		return "never"
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}
