// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gateway"
)

// newGatewaySnapshotCommand builds `platformctl sdn gateway snapshot`: the
// telemetry snapshot a gateway reports, printed section by section (#594).
func newGatewaySnapshotCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var gatewayID string
	var all bool

	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Show a gateway's telemetry snapshot",
		Long: `Display the telemetry snapshot of a gateway: what its services actually
programmed.

Sections:
  - Services: every configured section, whether it runs, its own health
    verdict, and the blocker behind a section the gateway refuses to run
  - BGP: one row per session with its FSM state, prefix counters and BFD
  - Tunnels: transport, link state, the uplink each is pinned to, counters
  - Uplinks: per-uplink routing table, next hops and policy rules
  - Host filter, firewall, NAT and the base OVS pipeline

With no --gateway-id the snapshot is the gateway this node runs itself; with
one it is the report the control plane holds for that gateway.

Examples:
  # This node's own gateway
  platformctl sdn gateway snapshot

  # A reported gateway, from the control plane
  platformctl sdn gateway snapshot --gateway-id node-01-gateway

  # Every gateway that has reported
  platformctl sdn gateway snapshot --all -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGatewaySnapshot(cmd, getFlags(), gatewayID, all)
		},
	}

	cmd.Flags().StringVar(&gatewayID, "gateway-id", "", "Read the snapshot this gateway reported (default: this node's own gateway)")
	cmd.Flags().BoolVar(&all, "all", false, "List every reported gateway's snapshot")
	return cmd
}

// runGatewaySnapshot fetches and renders one or every snapshot.
func runGatewaySnapshot(cmd *cobra.Command, flags *cli.CommonFlags, gatewayID string, all bool) error {
	if all && gatewayID != "" {
		return &ErrSnapshotArguments{Reason: "--all and --gateway-id name different reads; use one"}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())
	ctx, cancel := newCLIContext()
	defer cancel()

	if all {
		snapshots, err := gatewayClient.ListSnapshots(ctx)
		if err != nil {
			return &WrappedError{Msg: "failed to list gateway snapshots", Err: err}
		}
		if isStructuredOutput(flags) {
			return base.Output(snapshots)
		}
		for i, snap := range snapshots {
			if i > 0 {
				fmt.Fprintln(cmd.OutOrStdout())
			}
			printGatewaySnapshot(cmd.OutOrStdout(), snap)
		}
		return nil
	}

	snapshot, err := gatewayClient.GetSnapshot(ctx, gatewayID)
	if err != nil {
		return &WrappedError{Msg: "failed to get the gateway snapshot", Err: err}
	}
	if isStructuredOutput(flags) {
		return base.Output(snapshot)
	}
	printGatewaySnapshot(cmd.OutOrStdout(), snapshot)
	return nil
}

// isStructuredOutput reports whether the caller asked for a machine format,
// in which case the snapshot is emitted whole rather than rendered.
func isStructuredOutput(flags *cli.CommonFlags) bool {
	if flags == nil {
		return false
	}
	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return true
	default:
		return false
	}
}

// printGatewaySnapshot renders a snapshot as sections an operator reads
// top-down: identity, then what each service programmed.
func printGatewaySnapshot(w io.Writer, snap *platformv1.GatewaySnapshot) {
	if snap == nil {
		fmt.Fprintln(w, "no snapshot")
		return
	}
	fmt.Fprintf(w, "Gateway:  %s\n", snap.GetGatewayId())
	if host := snap.GetHostname(); host != "" {
		fmt.Fprintf(w, "Host:     %s\n", host)
	}
	if health := snap.GetHealth(); health != nil {
		fmt.Fprintf(w, "Health:   %s\n", health.GetStatus())
	}
	if reported := snap.GetReportedAt(); reported != nil {
		fmt.Fprintf(w, "Reported: %s\n", reported.AsTime().Format("2006-01-02 15:04:05 MST"))
	}

	if services := snap.GetServices(); len(services) > 0 {
		fmt.Fprintln(w, "\nServices")
		for _, svc := range services {
			line := fmt.Sprintf("  %-14s active=%-5t healthy=%t", svc.GetName(), svc.GetActive(), svc.GetHealthy())
			if reason := svc.GetRefusedReason(); reason != "" {
				line += "  refused: " + reason
			}
			fmt.Fprintln(w, line)
		}
	}

	if bgpState := snap.GetBgp(); bgpState != nil && len(bgpState.GetPeers()) > 0 {
		fmt.Fprintf(w, "\nBGP  AS %d  router-id %s  %d/%d established\n",
			bgpState.GetLocalAsn(), bgpState.GetRouterId(), bgpState.GetEstablishedPeers(), bgpState.GetPeerCount())
		for _, peer := range bgpState.GetPeers() {
			fmt.Fprintf(w, "  %-18s AS%-8d %-12s recv=%d accepted=%d sent=%d\n",
				peer.GetAddress(), peer.GetAsn(), peer.GetState(),
				peer.GetPrefixesReceived(), peer.GetPrefixesAccepted(), peer.GetPrefixesSent())
			if bfd := peer.GetBfd(); bfd != nil {
				fmt.Fprintf(w, "  %-18s bfd %s (remote %s) failures=%d\n",
					"", bfd.GetState(), bfd.GetRemoteState(), bfd.GetFailureTransitions())
			}
		}
	}

	if tunnels := snap.GetTunnels(); len(tunnels) > 0 {
		fmt.Fprintln(w, "\nTunnels")
		for _, tun := range tunnels {
			uplink := tun.GetUplink()
			if uplink == "" {
				uplink = "-"
			}
			fmt.Fprintf(w, "  %-12s %-10s %-6s uplink=%-8s %s -> %s  rx=%d tx=%d\n",
				tun.GetName(), tun.GetTransport(), tun.GetState(), uplink,
				tun.GetLocalIp(), tun.GetRemoteIp(), tun.GetRxBytes(), tun.GetTxBytes())
		}
	}

	if uplinks := snap.GetUplinks(); len(uplinks) > 0 {
		fmt.Fprintln(w, "\nUplinks")
		for _, up := range uplinks {
			fmt.Fprintf(w, "  %-10s %-8s table=%-4d via %s rules=%d tunnels=%s\n",
				up.GetName(), up.GetInterface(), up.GetTable(), up.GetGatewayV4(),
				up.GetRuleCount(), strings.Join(up.GetTunnels(), ","))
		}
	}

	if hf := snap.GetHostFirewall(); hf != nil {
		fmt.Fprintf(w, "\nHost filter  installed=%t rules=%d fingerprint=%s\n",
			hf.GetInstalled(), hf.GetRuleCount(), hf.GetFingerprint())
		if lastErr := hf.GetLastError(); lastErr != "" {
			fmt.Fprintf(w, "  last error: %s\n", lastErr)
		}
	}
	if fw := snap.GetFirewall(); fw != nil {
		fmt.Fprintf(w, "Firewall     active=%t flows=%d\n", fw.GetActive(), fw.GetFlowCount())
	}
	if nat := snap.GetNat(); nat != nil {
		fmt.Fprintf(w, "NAT          snat=%t dnat=%d\n", nat.GetSnatEnabled(), nat.GetDnatRules())
		for _, up := range nat.GetUplinks() {
			fmt.Fprintf(w, "  %-10s pool=%d ports=%d static=%d default=%t\n",
				up.GetName(), up.GetPoolAddresses(), up.GetPorts(), up.GetStaticTranslations(), up.GetIsDefault())
		}
	}
	if pipeline := snap.GetPipeline(); pipeline != nil {
		fmt.Fprintf(w, "Pipeline     bridge=%s owner=%s terminal=%s fail-mode=%s\n",
			pipeline.GetBridge(), pipeline.GetOwner(), pipeline.GetTerminal(), pipeline.GetFailMode())
	}
	if overlay := snap.GetOverlay(); overlay != nil {
		fmt.Fprintf(w, "Overlay      running=%t local=%s vnis=%d remote-vteps=%d macs=%d/%d prefixes=%d refused=%d\n",
			overlay.GetRunning(), overlay.GetLocalVtep(), overlay.GetVniCount(), overlay.GetRemoteVtepCount(),
			overlay.GetLocalMacCount(), overlay.GetRemoteMacCount(), overlay.GetPrefixCount(), overlay.GetRefusedBindings())
		if counters := overlay.GetNdCounters(); counters != nil {
			fmt.Fprintf(w, "  nd punted=%d answered=%d meter-dropped=%d queue-dropped=%d fell-through=%d\n",
				counters.GetPunted(), counters.GetAnswered(), counters.GetMeterDropped(), counters.GetQueueDropped(), counters.GetFellThrough())
		}
		for _, vtep := range overlay.GetAdmittedVteps() {
			printGatewayAdmittedVTEP(w, vtep)
		}
	}
}

func newGatewayOverlayCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "overlay",
		Short: "Gateway overlay operations",
	}
	cmd.AddCommand(newGatewayAdmittedVTEPsCommand(getFlags))
	return cmd
}

func newGatewayAdmittedVTEPsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var gatewayID string
	cmd := &cobra.Command{
		Use:   "vteps",
		Short: "List admitted overlay VTEPs",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGatewayAdmittedVTEPs(cmd, getFlags(), gatewayID)
		},
	}
	cmd.Flags().StringVar(&gatewayID, "gateway-id", "", "Gateway id to read; omit for this node")
	cmd.AddCommand(newGatewayAdmittedVTEPGetCommand(getFlags))
	return cmd
}

func newGatewayAdmittedVTEPGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var gatewayID string
	cmd := &cobra.Command{
		Use:   "get <vtep>",
		Short: "Show one admitted overlay VTEP",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGatewayAdmittedVTEPGet(cmd, getFlags(), gatewayID, args[0])
		},
	}
	cmd.Flags().StringVar(&gatewayID, "gateway-id", "", "Gateway id to read; omit for this node")
	return cmd
}

func runGatewayAdmittedVTEPs(cmd *cobra.Command, flags *cli.CommonFlags, gatewayID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())
	ctx, cancel := newCLIContext()
	defer cancel()

	vteps, err := gatewayClient.ListAdmittedVTEPs(ctx, gatewayID)
	if err != nil {
		return &WrappedError{Msg: "failed to list gateway admitted VTEPs", Err: err}
	}
	if isStructuredOutput(flags) {
		return base.Output(vteps)
	}
	printGatewayAdmittedVTEPs(cmd.OutOrStdout(), vteps)
	return nil
}

func runGatewayAdmittedVTEPGet(cmd *cobra.Command, flags *cli.CommonFlags, gatewayID, vtep string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())
	ctx, cancel := newCLIContext()
	defer cancel()

	admitted, err := gatewayClient.GetAdmittedVTEP(ctx, gatewayID, vtep)
	if err != nil {
		return &WrappedError{Msg: "failed to get gateway admitted VTEP", Err: err}
	}
	if isStructuredOutput(flags) {
		return base.Output(admitted)
	}
	printGatewayAdmittedVTEP(cmd.OutOrStdout(), admitted)
	return nil
}

func printGatewayAdmittedVTEPs(w io.Writer, vteps []*platformv1.GatewayAdmittedVTEP) {
	if len(vteps) == 0 {
		fmt.Fprintln(w, "no admitted VTEPs")
		return
	}
	fmt.Fprintln(w, "Admitted VTEPs")
	for _, vtep := range vteps {
		printGatewayAdmittedVTEP(w, vtep)
	}
}

func printGatewayAdmittedVTEP(w io.Writer, vtep *platformv1.GatewayAdmittedVTEP) {
	if vtep == nil {
		fmt.Fprintln(w, "no admitted VTEP")
		return
	}
	verdict := "-"
	if ts := vtep.GetVerdictAt(); ts != nil {
		verdict = ts.AsTime().Format(time.RFC3339)
	}
	fmt.Fprintf(w, "  %-15s device=%d host=%s serial=%s allocation=%s baseline=%s profile=%d verdict=%s\n",
		vtep.GetVtep(), vtep.GetDeviceId(), vtep.GetHostId(), vtep.GetSerial(),
		vtep.GetAllocationId(), vtep.GetBaselineSource(), vtep.GetProfileId(), verdict)
}

// ErrSnapshotArguments reports a snapshot command whose flags contradict.
type ErrSnapshotArguments struct {
	Reason string
}

// Error implements the error interface.
func (e *ErrSnapshotArguments) Error() string {
	return "gateway snapshot: " + e.Reason
}
