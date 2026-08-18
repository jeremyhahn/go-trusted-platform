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

package bmc

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// discoverHostMACs is the package-level entry point for out-of-band host
// MAC discovery. Tests override it to exercise the command without a BMC
// on the network (same pattern as newBMCClient in standalone.go).
var discoverHostMACs = bmc.DiscoverMACs

// newMACCommand creates the mac subcommand. It is standalone-only: the
// CLI talks directly to the BMC (like the other --bmc-host operations)
// and never routes through platformd, so there is no --server-url /
// --profile-id mode.
func newMACCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var standalone standaloneBMCFlags

	cmd := &cobra.Command{
		Use:   "mac",
		Short: "Discover host NIC MAC addresses via BMC (standalone)",
		Long: `Discover the host system's NIC MAC addresses out-of-band via its BMC.

Over Redfish the EthernetInterfaces collection is queried. Over IPMI,
Supermicro-family BMCs (including rebadged boards such as the VeloCloud
EDGE840) answer the OEM command NetFn 0x30 / Cmd 0x21, which returns the
host LAN1 MAC — the only out-of-band path on X10 ATEN firmware, whose
Redfish EthernetInterfaces collection is unpopulated. Non-Supermicro
vendors on the IPMI protocol fall through to a Redfish probe.

This is a standalone command: it talks directly to the BMC and requires
--bmc-host. There is no platformd (--server-url) mode.

Examples:
  platformctl bmc mac \
    --bmc-host 198.51.100.103 \
    --bmc-user ADMIN \
    --bmc-pass-file ~/.bmc-pass \
    --bmc-protocol ipmi`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !standalone.isSet() {
				return ErrBMCStandaloneRequired{Command: "mac"}
			}
			return runStandaloneMAC(cmd.Context(), &standalone, getFlags)
		},
	}

	addStandaloneFlags(cmd, &standalone)

	return cmd
}

// runStandaloneMAC builds the standalone BMC config and runs out-of-band
// host MAC discovery against it, printing every MAC found (primary first).
func runStandaloneMAC(ctx context.Context, standalone *standaloneBMCFlags, getFlags func() *cli.CommonFlags) error {
	cfg, err := newStandaloneConfig(ctx, standalone)
	if err != nil {
		return err
	}

	macs, err := discoverHostMACs(ctx, cfg, standaloneLogger())
	if err != nil {
		return err
	}

	resp := macResponse{Host: standalone.host, MACs: macs}
	done, err := emitJSON(getFlags, resp)
	if err != nil || done {
		return err
	}

	fmt.Fprintf(os.Stdout, "Host: %s\n", resp.Host)
	for _, mac := range resp.MACs {
		fmt.Fprintf(os.Stdout, "MAC:  %s\n", mac)
	}
	return nil
}
