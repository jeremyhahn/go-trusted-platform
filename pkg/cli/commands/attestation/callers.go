// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package attestation

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// newCallersCommand creates the callers command.
func newCallersCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "callers",
		Short: "Show the node's compiled caller-admission policy",
		Long: `Show which callers this node lets collect its quotes: the compiled
caller-admission policy behind POST /api/v1/attestation/host.

Read it on a node whose report the control plane cannot collect. A policy
that admits nobody (an invalid identity list, no trust anchors, or
any-attested with no attested-peer evidence) is the usual reason a device is
never collected.

Examples:
  platformctl attestation callers
  platformctl attestation callers -o yaml`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			r, closer, err := connect(getFlags())
			if err != nil {
				return err
			}
			defer closer.Close()
			return r.describeCallers()
		},
	}
}

func (r *runner) describeCallers() error {
	policy, err := r.client.DescribeCallerPolicy(r.ctx)
	if err != nil {
		return ErrDescribeCallersFailed{Reason: err.Error()}
	}
	desc := descriptionFromProto(policy)
	if r.format == cli.OutputFormatTable {
		printCallers(r.printer, desc)
		return nil
	}
	return r.output(desc)
}

// descriptionFromProto restores the wire shape of the caller policy.
func descriptionFromProto(p *platformv1.CallerPolicyDescription) calleradmission.Description {
	return calleradmission.Description{
		Strategy:               calleradmission.Strategy(p.GetStrategy()),
		Identities:             p.GetIdentities(),
		IdentitiesSource:       p.GetIdentitiesSource(),
		ListValid:              p.GetListValid(),
		InvalidEntries:         p.GetInvalidEntries(),
		AnchorsConfigured:      p.GetAnchorsConfigured(),
		AnchorSource:           p.GetAnchorSource(),
		AttestedPeersAvailable: p.GetAttestedPeersAvailable(),
		AdmitsNobody:           p.GetAdmitsNobody(),
	}
}

// printCallers renders the policy.
func printCallers(printer *cli.Printer, d calleradmission.Description) {
	printer.PrintKeyValue("Strategy", string(d.Strategy))
	printer.PrintKeyValue("Admits nobody", yesNo(d.AdmitsNobody))
	printer.PrintKeyValue("Identities", listOrNone(d.Identities))
	if d.IdentitiesSource != "" {
		printer.PrintKeyValue("Identities source", d.IdentitiesSource)
	}
	printer.PrintKeyValue("Identity list valid", yesNo(d.ListValid))
	if len(d.InvalidEntries) > 0 {
		printer.PrintKeyValue("Invalid entries", strings.Join(d.InvalidEntries, ", "))
	}
	printer.PrintKeyValue("Trust anchors configured", yesNo(d.AnchorsConfigured))
	if d.AnchorSource != "" {
		printer.PrintKeyValue("Anchor source", d.AnchorSource)
	}
	printer.PrintKeyValue("Attested peers available", yesNo(d.AttestedPeersAvailable))
}

// listOrNone joins a list, or says none.
func listOrNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}
