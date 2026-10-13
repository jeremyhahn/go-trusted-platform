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
//
// Package attestation provides the platformctl verbs for the attestation
// reporting surface: the control plane's cached device verdicts, the
// out-of-cycle refresh trigger, the live verdict feed, and a node's
// caller-admission policy.
package attestation

import (
	"context"
	"io"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/attestation"
)

// NewCommand creates the attestation root command.
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attestation",
		Short: "Attestation reporting: device verdicts and caller policy",
		Long: `Read the control plane's device attestation reports and a node's
caller-admission policy.

The control plane's collector dials every enrolled device on a schedule,
verifies the quote it gets back and caches the verdict. These verbs read that
cache; none of them reaches a device. A verdict is always shown beside its
freshness and age, because a verified report that is hours old says less than
it appears to.

Examples:
  # Every device's verdict with its age
  platformctl attestation reports list

  # One device's full report
  platformctl attestation reports get 123

  # Ask the collector to attest a device out of cycle (enqueues; never waits)
  platformctl attestation reports refresh 123

  # Which control planes this node lets collect its quotes
  platformctl attestation callers

  # Print every device verdict platformd records from now on
  platformctl attestation verdicts follow

  # Machine-readable output carries the wire shape unchanged
  platformctl attestation reports get 123 -o json`,
	}
	cmd.AddCommand(newReportsCommand(getFlags))
	cmd.AddCommand(newCallersCommand(getFlags))
	cmd.AddCommand(newVerdictsCommand(getFlags))
	return cmd
}

// runner holds what every verb needs once connected. Tests build one around
// a fake gRPC client and a buffered printer; the verbs never touch the
// transport directly.
type runner struct {
	client  *attestation.Client
	printer *cli.Printer
	format  cli.OutputFormat
	ctx     context.Context
}

// connect opens the SDK client for the selected context and returns the
// runner plus the connection to close when the verb is done.
func connect(flags *cli.CommonFlags) (*runner, io.Closer, error) {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return nil, nil, err
	}
	r := &runner{
		client:  attestation.NewClientFromGRPC(base.Client().Attestation()),
		printer: base.Printer(),
		format:  flags.OutputFormat,
		ctx:     base.Context(),
	}
	return r, base, nil
}

// output renders v in the selected machine-readable format.
func (r *runner) output(v any) error {
	return r.printer.Print(v)
}
