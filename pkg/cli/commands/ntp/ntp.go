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

// Package ntp provides CLI commands for the platform's time-synchronization
// service: sync status, source enumeration, and operator-driven clock steps.
// Every command goes through the SDK, so the global --protocol flag selects
// REST, gRPC, QUIC, MCP, or the Unix socket with identical behavior.
package ntp

import (
	"context"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	ntpsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ntp"
)

// defaultCLITimeout is the context deadline for all NTP CLI operations.
const defaultCLITimeout = 30 * time.Second

// newCLIContext returns a context with the default CLI timeout and its cancel
// function. Callers must defer cancel().
func newCLIContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), defaultCLITimeout)
}

// clientFactory builds a time-synchronization client from the common CLI
// flags. Tests replace it with a fake to exercise command wiring without a
// daemon.
type clientFactory func(flags *cli.CommonFlags) (ntpClient, func() error, error)

// newNTPClient is the production client factory. It honors the global
// --protocol/--endpoint flags via cli.NewBaseCommand.
var newNTPClient clientFactory = func(flags *cli.CommonFlags) (ntpClient, func() error, error) {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return nil, nil, err
	}
	return ntpsvc.NewClientFromGRPC(base.Client().NTP()), base.Close, nil
}

// outputFunc renders a command result. Tests replace it to capture output.
type outputFunc func(flags *cli.CommonFlags, v any) error

// output is the production output renderer.
var output outputFunc = func(flags *cli.CommonFlags, v any) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()
	return base.Output(v)
}

// NewCommand creates the root ntp command.
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ntp",
		Short: "Time synchronization status and control",
		Long: `Inspect and control the node's time synchronization.

Time is a trust primitive on this platform: TPM attestation freshness, ACME
(RFC 8555) issuance, DANE/DNSSEC signature windows, and JWT exp/nbf are all
meaningless against a wrong clock. platformd renders chrony's configuration,
manages its OpenRC service, and reads sync state from its control socket.

Examples:
  # Current synchronization state
  platformctl ntp status
  platformctl ntp status -o json

  # Configured time sources and their reachability
  platformctl ntp sources

  # Operator recovery: force an immediate correction. Fails when no
  # source is reachable rather than moving the clock on stale data.
  platformctl ntp step`,
	}

	cmd.AddCommand(newStatusCommand(getFlags))
	cmd.AddCommand(newSourcesCommand(getFlags))
	cmd.AddCommand(newStepCommand(getFlags))

	return cmd
}

// newStatusCommand creates the ntp status subcommand.
func newStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the node's clock synchronization state",
		Long: `Show the node's clock synchronization state: synced flag, stratum,
leap status, current offset, root dispersion, last sync time, mode, and how
many configured sources are reachable.

Examples:
  platformctl ntp status
  platformctl ntp status -o json`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(getFlags())
		},
	}
}

// runStatus executes the status subcommand.
func runStatus(flags *cli.CommonFlags) error {
	client, closeFn, err := newNTPClient(flags)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := newCLIContext()
	defer cancel()

	status, err := client.Status(ctx)
	if err != nil {
		return &WrappedError{Msg: "failed to get NTP status", Err: err}
	}
	if isStructuredOutput(flags) {
		return output(flags, status)
	}
	return output(flags, statusTable(status))
}

// newSourcesCommand creates the ntp sources subcommand.
func newSourcesCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "sources",
		Short: "List configured time sources",
		Long: `List every configured time source with its selection state,
stratum, poll interval, reachability register, last receive time, and measured
offset.

Examples:
  platformctl ntp sources
  platformctl ntp sources -o json`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSources(getFlags())
		},
	}
}

// runSources executes the sources subcommand.
func runSources(flags *cli.CommonFlags) error {
	client, closeFn, err := newNTPClient(flags)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := newCLIContext()
	defer cancel()

	sources, err := client.Sources(ctx)
	if err != nil {
		return &WrappedError{Msg: "failed to list NTP sources", Err: err}
	}
	if isStructuredOutput(flags) {
		return output(flags, sources)
	}
	return output(flags, sourcesTable(sources))
}

// newStepCommand creates the ntp step subcommand.
func newStepCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "step",
		Short: "Force an immediate clock correction (operator recovery)",
		Long: `Force chronyd to step the clock immediately instead of slewing.

This is an operator recovery action gated by the ntp:write scope. It fails
when no time source is reachable rather than moving the clock on stale data.

Examples:
  platformctl ntp step`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStep(getFlags())
		},
	}
}

// runStep executes the step subcommand.
func runStep(flags *cli.CommonFlags) error {
	client, closeFn, err := newNTPClient(flags)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := newCLIContext()
	defer cancel()

	status, err := client.Step(ctx)
	if err != nil {
		return &WrappedError{Msg: "failed to step the clock", Err: err}
	}
	if isStructuredOutput(flags) {
		return output(flags, status)
	}
	return output(flags, statusTable(status))
}

// isStructuredOutput reports whether the caller asked for JSON or YAML, in
// which case the raw proto message is rendered instead of a table.
func isStructuredOutput(flags *cli.CommonFlags) bool {
	if flags == nil {
		return false
	}
	return flags.OutputFormat == cli.OutputFormatJSON || flags.OutputFormat == cli.OutputFormatYAML
}

// statusTable renders a status message as a two-column table.
func statusTable(status *platformv1.NTPStatus) *cli.TableData {
	table := cli.NewTableData("FIELD", "VALUE")
	if status == nil {
		return table
	}

	table.AddRow("synced", strconv.FormatBool(status.GetSynced()))
	table.AddRow("stratum", strconv.FormatUint(uint64(status.GetStratum()), 10))
	table.AddRow("leap status", status.GetLeapStatus())
	table.AddRow("offset (s)", strconv.FormatFloat(status.GetOffsetSeconds(), 'f', 9, 64))
	table.AddRow("root dispersion (s)", strconv.FormatFloat(status.GetRootDispersion(), 'f', 9, 64))
	table.AddRow("root delay (s)", strconv.FormatFloat(status.GetRootDelay(), 'f', 9, 64))
	table.AddRow("last sync", formatUnix(status.GetLastSyncUnix()))
	table.AddRow("mode", status.GetMode())
	table.AddRow("reference", status.GetReferenceName())
	table.AddRow("sources", strconv.FormatUint(uint64(status.GetSourcesReachable()), 10)+
		"/"+strconv.FormatUint(uint64(status.GetSourcesTotal()), 10)+" reachable")
	table.AddRow("anomaly", strconv.FormatBool(status.GetAnomaly()))
	if status.GetAnomalyReason() != "" {
		table.AddRow("anomaly reason", status.GetAnomalyReason())
	}
	return table
}

// sourcesTable renders the source list as a table.
func sourcesTable(sources []*platformv1.NTPSource) *cli.TableData {
	table := cli.NewTableData("ADDRESS", "MODE", "STATE", "STRATUM", "POLL", "REACH", "LAST RX", "OFFSET")
	for _, src := range sources {
		table.AddRow(
			src.GetAddress(),
			src.GetMode(),
			src.GetState(),
			strconv.FormatUint(uint64(src.GetStratum()), 10),
			strconv.FormatUint(uint64(src.GetPollSeconds()), 10)+"s",
			strconv.FormatUint(uint64(src.GetReach()), 10),
			strconv.FormatInt(src.GetLastRxSeconds(), 10)+"s",
			strconv.FormatFloat(src.GetOffsetSeconds(), 'f', 9, 64),
		)
	}
	return table
}

// formatUnix renders a UNIX timestamp, reporting "never" for the zero value
// so an unsynchronized node is unambiguous.
func formatUnix(seconds int64) string {
	if seconds <= 0 {
		return "never"
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}
