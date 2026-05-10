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

package container

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

// logsOptions holds the options for the logs command
type logsOptions struct {
	follow     bool
	tail       uint32
	timestamps bool
	stdout     bool
	stderr     bool
}

// newLogsCommand creates the container logs subcommand
func newLogsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &logsOptions{}

	cmd := &cobra.Command{
		Use:   "logs <container-id>",
		Short: "Get container logs",
		Long: `Fetch the logs of a container.

By default, this command fetches all logs from the container.
Use --tail to limit the output to the last N lines.
Use --follow to stream logs in real-time.

Examples:
  # Get all logs
  platformctl container logs myapp

  # Get last 100 lines
  platformctl container logs myapp --tail 100

  # Follow log output
  platformctl container logs myapp --follow

  # Show timestamps with logs
  platformctl container logs myapp --timestamps

  # Get only stderr
  platformctl container logs myapp --stderr

  # Get logs with JSON output
  platformctl container logs myapp --output json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runLogs(flags, args[0], opts)
		},
	}

	cmd.Flags().BoolVarP(&opts.follow, "follow", "f", false, "follow log output")
	cmd.Flags().Uint32VarP(&opts.tail, "tail", "n", 0, "number of lines to show from the end (0 = all)")
	cmd.Flags().BoolVarP(&opts.timestamps, "timestamps", "t", false, "show timestamps")
	cmd.Flags().BoolVar(&opts.stdout, "stdout", true, "show stdout logs")
	cmd.Flags().BoolVar(&opts.stderr, "stderr", true, "show stderr logs")

	return cmd
}

// runLogs executes the container logs command
func runLogs(flags *cli.CommonFlags, containerID string, opts *logsOptions) error {
	if containerID == "" {
		return ErrInvalidContainerConfig{Field: "id", Reason: "container ID is required"}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	computeClient := computesvc.NewClientFromGRPC(base.Client().Compute())

	params := &computesvc.GetContainerLogsParams{
		ID:        containerID,
		Follow:    opts.follow,
		TailLines: opts.tail,
		Stdout:    opts.stdout,
		Stderr:    opts.stderr,
	}

	ctx := base.Context()
	printer := base.Printer()

	// For JSON/YAML output, collect all logs and print at once
	if flags.OutputFormat == cli.OutputFormatJSON || flags.OutputFormat == cli.OutputFormatYAML {
		return collectAndPrintLogs(ctx, printer, computeClient, params)
	}

	// For table format, stream logs directly
	return streamLogs(ctx, computeClient, params, opts.timestamps)
}

// collectAndPrintLogs collects all log entries and prints them in the specified format
func collectAndPrintLogs(ctx context.Context, printer *cli.Printer, client *computesvc.Client, params *computesvc.GetContainerLogsParams) error {
	entries, err := client.GetContainerLogsBatch(ctx, params)
	if err != nil {
		return ErrContainerOperationFailed{Operation: "logs", ID: params.ID, Err: err}
	}

	result := struct {
		Entries []*computesvc.LogEntry `json:"entries" yaml:"entries"`
		Count   int                    `json:"count" yaml:"count"`
	}{
		Entries: entries,
		Count:   len(entries),
	}

	return printer.Print(result)
}

// streamLogs streams log entries to the console
func streamLogs(ctx context.Context, client *computesvc.Client, params *computesvc.GetContainerLogsParams, showTimestamps bool) error {
	return client.GetContainerLogsDomain(ctx, params, func(entry *computesvc.LogEntry) error {
		printLogEntry(entry, showTimestamps)
		return nil
	})
}

// printLogEntry prints a single log entry
func printLogEntry(entry *computesvc.LogEntry, showTimestamp bool) {
	if showTimestamp && !entry.Timestamp.IsZero() {
		ts := entry.Timestamp.UTC().Format(time.RFC3339)
		fmt.Printf("%s %s\n", ts, entry.Message)
	} else {
		fmt.Println(entry.Message)
	}
}
