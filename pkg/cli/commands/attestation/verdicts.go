// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// newVerdictsCommand creates the verdicts command group.
func newVerdictsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verdicts",
		Short: "Device verdicts as platformd records them",
		Long: `Follow the device verdicts platformd records, as it records them.

Each verdict is the outcome of one attestation: passed, failed (a check ran and
failed, evidence of compromise) or not verified (a check could not run). A
caller acting for a tenant sees only its own devices' verdicts.`,
	}
	cmd.AddCommand(newVerdictsFollowCommand(getFlags))
	return cmd
}

func newVerdictsFollowCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "follow",
		Short: "Print every device verdict from now on, until interrupted",
		Long: `Print every device verdict platformd records from now on, one per line,
until interrupted (Ctrl-C) or the stream ends.

Only verdicts recorded after the follow starts are printed; read the cached
reports for the current state. The follow works on every transport: gRPC and
Unix stream, REST, QUIC, MCP and embedded long-poll. A follow that falls too
far behind fails rather than skipping verdicts; start it again.

-o json prints one JSON object per verdict, -o yaml one YAML document.

Examples:
  platformctl attestation verdicts follow
  platformctl attestation verdicts follow -o json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			r, closer, err := connect(getFlags())
			if err != nil {
				return err
			}
			defer closer.Close()
			ctx, stop := signal.NotifyContext(r.ctx, os.Interrupt, syscall.SIGTERM)
			defer stop()
			r.ctx = ctx
			return r.followVerdicts()
		},
	}
}

// verdictOutput is one verdict as -o json|yaml print it, in the proto's field
// names.
type verdictOutput struct {
	EventID       string    `json:"event_id" yaml:"event_id"`
	RecordedAt    time.Time `json:"recorded_at" yaml:"recorded_at"`
	DeviceID      uint64    `json:"device_id" yaml:"device_id"`
	TenantID      string    `json:"tenant_id" yaml:"tenant_id"`
	HostID        string    `json:"host_id" yaml:"host_id"`
	Serial        string    `json:"serial" yaml:"serial"`
	Passed        bool      `json:"passed" yaml:"passed"`
	Cryptographic bool      `json:"cryptographic" yaml:"cryptographic"`
	Reason        string    `json:"reason" yaml:"reason"`
}

// followVerdicts prints each verdict as it arrives. The stream ending, or the
// command's context ending, ends the follow cleanly; any other failure is an
// error after the verdicts already received have been printed.
func (r *runner) followVerdicts() error {
	stream, err := r.client.StreamDeviceVerdicts(r.ctx)
	if err != nil {
		return r.followEnded(err)
	}
	for {
		event, err := stream.Recv()
		if err != nil {
			return r.followEnded(err)
		}
		if err := r.printVerdict(verdictFromProto(event)); err != nil {
			return err
		}
	}
}

// followEnded decides whether err ends the follow cleanly.
func (r *runner) followEnded(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(r.ctx.Err(), context.Canceled) {
		return nil
	}
	return ErrFollowVerdictsFailed{Reason: err.Error()}
}

// printVerdict prints one verdict: a line in table mode, otherwise one JSON
// object or one YAML document, so the output stays a parseable stream.
func (r *runner) printVerdict(v verdictOutput) error {
	switch r.format {
	case cli.OutputFormatTable:
		r.printer.Println(verdictLine(v))
		return nil
	case cli.OutputFormatYAML:
		r.printer.Println("---")
	}
	return r.output(v)
}

func verdictFromProto(e *platformv1.DeviceVerdictEvent) verdictOutput {
	return verdictOutput{
		EventID:       e.GetEventId(),
		RecordedAt:    timeOf(e.GetRecordedAt()),
		DeviceID:      e.GetDeviceId(),
		TenantID:      e.GetTenantId(),
		HostID:        e.GetHostId(),
		Serial:        e.GetSerial(),
		Passed:        e.GetPassed(),
		Cryptographic: e.GetCryptographic(),
		Reason:        e.GetReason(),
	}
}

// verdictLine is the one line a followed verdict is printed on. It names the
// verdict the way the reports do: verified, failed or not verified.
func verdictLine(v verdictOutput) string {
	label := "not verified"
	switch {
	case v.Passed:
		label = "verified"
	case v.Cryptographic:
		label = "failed"
	}
	if !v.Passed && v.Reason != "" {
		label += ": " + v.Reason
	}
	return formatTime(v.RecordedAt) + "  device " + strconv.FormatUint(v.DeviceID, 10) +
		"  serial " + orDash(v.Serial) + "  tenant " + orDash(v.TenantID) + "  " + label
}
