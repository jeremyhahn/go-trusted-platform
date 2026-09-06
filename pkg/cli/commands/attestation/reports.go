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
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	attestationsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/attestation"
)

// newReportsCommand creates the reports command group.
func newReportsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reports",
		Short: "Cached device attestation reports (verdict with its age)",
		Long: `Read the device attestation reports the control plane's collector has
cached, or ask it to collect one device again.

Every report carries its verdict together with whether it is still fresh and
how old it is. Read the three together: a stale verified report means the
evidence is old, not that the device has none. A device the collector has
never reached has no report at all; that is reported as its own state, never
as a failed verdict.`,
	}
	cmd.AddCommand(newReportsListCommand(getFlags))
	cmd.AddCommand(newReportsGetCommand(getFlags))
	cmd.AddCommand(newReportsRefreshCommand(getFlags))
	return cmd
}

func newReportsListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List every cached device report with its verdict and age",
		Long: `List every device attestation report in the control plane's cache,
ordered by device id.

The table shows each device's verdict beside its freshness and age, and the
PCR baseline source (signed or tofu) the verdict rests on. A TOFU pass is a
weaker claim than a signed-manifest pass and must not be read the same way.

Examples:
  platformctl attestation reports list
  platformctl attestation reports list -o json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			r, closer, err := connect(getFlags())
			if err != nil {
				return err
			}
			defer closer.Close()
			return r.listReports()
		},
	}
}

func newReportsGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "get <device-id>",
		Short: "Show one device's full attestation report",
		Long: `Show one device's cached attestation report: the verdict with its
freshness and age, the four checks behind it, whether a negative verdict came
from a check that ran and failed (cryptographic, the only kind that
quarantines) or from one that could not run, the PCR baseline the verdict
rests on, and the verifier's and collector's timestamps.

A device the collector has never reached has no report. That is reported as
its own state and exits non-zero; it is not a failed verdict.

Examples:
  platformctl attestation reports get 123
  platformctl attestation reports get 123 -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseDeviceID(args[0])
			if err != nil {
				return err
			}
			r, closer, err := connect(getFlags())
			if err != nil {
				return err
			}
			defer closer.Close()
			return r.getReport(id)
		},
	}
}

func newReportsRefreshCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "refresh <device-id>",
		Short: "Ask the collector to attest a device out of cycle",
		Long: `Enqueue an out-of-cycle collection for one device.

The request goes to the collector, which applies the same TTL, coalescing and
per-device serialization as scheduled work, so a refresh cannot put more load
on a node's TPM than the schedule would. The command returns as soon as the
request is enqueued; it never waits for, and never prints, a quote or a
verdict. Read the report again for the outcome and its age.

Examples:
  platformctl attestation reports refresh 123
  platformctl attestation reports get 123`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseDeviceID(args[0])
			if err != nil {
				return err
			}
			r, closer, err := connect(getFlags())
			if err != nil {
				return err
			}
			defer closer.Close()
			return r.refreshReport(id)
		},
	}
}

// parseDeviceID validates a device id before anything connects: a positive
// decimal integer, returned in canonical form.
func parseDeviceID(raw string) (string, error) {
	id, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil || id == 0 {
		return "", ErrInvalidDeviceID{ID: raw}
	}
	return strconv.FormatUint(id, 10), nil
}

// reportsOutput is the fleet list as the REST and MCP transports serialise
// it: the reports and their count.
type reportsOutput struct {
	Reports []reporting.View `json:"reports"`
	Count   int              `json:"count"`
}

// refreshOutput is the refresh acknowledgement as every transport serialises
// it. Enqueued is the only claim the command makes.
type refreshOutput struct {
	DeviceID string `json:"device_id"`
	Enqueued bool   `json:"enqueued"`
	Note     string `json:"note"`
}

func (r *runner) listReports() error {
	reports, err := r.client.ListDeviceReports(r.ctx)
	if err != nil {
		return ErrListReportsFailed{Reason: err.Error()}
	}
	views := make([]reporting.View, 0, len(reports))
	for _, rep := range reports {
		views = append(views, viewFromProto(rep))
	}
	if r.format == cli.OutputFormatTable {
		printReportsTable(r.printer, views)
		return nil
	}
	return r.output(reportsOutput{Reports: views, Count: len(views)})
}

func (r *runner) getReport(deviceID string) error {
	report, err := r.client.GetDeviceReport(r.ctx, deviceID)
	if err != nil {
		var never *attestationsvc.ErrNoDeviceReport
		if errors.As(err, &never) {
			return ErrNeverCollected{DeviceID: deviceID}
		}
		return ErrGetReportFailed{DeviceID: deviceID, Reason: err.Error()}
	}
	view := viewFromProto(report)
	if r.format == cli.OutputFormatTable {
		printReportDetails(r.printer, view)
		return nil
	}
	return r.output(view)
}

func (r *runner) refreshReport(deviceID string) error {
	resp, err := r.client.RefreshDeviceReport(r.ctx, deviceID)
	if err != nil {
		return ErrRefreshFailed{DeviceID: deviceID, Reason: err.Error()}
	}
	out := refreshOutput{DeviceID: resp.GetDeviceId(), Enqueued: resp.GetEnqueued(), Note: resp.GetNote()}
	if out.DeviceID == "" {
		out.DeviceID = deviceID
	}
	if r.format == cli.OutputFormatTable {
		printRefresh(r.printer, out)
		return nil
	}
	return r.output(out)
}

// viewFromProto is the inverse of the daemon's viewToProto: it restores the
// wire shape every transport serialises, so -o json|yaml carry it unchanged
// and the table renders from one set of field names.
func viewFromProto(p *platformv1.DeviceAttestationReport) reporting.View {
	return reporting.View{
		DeviceID:              p.GetDeviceId(),
		Serial:                p.GetSerial(),
		Model:                 p.GetModel(),
		Verified:              p.GetVerified(),
		AKCertificateVerified: p.GetAkCertificateVerified(),
		SignatureValid:        p.GetSignatureValid(),
		NonceValid:            p.GetNonceValid(),
		PCRsValid:             p.GetPcrsValid(),
		CryptographicFailure:  p.GetCryptographicFailure(),
		PCRBaselineSource:     p.GetPcrBaselineSource(),
		PCRBaselineRecordedAt: timeOf(p.GetPcrBaselineRecordedAt()),
		PCRBaselineCaptured:   p.GetPcrBaselineCaptured(),
		Status:                p.GetStatus(),
		Message:               p.GetMessage(),
		AttestedAt:            timeOf(p.GetAttestedAt()),
		CollectedAt:           timeOf(p.GetCollectedAt()),
		Fresh:                 p.GetFresh(),
		AgeSeconds:            p.GetAgeSeconds(),
		AsOf:                  timeOf(p.GetAsOf()),
		TimeSynced:            timeSyncedOf(p),
	}
}

// timeSyncedOf reads the report's optional clock state.
//
// The generated GetTimeSynced() collapses absent to false, which is the one
// distinction this field exists to keep, so presence is read from the
// pointer directly — with a nil guard, because viewFromProto accepts a nil
// report.
func timeSyncedOf(p *platformv1.DeviceAttestationReport) *bool {
	if p == nil {
		return nil
	}
	return p.TimeSynced
}

// timestampReader is the one method viewFromProto needs from a pb Timestamp.
type timestampReader interface {
	AsTime() time.Time
	IsValid() bool
}

// timeOf converts an optional pb timestamp; an absent one is the zero time.
func timeOf(ts timestampReader) time.Time {
	if ts == nil || !ts.IsValid() {
		return time.Time{}
	}
	return ts.AsTime().UTC()
}

// Table rendering ------------------------------------------------------------

// verdictLabel names the verdict the way the console does: verified, failed
// (a check ran and failed) or not verified (a check could not run).
func verdictLabel(v reporting.View) string {
	if v.Verified {
		return "verified"
	}
	if v.CryptographicFailure {
		return "failed"
	}
	return "not verified"
}

// freshnessLabel is fresh or stale.
func freshnessLabel(fresh bool) string {
	if fresh {
		return "fresh"
	}
	return "stale"
}

// formatAge renders age_seconds as a duration.
func formatAge(seconds int64) string {
	return (time.Duration(seconds) * time.Second).String()
}

// formatTime renders a timestamp in RFC 3339 UTC, or "-" when absent.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

// orDash renders an absent string as "-".
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// yesNo renders a check result.
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// clockLabel names the device's own clock trust state at collection. An
// absent state renders as "unknown", never as "unsynced": the device did
// not answer, which says nothing about its clock.
func clockLabel(v reporting.View) string {
	if v.TimeSynced == nil {
		return "unknown"
	}
	if *v.TimeSynced {
		return "synced"
	}
	return "UNSYNCED"
}

// baselineLabel names the PCR baseline a verdict rests on; empty means no
// baseline was evaluated.
func baselineLabel(v reporting.View) string {
	if v.PCRBaselineSource == "" {
		return "none evaluated"
	}
	label := v.PCRBaselineSource
	if !v.PCRBaselineRecordedAt.IsZero() {
		label += " (recorded " + formatTime(v.PCRBaselineRecordedAt) + ")"
	}
	if v.PCRBaselineCaptured {
		label += ", captured on this collection"
	}
	return label
}

// verdictWithAge is the one line a verdict is ever printed on: the label,
// its freshness and its age together.
func verdictWithAge(v reporting.View) string {
	return verdictLabel(v) + " (" + freshnessLabel(v.Fresh) + ", age " + formatAge(v.AgeSeconds) + ")"
}

// printReportsTable renders the fleet: every row carries FRESH and AGE
// beside VERDICT.
func printReportsTable(printer *cli.Printer, views []reporting.View) {
	if len(views) == 0 {
		printer.PrintInfo("No device attestation reports have been collected yet")
		return
	}
	table := cli.TableData{
		Headers: []string{"Device", "Serial", "Verdict", "Fresh", "Age", "Clock", "Baseline", "Collected"},
	}
	for _, v := range views {
		table.Rows = append(table.Rows, []string{
			v.DeviceID, orDash(v.Serial), verdictLabel(v), freshnessLabel(v.Fresh),
			formatAge(v.AgeSeconds), clockLabel(v), orDash(v.PCRBaselineSource),
			formatTime(v.CollectedAt),
		})
	}
	_ = printer.Print(table)
}

// printReportDetails renders one report.
func printReportDetails(printer *cli.Printer, v reporting.View) {
	printer.PrintKeyValue("Device", v.DeviceID)
	printer.PrintKeyValue("Serial", orDash(v.Serial))
	printer.PrintKeyValue("Model", orDash(v.Model))
	printer.PrintKeyValue("Verdict", verdictWithAge(v))
	printer.PrintKeyValue("AK certificate verified", yesNo(v.AKCertificateVerified))
	printer.PrintKeyValue("Signature valid", yesNo(v.SignatureValid))
	printer.PrintKeyValue("Nonce valid", yesNo(v.NonceValid))
	printer.PrintKeyValue("PCRs valid", yesNo(v.PCRsValid))
	printer.PrintKeyValue("Cryptographic failure", yesNo(v.CryptographicFailure))
	printer.PrintKeyValue("PCR baseline", baselineLabel(v))
	printer.PrintKeyValue("Device clock", clockLabel(v))
	printer.PrintKeyValue("Status", v.Status)
	if v.Message != "" {
		printer.PrintKeyValue("Message", v.Message)
	}
	printer.PrintKeyValue("Attested at", formatTime(v.AttestedAt))
	printer.PrintKeyValue("Collected at", formatTime(v.CollectedAt))
	printer.PrintKeyValue("As of", formatTime(v.AsOf))
}

// printRefresh renders the acknowledgement; it claims nothing beyond
// enqueued.
func printRefresh(printer *cli.Printer, out refreshOutput) {
	printer.PrintKeyValue("Device", out.DeviceID)
	printer.PrintKeyValue("Enqueued", yesNo(out.Enqueued))
	if out.Note != "" {
		printer.PrintKeyValue("Note", out.Note)
	}
}
