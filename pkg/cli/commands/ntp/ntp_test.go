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

package ntp

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ntp"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// errFakeClient is the sentinel failure injected by the fake client.
var errFakeClient = errors.New("fake client failure")

// fakeCLIClient records invocations of the ntpClient interface.
type fakeCLIClient struct {
	err      error
	lastCall string
}

// Status records the call and returns a converged reading.
func (f *fakeCLIClient) Status(context.Context) (*platformv1.NTPStatus, error) {
	f.lastCall = "Status"
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.NTPStatus{
		Synced:           true,
		Stratum:          3,
		LeapStatus:       "Normal",
		Mode:             "both",
		ReferenceName:    "10.4.200.1",
		LastSyncUnix:     1755000000,
		SourcesReachable: 1,
		SourcesTotal:     2,
	}, nil
}

// Sources records the call and returns one reachable source.
func (f *fakeCLIClient) Sources(context.Context) ([]*platformv1.NTPSource, error) {
	f.lastCall = "Sources"
	if f.err != nil {
		return nil, f.err
	}
	return []*platformv1.NTPSource{
		{Address: "10.4.200.1", Mode: "server", State: "selected", Stratum: 2,
			PollSeconds: 64, Reach: 377, LastRxSeconds: 23, Reachable: true},
	}, nil
}

// Step records the call and returns the post-step reading.
func (f *fakeCLIClient) Step(context.Context) (*platformv1.NTPStatus, error) {
	f.lastCall = "Step"
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.NTPStatus{Synced: true, Stratum: 3}, nil
}

// withFakeClient swaps the client factory and output renderer, returning a
// pointer to the last rendered value.
func withFakeClient(t *testing.T, fake *fakeCLIClient) *any {
	t.Helper()
	origFactory := newNTPClient
	origOutput := output
	var lastOutput any
	newNTPClient = func(*cli.CommonFlags) (ntpClient, func() error, error) {
		return fake, func() error { return nil }, nil
	}
	output = func(_ *cli.CommonFlags, v any) error {
		lastOutput = v
		return nil
	}
	t.Cleanup(func() {
		newNTPClient = origFactory
		output = origOutput
	})
	return &lastOutput
}

// execute runs the ntp command tree with the given args.
func execute(t *testing.T, args ...string) error {
	t.Helper()
	return executeWithFlags(t, &cli.CommonFlags{}, args...)
}

// executeWithFlags runs the ntp command tree with explicit common flags.
func executeWithFlags(t *testing.T, flags *cli.CommonFlags, args ...string) error {
	t.Helper()
	cmd := NewCommand(func() *cli.CommonFlags { return flags })
	cmd.SetArgs(args)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	return cmd.Execute()
}

func TestNTPCommandsRenderTables(t *testing.T) {
	fake := &fakeCLIClient{}
	lastOutput := withFakeClient(t, fake)

	t.Run("status", func(t *testing.T) {
		if err := execute(t, "status"); err != nil {
			t.Fatalf("status: %v", err)
		}
		if fake.lastCall != "Status" {
			t.Fatalf("call = %s, want Status", fake.lastCall)
		}
		if _, ok := (*lastOutput).(*cli.TableData); !ok {
			t.Fatalf("output = %T, want *cli.TableData", *lastOutput)
		}
	})

	t.Run("sources", func(t *testing.T) {
		if err := execute(t, "sources"); err != nil {
			t.Fatalf("sources: %v", err)
		}
		if fake.lastCall != "Sources" {
			t.Fatalf("call = %s, want Sources", fake.lastCall)
		}
	})

	t.Run("step", func(t *testing.T) {
		if err := execute(t, "step"); err != nil {
			t.Fatalf("step: %v", err)
		}
		if fake.lastCall != "Step" {
			t.Fatalf("call = %s, want Step", fake.lastCall)
		}
	})
}

func TestNTPCommandsRenderTablesNotYAML(t *testing.T) {
	fake := &fakeCLIClient{}
	lastOutput := withFakeClient(t, fake)
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatTable, NoColor: true}

	for command, header := range map[string]string{"status": "FIELD", "sources": "ADDRESS", "step": "FIELD"} {
		if err := executeWithFlags(t, flags, command); err != nil {
			t.Fatalf("%s: %v", command, err)
		}
		var buf bytes.Buffer
		if err := render(&buf, flags, *lastOutput); err != nil {
			t.Fatalf("%s: render: %v", command, err)
		}
		if !strings.HasPrefix(strings.TrimSpace(buf.String()), header) {
			t.Fatalf("%s rendered %q, want a table starting with %s", command, buf.String(), header)
		}
		if strings.Contains(buf.String(), "headers:") {
			t.Fatalf("%s rendered YAML, want a table:\n%s", command, buf.String())
		}
	}
}

func TestRenderRefusesAnUnknownOutputFormat(t *testing.T) {
	var buf bytes.Buffer
	err := render(&buf, &cli.CommonFlags{OutputFormat: "xml"}, cli.NewTableData("FIELD", "VALUE"))

	var want cli.ErrInvalidOutputFormat
	if !errors.As(err, &want) {
		t.Fatalf("render error = %v, want cli.ErrInvalidOutputFormat", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("render wrote %q for a refused format", buf.String())
	}
}

func TestNTPCommandsEmitRawMessagesForStructuredOutput(t *testing.T) {
	fake := &fakeCLIClient{}
	lastOutput := withFakeClient(t, fake)
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	if err := executeWithFlags(t, flags, "status"); err != nil {
		t.Fatalf("status: %v", err)
	}
	if _, ok := (*lastOutput).(*platformv1.NTPStatus); !ok {
		t.Fatalf("status output = %T, want *platformv1.NTPStatus", *lastOutput)
	}

	if err := executeWithFlags(t, flags, "sources"); err != nil {
		t.Fatalf("sources: %v", err)
	}
	if _, ok := (*lastOutput).([]*platformv1.NTPSource); !ok {
		t.Fatalf("sources output = %T, want []*platformv1.NTPSource", *lastOutput)
	}
}

func TestNTPCommandsWrapClientFailures(t *testing.T) {
	fake := &fakeCLIClient{err: errFakeClient}
	withFakeClient(t, fake)

	cases := map[string]string{
		"status":  "failed to get NTP status",
		"sources": "failed to list NTP sources",
		"step":    "failed to step the clock",
	}

	for command, want := range cases {
		t.Run(command, func(t *testing.T) {
			err := execute(t, command)
			if err == nil {
				t.Fatalf("%s = nil error, want the client failure", command)
			}
			if !errors.Is(err, errFakeClient) {
				t.Fatalf("%s error = %v, want it to unwrap to the client failure", command, err)
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("%s error = %q, want it to mention %q", command, err, want)
			}
		})
	}
}

func TestNTPCommandsSurfaceFactoryFailures(t *testing.T) {
	factoryErr := errors.New("no daemon endpoint configured")
	origFactory := newNTPClient
	newNTPClient = func(*cli.CommonFlags) (ntpClient, func() error, error) {
		return nil, nil, factoryErr
	}
	t.Cleanup(func() { newNTPClient = origFactory })

	for _, command := range []string{"status", "sources", "step"} {
		t.Run(command, func(t *testing.T) {
			if err := execute(t, command); !errors.Is(err, factoryErr) {
				t.Fatalf("%s error = %v, want the factory error", command, err)
			}
		})
	}
}

func TestStatusTableRendersNeverForAnUnsynchronizedClock(t *testing.T) {
	table := statusTable(&platformv1.NTPStatus{Mode: "consume"})
	if table == nil {
		t.Fatal("statusTable() = nil")
	}
	if got := formatUnix(0); got != "never" {
		t.Fatalf("formatUnix(0) = %q, want never", got)
	}
	if got := formatUnix(1755000000); !strings.HasPrefix(got, "2025-") {
		t.Fatalf("formatUnix(1755000000) = %q, want an RFC3339 timestamp", got)
	}

	// A nil status must render an empty table rather than panicking.
	if statusTable(nil) == nil {
		t.Fatal("statusTable(nil) = nil, want an empty table")
	}
	if sourcesTable(nil) == nil {
		t.Fatal("sourcesTable(nil) = nil, want an empty table")
	}
}

func TestStatusTableIncludesTheAnomalyReasonWhenPresent(t *testing.T) {
	withReason := statusTable(&platformv1.NTPStatus{
		Anomaly:       true,
		AnomalyReason: "clock corrected by 42.000s after the first-boot correction",
	})
	withoutReason := statusTable(&platformv1.NTPStatus{})

	if len(withReason.Rows) <= len(withoutReason.Rows) {
		t.Fatalf("anomaly reason row was not added (%d vs %d rows)",
			len(withReason.Rows), len(withoutReason.Rows))
	}
}

func TestIsStructuredOutputHandlesMissingFlags(t *testing.T) {
	if isStructuredOutput(nil) {
		t.Fatal("isStructuredOutput(nil) = true, want false")
	}
	if isStructuredOutput(&cli.CommonFlags{OutputFormat: cli.OutputFormatTable}) {
		t.Fatal("table output should not be treated as structured")
	}
	if !isStructuredOutput(&cli.CommonFlags{OutputFormat: cli.OutputFormatYAML}) {
		t.Fatal("YAML output should be treated as structured")
	}
}

// TestStatusTableNamesAnUnreachableServeName asserts `platformctl ntp
// status` shows that this node advertises an NTS-KE name its own allow list
// refuses. Every other field on the table can look perfect while clients
// complete the handshake and are then refused time (#509).
func TestStatusTableNamesAnUnreachableServeName(t *testing.T) {
	table := statusTable(&platformv1.NTPStatus{
		Synced:  true,
		Stratum: 3,
		ServeNameFindings: []*platformv1.NTSServeNameFinding{{
			Kind:           string(ntp.ServeNameUnreachable),
			Name:           "cp.example.internal",
			Address:        "192.0.2.140",
			ListenNetworks: []string{"10.4.200.0/24", "198.51.100.0/24"},
		}},
	})

	var line string
	for _, row := range table.Rows {
		if row[0] == "nts name unreachable" {
			line = row[1]
		}
	}
	if line == "" {
		t.Fatal("the advertised-name mismatch is missing from the status table")
	}
	for _, want := range []string{"cp.example.internal", "192.0.2.140", "10.4.200.0/24"} {
		if !strings.Contains(line, want) {
			t.Errorf("row %q does not name %q", line, want)
		}
	}
}

// TestStatusTableOmitsTheRowWhenThereIsNoMismatch covers the healthy side,
// and the nil entry a malformed wire message could carry.
func TestStatusTableOmitsTheRowWhenThereIsNoMismatch(t *testing.T) {
	table := statusTable(&platformv1.NTPStatus{Synced: true, Stratum: 3})
	for _, row := range table.Rows {
		if row[0] == "nts name unreachable" {
			t.Fatalf("a correctly configured node must not show the row: %v", row)
		}
	}
	if got := serveNameFindingLine(nil); got != "" {
		t.Errorf("serveNameFindingLine(nil) = %q, want empty", got)
	}
	if got := serveNameFindingLine(&platformv1.NTSServeNameFinding{Name: "cp", Address: "10.0.0.1"}); !strings.Contains(got, "none") {
		t.Errorf("an empty allow list must render readably, got %q", got)
	}
}

// TestStatusTableNamesAnUnresolvableServeName asserts the second kind gets
// its own row label and carries the resolver's own words, so an operator can
// tell "the zone has no record" from "this node refuses that segment" — two
// faults with different fixes.
func TestStatusTableNamesAnUnresolvableServeName(t *testing.T) {
	table := statusTable(&platformv1.NTPStatus{
		Synced: true,
		ServeNameFindings: []*platformv1.NTSServeNameFinding{{
			Kind:  string(ntp.ServeNameUnresolvable),
			Name:  "time.example.internal",
			Error: "lookup time.example.internal: no such host",
		}},
	})

	var label, line string
	for _, row := range table.Rows {
		if strings.Contains(row[0], "unresolvable") {
			label, line = row[0], row[1]
		}
	}
	if label == "" {
		t.Fatal("the unresolvable finding is missing from the status table")
	}
	if strings.Contains(label, "unreachable") {
		t.Errorf("label %q must not read as an allow-list refusal", label)
	}
	for _, want := range []string{"time.example.internal", "no such host", "does not resolve"} {
		if !strings.Contains(line, want) {
			t.Errorf("row %q does not carry %q", line, want)
		}
	}
}

// TestServeNameFindingLabelFallsBackReadably asserts a finding with no kind
// on the wire still labels readably, and an unknown future kind is shown
// verbatim rather than mislabelled as one of the known ones.
func TestServeNameFindingLabelFallsBackReadably(t *testing.T) {
	if got := serveNameFindingLabel(&platformv1.NTSServeNameFinding{}); got != "nts name unreachable" {
		t.Errorf("empty kind = %q, want the unreachable label", got)
	}
	if got := serveNameFindingLabel(&platformv1.NTSServeNameFinding{Kind: "nts-name-future"}); got != "nts name future" {
		t.Errorf("unknown kind = %q, want it shown verbatim", got)
	}
}
