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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	attestationsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/attestation"
)

var update = flag.Bool("update", false, "rewrite the golden files under testdata/")

// fakeAttestationClient stubs the four report RPCs; the embedded interface
// panics on anything else, pinning each verb to the RPC it must call.
type fakeAttestationClient struct {
	platformv1.AttestationServiceClient

	listResp     *platformv1.ListDeviceReportsResponse
	listErr      error
	getReq       *platformv1.GetDeviceReportRequest
	getResp      *platformv1.GetDeviceReportResponse
	getErr       error
	refreshReq   *platformv1.RefreshDeviceReportRequest
	refreshResp  *platformv1.RefreshDeviceReportResponse
	refreshErr   error
	describeResp *platformv1.DescribeCallerPolicyResponse
	describeErr  error
}

func (f *fakeAttestationClient) ListDeviceReports(context.Context, *platformv1.ListDeviceReportsRequest, ...grpc.CallOption) (*platformv1.ListDeviceReportsResponse, error) {
	return f.listResp, f.listErr
}

func (f *fakeAttestationClient) GetDeviceReport(_ context.Context, in *platformv1.GetDeviceReportRequest, _ ...grpc.CallOption) (*platformv1.GetDeviceReportResponse, error) {
	f.getReq = in
	return f.getResp, f.getErr
}

func (f *fakeAttestationClient) RefreshDeviceReport(_ context.Context, in *platformv1.RefreshDeviceReportRequest, _ ...grpc.CallOption) (*platformv1.RefreshDeviceReportResponse, error) {
	f.refreshReq = in
	return f.refreshResp, f.refreshErr
}

func (f *fakeAttestationClient) DescribeCallerPolicy(context.Context, *platformv1.DescribeCallerPolicyRequest, ...grpc.CallOption) (*platformv1.DescribeCallerPolicyResponse, error) {
	return f.describeResp, f.describeErr
}

// newRunner builds a runner around the fake with a buffered, colourless
// printer so output can be compared byte for byte.
func newRunner(fake platformv1.AttestationServiceClient, format cli.OutputFormat) (*runner, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &runner{
		client:  attestationsvc.NewClientFromGRPC(fake),
		printer: cli.NewPrinterWithWriter(format, true, out),
		format:  format,
		ctx:     context.Background(),
	}, out
}

var (
	baselineAt  = time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	attestedAt  = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	collectedAt = attestedAt.Add(time.Second)
	asOf        = collectedAt.Add(42 * time.Second)
)

// verifiedReport is a fresh, signed-baseline pass.
func verifiedReport() *platformv1.DeviceAttestationReport {
	return &platformv1.DeviceAttestationReport{
		DeviceId: "9", Serial: "SN-9", Model: "X10SDV-TLN4F",
		Verified: true, AkCertificateVerified: true, SignatureValid: true, NonceValid: true, PcrsValid: true,
		PcrBaselineSource: "signed", PcrBaselineRecordedAt: timestamppb.New(baselineAt),
		Status: "verified", AttestedAt: timestamppb.New(attestedAt), CollectedAt: timestamppb.New(collectedAt),
		Fresh: true, AgeSeconds: 42, AsOf: timestamppb.New(asOf),
		TimeSynced: proto.Bool(true),
	}
}

// failedReport is a stale cryptographic failure on a TOFU baseline captured
// this collection: the PCRs did not match.
func failedReport() *platformv1.DeviceAttestationReport {
	return &platformv1.DeviceAttestationReport{
		DeviceId: "12", Serial: "SN-12", Model: "X10SDV-TLN4F",
		Verified: false, AkCertificateVerified: true, SignatureValid: true, NonceValid: true, PcrsValid: false,
		CryptographicFailure: true, PcrBaselineSource: "tofu", PcrBaselineCaptured: true,
		Status: "failed", Message: "PCR 7 does not match the baseline",
		AttestedAt: timestamppb.New(attestedAt), CollectedAt: timestamppb.New(collectedAt),
		Fresh: false, AgeSeconds: 3725, AsOf: timestamppb.New(asOf),
		// The device reported an undisciplined clock. Rendered distinctly
		// from the third fixture, which reported nothing at all.
		TimeSynced: proto.Bool(false),
	}
}

// notVerifiedReport is a negative verdict from a check that could not run:
// the device has no attestation certificate on record. It also carries NO
// clock state: the collector could not read one, which must not render as
// an unsynchronized clock.
func notVerifiedReport() *platformv1.DeviceAttestationReport {
	return &platformv1.DeviceAttestationReport{
		DeviceId: "15", Serial: "SN-15",
		Verified: false, AkCertificateVerified: false, SignatureValid: true, NonceValid: true, PcrsValid: true,
		Status: "denied", Message: "device has no attestation certificate on record",
		CollectedAt: timestamppb.New(collectedAt), Fresh: true, AgeSeconds: 42, AsOf: timestamppb.New(asOf),
	}
}

func fleet() *platformv1.ListDeviceReportsResponse {
	return &platformv1.ListDeviceReportsResponse{
		Reports: []*platformv1.DeviceAttestationReport{verifiedReport(), failedReport(), notVerifiedReport()},
		Total:   3,
	}
}

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		require.NoError(t, os.WriteFile(path, got, 0o644))
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err, "golden %s missing; run go test ./pkg/cli/commands/attestation -update", path)
	assert.Equal(t, string(want), string(got), "table rendering drifted from %s", path)
}

// Command wiring ----------------------------------------------------------------

// quietCommand builds the group the way root.go does (usage and errors are
// the root's to print), without a context so connecting fails typed.
func quietCommand() *cobra.Command {
	cmd := NewCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	return cmd
}

func TestNewCommand_Surface(t *testing.T) {
	cmd := NewCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	assert.Equal(t, "attestation", cmd.Use)

	names := map[string]bool{}
	for _, sub := range cmd.Commands() {
		names[sub.Name()] = true
	}
	assert.Equal(t, map[string]bool{"reports": true, "callers": true}, names)

	reports, _, err := cmd.Find([]string{"reports"})
	require.NoError(t, err)
	verbs := map[string]bool{}
	for _, sub := range reports.Commands() {
		verbs[sub.Name()] = true
	}
	assert.Equal(t, map[string]bool{"list": true, "get": true, "refresh": true}, verbs)
}

// TestCommands_InvalidDeviceIDFailsBeforeConnecting pins the typed error
// path: a bad id never reaches NewBaseCommand (whose nil-context error is
// what a connecting command would return here).
func TestCommands_InvalidDeviceIDFailsBeforeConnecting(t *testing.T) {
	cmd := quietCommand()
	for _, args := range [][]string{
		{"reports", "get", "abc"},
		{"reports", "get", "0"},
		{"reports", "refresh", "12x"},
		{"reports", "refresh", ""},
	} {
		cmd.SetArgs(args)
		err := cmd.Execute()
		var invalid ErrInvalidDeviceID
		assert.ErrorAs(t, err, &invalid, "args %v", args)
	}
}

func TestCommands_WithoutContextReportTheConnectionError(t *testing.T) {
	cmd := quietCommand()
	for _, args := range [][]string{
		{"reports", "list"},
		{"reports", "get", "9"},
		{"reports", "refresh", "9"},
		{"callers"},
	} {
		cmd.SetArgs(args)
		err := cmd.Execute()
		var noContext cli.ErrNoContextSet
		assert.ErrorAs(t, err, &noContext, "args %v", args)
	}
}

func TestParseDeviceID(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{{"9", "9"}, {" 12 ", "12"}, {"007", "7"}} {
		got, err := parseDeviceID(tc.raw)
		require.NoError(t, err, tc.raw)
		assert.Equal(t, tc.want, got)
	}
	for _, raw := range []string{"", "0", "-1", "abc", "1.5", "18446744073709551616"} {
		_, err := parseDeviceID(raw)
		var invalid ErrInvalidDeviceID
		assert.ErrorAs(t, err, &invalid, raw)
	}
}

// reports list ------------------------------------------------------------------

func TestListReports_Table(t *testing.T) {
	r, out := newRunner(&fakeAttestationClient{listResp: fleet()}, cli.OutputFormatTable)
	require.NoError(t, r.listReports())
	checkGolden(t, "reports_list", out.Bytes())

	// Every verdict is printed beside its freshness and age.
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 4)
	assert.Contains(t, lines[0], "FRESH")
	assert.Contains(t, lines[0], "AGE")
	assert.Contains(t, lines[0], "CLOCK")
	assert.Regexp(t, `verified\s+fresh\s+42s\s+synced\s+signed`, lines[1])
	assert.Regexp(t, `failed\s+stale\s+1h2m5s\s+UNSYNCED\s+tofu`, lines[2])
	// The device that reported no clock state renders "unknown", never
	// "UNSYNCED": absence of evidence is not evidence.
	assert.Regexp(t, `not verified\s+fresh\s+42s\s+unknown\s+-`, lines[3])
}

func TestListReports_TableEmpty(t *testing.T) {
	r, out := newRunner(&fakeAttestationClient{listResp: &platformv1.ListDeviceReportsResponse{}}, cli.OutputFormatTable)
	require.NoError(t, r.listReports())
	assert.Contains(t, out.String(), "No device attestation reports have been collected yet")
	assert.NotContains(t, out.String(), "verified")
}

func TestListReports_JSONCarriesTheWireShape(t *testing.T) {
	r, out := newRunner(&fakeAttestationClient{listResp: fleet()}, cli.OutputFormatJSON)
	require.NoError(t, r.listReports())

	var got struct {
		Reports []map[string]any `json:"reports"`
		Count   int              `json:"count"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	assert.Equal(t, 3, got.Count)
	require.Len(t, got.Reports, 3)
	first := got.Reports[0]
	assert.Equal(t, "9", first["device_id"])
	assert.Equal(t, true, first["verified"])
	assert.Equal(t, true, first["fresh"])
	assert.EqualValues(t, 42, first["age_seconds"])
	assert.Equal(t, "signed", first["pcr_baseline_source"])
	assert.Equal(t, "2026-09-05T12:00:01Z", first["collected_at"])
	// A failed verdict is present as verified:false, not omitted.
	assert.Equal(t, false, got.Reports[1]["verified"])
	assert.Equal(t, true, got.Reports[1]["cryptographic_failure"])
}

func TestListReports_YAML(t *testing.T) {
	r, out := newRunner(&fakeAttestationClient{listResp: fleet()}, cli.OutputFormatYAML)
	require.NoError(t, r.listReports())
	var got map[string]any
	require.NoError(t, yaml.Unmarshal(out.Bytes(), &got))
	assert.EqualValues(t, 3, got["count"])
}

func TestListReports_Error(t *testing.T) {
	r, out := newRunner(&fakeAttestationClient{listErr: status.Error(codes.Unavailable, "the reporting service is not configured on this node")}, cli.OutputFormatTable)
	err := r.listReports()
	var typed ErrListReportsFailed
	require.ErrorAs(t, err, &typed)
	assert.Contains(t, err.Error(), "not configured")
	assert.Empty(t, out.String())
}

// reports get -------------------------------------------------------------------

func TestGetReport_TableVerified(t *testing.T) {
	fake := &fakeAttestationClient{getResp: &platformv1.GetDeviceReportResponse{Report: verifiedReport()}}
	r, out := newRunner(fake, cli.OutputFormatTable)
	require.NoError(t, r.getReport("9"))
	assert.Equal(t, "9", fake.getReq.GetDeviceId())
	checkGolden(t, "report_get_verified", out.Bytes())
	assert.Contains(t, out.String(), "Verdict: verified (fresh, age 42s)")
	assert.Contains(t, out.String(), "PCR baseline: signed (recorded 2026-09-01T10:00:00Z)")
}

func TestGetReport_TableFailed(t *testing.T) {
	fake := &fakeAttestationClient{getResp: &platformv1.GetDeviceReportResponse{Report: failedReport()}}
	r, out := newRunner(fake, cli.OutputFormatTable)
	require.NoError(t, r.getReport("12"))
	checkGolden(t, "report_get_failed", out.Bytes())
	assert.Contains(t, out.String(), "Verdict: failed (stale, age 1h2m5s)")
	assert.Contains(t, out.String(), "Cryptographic failure: yes")
	assert.Contains(t, out.String(), "PCR baseline: tofu, captured on this collection")
	assert.Contains(t, out.String(), "Message: PCR 7 does not match the baseline")
}

func TestGetReport_TableNotVerified(t *testing.T) {
	fake := &fakeAttestationClient{getResp: &platformv1.GetDeviceReportResponse{Report: notVerifiedReport()}}
	r, out := newRunner(fake, cli.OutputFormatTable)
	require.NoError(t, r.getReport("15"))
	checkGolden(t, "report_get_not_verified", out.Bytes())
	assert.Contains(t, out.String(), "Verdict: not verified (fresh, age 42s)")
	assert.Contains(t, out.String(), "Cryptographic failure: no")
	assert.Contains(t, out.String(), "PCR baseline: none evaluated")
	assert.Contains(t, out.String(), "Model: -")
	assert.Contains(t, out.String(), "Attested at: -")
}

func TestGetReport_JSONCarriesTheWireShape(t *testing.T) {
	fake := &fakeAttestationClient{getResp: &platformv1.GetDeviceReportResponse{Report: failedReport()}}
	r, out := newRunner(fake, cli.OutputFormatJSON)
	require.NoError(t, r.getReport("12"))

	// Decoding into reporting.View proves the field names are the wire's.
	var view reporting.View
	require.NoError(t, json.Unmarshal(out.Bytes(), &view))
	assert.Equal(t, "12", view.DeviceID)
	assert.False(t, view.Verified)
	assert.True(t, view.CryptographicFailure)
	assert.False(t, view.Fresh)
	assert.EqualValues(t, 3725, view.AgeSeconds)
	assert.Equal(t, "tofu", view.PCRBaselineSource)
	assert.True(t, view.PCRBaselineCaptured)
	assert.Equal(t, attestedAt, view.AttestedAt)
	assert.Equal(t, asOf, view.AsOf)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &raw))
	for _, key := range []string{"verified", "fresh", "age_seconds", "cryptographic_failure", "pcrs_valid"} {
		assert.Contains(t, raw, key, "the verdict and its age must be present even when false or zero")
	}
}

// TestGetReport_NeverCollected_IsItsOwnState is the mutation check: a
// NotFound must surface as ErrNeverCollected with nothing on stdout in any
// format. If the verb ever rendered a zero report instead, the table would
// read "not verified" and the JSON would carry verified:false, both of which
// this test refuses.
func TestGetReport_NeverCollected_IsItsOwnState(t *testing.T) {
	causes := map[string]error{
		"grpc/unix/rest NotFound": status.Error(codes.NotFound, "no report has been collected for device 9"),
		"mcp NotFound":            status.Error(codes.NotFound, "attestation: no report has been collected for device 9"),
	}
	for name, cause := range causes {
		for _, format := range []cli.OutputFormat{cli.OutputFormatTable, cli.OutputFormatJSON, cli.OutputFormatYAML} {
			t.Run(name+"/"+string(format), func(t *testing.T) {
				r, out := newRunner(&fakeAttestationClient{getErr: cause}, format)
				err := r.getReport("9")

				var never ErrNeverCollected
				require.ErrorAs(t, err, &never)
				assert.Equal(t, "9", never.DeviceID)
				assert.Contains(t, err.Error(), "has never been collected")

				var failed ErrGetReportFailed
				assert.False(t, errors.As(err, &failed), "never collected must not read as a failed read")
				assert.Empty(t, out.String(), "never collected must print no report in any format")
				assert.NotContains(t, out.String(), "verified")
				assert.NotContains(t, out.String(), "Verdict")
			})
		}
	}
}

func TestGetReport_OtherErrors(t *testing.T) {
	r, out := newRunner(&fakeAttestationClient{getErr: status.Error(codes.PermissionDenied, "admin role required")}, cli.OutputFormatTable)
	err := r.getReport("9")
	var typed ErrGetReportFailed
	require.ErrorAs(t, err, &typed)
	assert.Equal(t, "9", typed.DeviceID)
	assert.Contains(t, err.Error(), "admin role required")
	var never ErrNeverCollected
	assert.False(t, errors.As(err, &never))
	assert.Empty(t, out.String())
}

// reports refresh ---------------------------------------------------------------

func TestRefreshReport_Table(t *testing.T) {
	fake := &fakeAttestationClient{refreshResp: &platformv1.RefreshDeviceReportResponse{
		DeviceId: "9", Enqueued: true,
		Note: "collection enqueued with the collector; read the report for the verdict and its age",
	}}
	r, out := newRunner(fake, cli.OutputFormatTable)
	require.NoError(t, r.refreshReport("9"))
	assert.Equal(t, "9", fake.refreshReq.GetDeviceId())
	checkGolden(t, "report_refresh", out.Bytes())
	assert.Contains(t, out.String(), "Enqueued: yes")
	// The refresh never claims a verdict.
	assert.NotContains(t, strings.ToLower(out.String()), "verified")
}

func TestRefreshReport_JSON(t *testing.T) {
	fake := &fakeAttestationClient{refreshResp: &platformv1.RefreshDeviceReportResponse{Enqueued: true, Note: "n"}}
	r, out := newRunner(fake, cli.OutputFormatJSON)
	require.NoError(t, r.refreshReport("9"))
	var got refreshOutput
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	assert.Equal(t, refreshOutput{DeviceID: "9", Enqueued: true, Note: "n"}, got,
		"a server that omits device_id still yields the id the operator asked for")
}

func TestRefreshReport_Error(t *testing.T) {
	r, out := newRunner(&fakeAttestationClient{refreshErr: status.Error(codes.Unavailable, "collector stopped")}, cli.OutputFormatTable)
	err := r.refreshReport("9")
	var typed ErrRefreshFailed
	require.ErrorAs(t, err, &typed)
	assert.Equal(t, "9", typed.DeviceID)
	assert.Contains(t, err.Error(), "collector stopped")
	assert.Empty(t, out.String())
}

// callers -----------------------------------------------------------------------

func policy() *platformv1.CallerPolicyDescription {
	return &platformv1.CallerPolicyDescription{
		Strategy: "identity-list", Identities: []string{"cp.example.internal"},
		IdentitiesSource: "attestation.callers.identities", ListValid: true,
		AnchorsConfigured: true, AnchorSource: "platform-anchor",
	}
}

func TestDescribeCallers_Table(t *testing.T) {
	r, out := newRunner(&fakeAttestationClient{describeResp: &platformv1.DescribeCallerPolicyResponse{Policy: policy()}}, cli.OutputFormatTable)
	require.NoError(t, r.describeCallers())
	checkGolden(t, "callers", out.Bytes())
	assert.Contains(t, out.String(), "Strategy: identity-list")
	assert.Contains(t, out.String(), "Admits nobody: no")
	assert.Contains(t, out.String(), "Identities: cp.example.internal")
}

func TestDescribeCallers_TableAdmitsNobody(t *testing.T) {
	resp := &platformv1.DescribeCallerPolicyResponse{Policy: &platformv1.CallerPolicyDescription{
		Strategy: "identity-list", InvalidEntries: []string{"not a name"}, AdmitsNobody: true,
	}}
	r, out := newRunner(&fakeAttestationClient{describeResp: resp}, cli.OutputFormatTable)
	require.NoError(t, r.describeCallers())
	assert.Contains(t, out.String(), "Admits nobody: yes")
	assert.Contains(t, out.String(), "Identities: none")
	assert.Contains(t, out.String(), "Identity list valid: no")
	assert.Contains(t, out.String(), "Invalid entries: not a name")
}

func TestDescribeCallers_JSONCarriesTheWireShape(t *testing.T) {
	r, out := newRunner(&fakeAttestationClient{describeResp: &platformv1.DescribeCallerPolicyResponse{Policy: policy()}}, cli.OutputFormatJSON)
	require.NoError(t, r.describeCallers())
	var raw map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &raw))
	assert.Equal(t, "identity-list", raw["strategy"])
	assert.Equal(t, []any{"cp.example.internal"}, raw["identities"])
	assert.Equal(t, true, raw["list_valid"])
	assert.Equal(t, false, raw["admits_nobody"])
	assert.Equal(t, "platform-anchor", raw["anchor_source"])
}

func TestDescribeCallers_Error(t *testing.T) {
	r, out := newRunner(&fakeAttestationClient{describeErr: status.Error(codes.Unavailable, "not configured")}, cli.OutputFormatTable)
	err := r.describeCallers()
	var typed ErrDescribeCallersFailed
	require.ErrorAs(t, err, &typed)
	assert.Empty(t, out.String())
}

// Rendering helpers -------------------------------------------------------------

func TestVerdictLabel(t *testing.T) {
	assert.Equal(t, "verified", verdictLabel(reporting.View{Verified: true}))
	assert.Equal(t, "failed", verdictLabel(reporting.View{CryptographicFailure: true}))
	assert.Equal(t, "not verified", verdictLabel(reporting.View{}))
	// Verified wins regardless of the failure flag: the server never sets both.
	assert.Equal(t, "verified", verdictLabel(reporting.View{Verified: true, CryptographicFailure: true}))
}

func TestVerdictWithAge_AlwaysCarriesFreshnessAndAge(t *testing.T) {
	for _, v := range []reporting.View{
		{Verified: true, Fresh: true, AgeSeconds: 0},
		{Verified: true, Fresh: false, AgeSeconds: 86400},
		{CryptographicFailure: true, Fresh: true, AgeSeconds: 5},
		{Fresh: false, AgeSeconds: 61},
	} {
		line := verdictWithAge(v)
		assert.Regexp(t, `^(verified|failed|not verified) \((fresh|stale), age [0-9hms.]+\)$`, line)
	}
	assert.Equal(t, "verified (stale, age 24h0m0s)", verdictWithAge(reporting.View{Verified: true, AgeSeconds: 86400}))
}

func TestFormatHelpers(t *testing.T) {
	assert.Equal(t, "0s", formatAge(0))
	assert.Equal(t, "1h1m1s", formatAge(3661))
	assert.Equal(t, "-", formatTime(time.Time{}))
	assert.Equal(t, "2026-09-05T12:00:00Z", formatTime(attestedAt.In(time.FixedZone("x", 3600))))
	assert.Equal(t, "none", listOrNone(nil))
	assert.Equal(t, "a, b", listOrNone([]string{"a", "b"}))
	assert.Equal(t, "none evaluated", baselineLabel(reporting.View{}))
	assert.Equal(t, "tofu", baselineLabel(reporting.View{PCRBaselineSource: "tofu"}))
}

func TestViewFromProto_RoundTripsEveryField(t *testing.T) {
	v := viewFromProto(failedReport())
	assert.Equal(t, reporting.View{
		DeviceID: "12", Serial: "SN-12", Model: "X10SDV-TLN4F",
		AKCertificateVerified: true, SignatureValid: true, NonceValid: true, PCRsValid: false,
		CryptographicFailure: true, PCRBaselineSource: "tofu", PCRBaselineCaptured: true,
		Status: "failed", Message: "PCR 7 does not match the baseline",
		AttestedAt: attestedAt, CollectedAt: collectedAt, Fresh: false, AgeSeconds: 3725, AsOf: asOf,
		TimeSynced: proto.Bool(false),
	}, v)

	// Absent stays absent: the generated getter would collapse it to
	// false, which is the one distinction the field exists to keep.
	assert.Nil(t, viewFromProto(notVerifiedReport()).TimeSynced,
		"a report with no clock state must not render as unsynced")

	empty := viewFromProto(&platformv1.DeviceAttestationReport{})
	assert.True(t, empty.AttestedAt.IsZero())
	assert.True(t, empty.PCRBaselineRecordedAt.IsZero())
	assert.True(t, viewFromProto(nil).AsOf.IsZero(), "a nil report renders as zero values, never panics")
}

func TestDescriptionFromProto(t *testing.T) {
	d := descriptionFromProto(policy())
	assert.EqualValues(t, "identity-list", d.Strategy)
	assert.Equal(t, []string{"cp.example.internal"}, d.Identities)
	assert.True(t, d.ListValid)
	assert.True(t, d.AnchorsConfigured)
	assert.False(t, d.AdmitsNobody)
	assert.Zero(t, descriptionFromProto(nil).Strategy)
}

func TestErrors_Messages(t *testing.T) {
	assert.Contains(t, ErrInvalidDeviceID{ID: "x"}.Error(), `"x"`)
	assert.Contains(t, ErrNeverCollected{DeviceID: "9"}.Error(), "device 9 has never been collected")
	assert.Contains(t, ErrNeverCollected{DeviceID: "9"}.Error(), "platformctl attestation callers")
	assert.Contains(t, ErrListReportsFailed{Reason: "r"}.Error(), "r")
	assert.Contains(t, ErrGetReportFailed{DeviceID: "9", Reason: "r"}.Error(), "device 9: r")
	assert.Contains(t, ErrRefreshFailed{DeviceID: "9", Reason: "r"}.Error(), "device 9: r")
	assert.Contains(t, ErrDescribeCallersFailed{Reason: "r"}.Error(), "r")
}
