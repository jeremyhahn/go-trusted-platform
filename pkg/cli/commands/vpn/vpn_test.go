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

package vpn

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// errFakeClient is the failure a fake client answers with.
var errFakeClient = errors.New("fake client failure")

// fakeCLIClient records the last call and its arguments.
type fakeCLIClient struct {
	err  error
	call string
	args []string
}

func (f *fakeCLIClient) record(call string, args ...string) {
	f.call = call
	f.args = args
}

func (f *fakeCLIClient) EnrolPeer(_ context.Context, tenantID, deviceID string, zones []string) (*platformv1.VPNPeer, error) {
	f.record("EnrolPeer", tenantID, deviceID, strings.Join(zones, ","))
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.VPNPeer{TenantId: tenantID, DeviceId: deviceID, Zones: zones}, nil
}

func (f *fakeCLIClient) ListPeers(_ context.Context, tenantID string) ([]*platformv1.VPNPeer, error) {
	f.record("ListPeers", tenantID)
	if f.err != nil {
		return nil, f.err
	}
	return []*platformv1.VPNPeer{{TenantId: "acme", DeviceId: "laptop-1"}}, nil
}

func (f *fakeCLIClient) RevokePeer(_ context.Context, tenantID, deviceID string) error {
	f.record("RevokePeer", tenantID, deviceID)
	return f.err
}

func (f *fakeCLIClient) Status(_ context.Context, gatewayID string) ([]*platformv1.VPNGatewayStatus, error) {
	f.record("Status", gatewayID)
	if f.err != nil {
		return nil, f.err
	}
	return []*platformv1.VPNGatewayStatus{{
		GatewayId: "gw-1",
		Reporting: true,
		Running:   true,
		RejectedPeers: []*platformv1.VPNRejectedPeer{
			{TenantId: "acme", DeviceId: "laptop-9", Reason: `zone "storage" is not served by this gateway`},
		},
	}}, nil
}

func (f *fakeCLIClient) GetPosturePolicy(_ context.Context, tenantID, name string) (*platformv1.VPNPosturePolicy, error) {
	f.record("GetPosturePolicy", tenantID, name)
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.VPNPosturePolicy{TenantId: tenantID, Name: name, Module: "package vpn.posture"}, nil
}

func (f *fakeCLIClient) SetPosturePolicy(_ context.Context, tenantID, name, module string) (*platformv1.VPNPosturePolicy, error) {
	f.record("SetPosturePolicy", tenantID, name, module)
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.VPNPosturePolicy{TenantId: tenantID, Name: name, Module: module}, nil
}

func (f *fakeCLIClient) DeletePosturePolicy(_ context.Context, tenantID, name string) error {
	f.record("DeletePosturePolicy", tenantID, name)
	return f.err
}

func (f *fakeCLIClient) ListPosturePolicies(_ context.Context, tenantID string) ([]*platformv1.VPNPosturePolicy, error) {
	f.record("ListPosturePolicies", tenantID)
	if f.err != nil {
		return nil, f.err
	}
	return []*platformv1.VPNPosturePolicy{{TenantId: "acme", Name: "corp"}}, nil
}

// withFakeClient swaps the client factory and renderer for the test and
// returns where the last rendered value lands.
func withFakeClient(t *testing.T, fake *fakeCLIClient) *any {
	t.Helper()
	origFactory := newVPNClient
	origOutput := output
	var lastOutput any
	newVPNClient = func(*cli.CommonFlags) (vpnClient, func() error, error) {
		return fake, func() error { return nil }, nil
	}
	output = func(_ *cli.CommonFlags, v any) error {
		lastOutput = v
		return nil
	}
	t.Cleanup(func() {
		newVPNClient = origFactory
		output = origOutput
	})
	return &lastOutput
}

// execute runs the vpn command tree with table output.
func execute(t *testing.T, args ...string) error {
	t.Helper()
	return executeWithFlags(t, &cli.CommonFlags{}, args...)
}

// executeWithFlags runs the vpn command tree with the given global flags.
func executeWithFlags(t *testing.T, flags *cli.CommonFlags, args ...string) error {
	t.Helper()
	cmd := NewCommand(func() *cli.CommonFlags { return flags })
	cmd.SetArgs(args)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	return cmd.Execute()
}

// writeModule writes a posture module to a temporary file.
func writeModule(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "corp.rego")
	if err := os.WriteFile(path, []byte("package vpn.posture"), 0o600); err != nil {
		t.Fatalf("write module: %v", err)
	}
	return path
}

// commandCase is one command line, the client call it must make, and the
// error message it must wrap a failure in.
type commandCase struct {
	args     []string
	call     string
	callArgs []string
	failure  string
}

func commandCases(module string) []commandCase {
	return []commandCase{
		{[]string{"peer", "enrol", "laptop-1", "--tenant", "acme", "--zone", "management", "--zone", "storage"}, "EnrolPeer", []string{"acme", "laptop-1", "management,storage"}, "failed to enrol VPN peer"},
		{[]string{"peer", "list", "--tenant", "acme"}, "ListPeers", []string{"acme"}, "failed to list VPN peers"},
		{[]string{"peer", "revoke", "laptop-1", "--tenant", "acme"}, "RevokePeer", []string{"acme", "laptop-1"}, "failed to revoke VPN peer"},
		{[]string{"status", "--gateway", "gw-1"}, "Status", []string{"gw-1"}, "failed to get VPN status"},
		{[]string{"posture-policy", "list"}, "ListPosturePolicies", []string{""}, "failed to list VPN posture policies"},
		{[]string{"posture-policy", "get", "corp", "--tenant", "acme"}, "GetPosturePolicy", []string{"acme", "corp"}, "failed to get VPN posture policy"},
		{[]string{"posture-policy", "set", "corp", "--tenant", "acme", "--file", module}, "SetPosturePolicy", []string{"acme", "corp", "package vpn.posture"}, "failed to set VPN posture policy"},
		{[]string{"posture-policy", "delete", "corp", "--tenant", "acme"}, "DeletePosturePolicy", []string{"acme", "corp"}, "failed to delete VPN posture policy"},
	}
}

func TestVPNCommandsCallTheClient(t *testing.T) {
	cases := commandCases(writeModule(t))
	if len(cases) != len(platformv1.VPNService_ServiceDesc.Methods) {
		t.Fatalf("the CLI covers %d operations, VPNService has %d", len(cases), len(platformv1.VPNService_ServiceDesc.Methods))
	}
	for _, tc := range cases {
		t.Run(tc.call, func(t *testing.T) {
			fake := &fakeCLIClient{}
			lastOutput := withFakeClient(t, fake)
			if err := execute(t, tc.args...); err != nil {
				t.Fatalf("%v: %v", tc.args, err)
			}
			if fake.call != tc.call || !reflect.DeepEqual(fake.args, tc.callArgs) {
				t.Fatalf("called %s%v, want %s%v", fake.call, fake.args, tc.call, tc.callArgs)
			}
			if *lastOutput == nil {
				t.Fatal("nothing was rendered")
			}
		})
	}
}

func TestVPNCommandsRenderTables(t *testing.T) {
	fake := &fakeCLIClient{}
	lastOutput := withFakeClient(t, fake)
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatTable, NoColor: true}

	for _, tc := range commandCases(writeModule(t)) {
		if err := executeWithFlags(t, flags, tc.args...); err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		var buf bytes.Buffer
		if err := render(&buf, flags, *lastOutput); err != nil {
			t.Fatalf("%v: render: %v", tc.args, err)
		}
		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		if len(lines) < 2 {
			t.Fatalf("%v rendered %q, want a header and a row", tc.args, buf.String())
		}
		if strings.Contains(buf.String(), "headers:") || strings.Contains(buf.String(), "tenant_id:") {
			t.Fatalf("%v rendered YAML, want a table:\n%s", tc.args, buf.String())
		}
	}
}

func TestVPNStatusTableNamesTheRejectedPeer(t *testing.T) {
	fake := &fakeCLIClient{}
	lastOutput := withFakeClient(t, fake)
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatTable, NoColor: true}

	if err := executeWithFlags(t, flags, "status"); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := render(&buf, flags, *lastOutput); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"REJECTED PEERS", `acme/laptop-9: zone "storage" is not served by this gateway`} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("status table lacks %q:\n%s", want, buf.String())
		}
	}
}

func TestRenderRefusesAnUnknownOutputFormat(t *testing.T) {
	var buf bytes.Buffer
	err := render(&buf, &cli.CommonFlags{OutputFormat: "xml"}, statusTable(nil))

	var want cli.ErrInvalidOutputFormat
	if !errors.As(err, &want) {
		t.Fatalf("render error = %v, want cli.ErrInvalidOutputFormat", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("render wrote %q for a refused format", buf.String())
	}
}

func TestVPNCommandsEmitRawMessagesForStructuredOutput(t *testing.T) {
	fake := &fakeCLIClient{}
	lastOutput := withFakeClient(t, fake)
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	if err := executeWithFlags(t, flags, "status"); err != nil {
		t.Fatalf("status: %v", err)
	}
	if _, ok := (*lastOutput).([]*platformv1.VPNGatewayStatus); !ok {
		t.Fatalf("status output = %T, want []*platformv1.VPNGatewayStatus", *lastOutput)
	}

	if err := executeWithFlags(t, flags, "peer", "list"); err != nil {
		t.Fatalf("peer list: %v", err)
	}
	if _, ok := (*lastOutput).([]*platformv1.VPNPeer); !ok {
		t.Fatalf("peer list output = %T, want []*platformv1.VPNPeer", *lastOutput)
	}
}

func TestVPNCommandsWrapClientFailures(t *testing.T) {
	for _, tc := range commandCases(writeModule(t)) {
		t.Run(tc.call, func(t *testing.T) {
			withFakeClient(t, &fakeCLIClient{err: errFakeClient})
			err := execute(t, tc.args...)
			var wrapped *WrappedError
			if !errors.As(err, &wrapped) || !errors.Is(err, errFakeClient) {
				t.Fatalf("%v error = %v, want a WrappedError around the client failure", tc.args, err)
			}
			if !strings.Contains(err.Error(), tc.failure) {
				t.Fatalf("%v error = %q, want it to mention %q", tc.args, err, tc.failure)
			}
		})
	}
}

func TestVPNCommandsSurfaceFactoryFailures(t *testing.T) {
	factoryErr := errors.New("no daemon endpoint configured")
	origFactory := newVPNClient
	newVPNClient = func(*cli.CommonFlags) (vpnClient, func() error, error) {
		return nil, nil, factoryErr
	}
	t.Cleanup(func() { newVPNClient = origFactory })

	for _, tc := range commandCases(writeModule(t)) {
		if err := execute(t, tc.args...); !errors.Is(err, factoryErr) {
			t.Fatalf("%v error = %v, want the factory error", tc.args, err)
		}
	}
}

func TestVPNCommandsRequireTheTenant(t *testing.T) {
	fake := &fakeCLIClient{}
	withFakeClient(t, fake)

	for _, args := range [][]string{
		{"peer", "enrol", "laptop-1"},
		{"peer", "revoke", "laptop-1"},
		{"posture-policy", "get", "corp"},
		{"posture-policy", "set", "corp", "--file", writeModule(t)},
		{"posture-policy", "delete", "corp"},
	} {
		err := execute(t, args...)
		if err == nil || !strings.Contains(err.Error(), "tenant") {
			t.Fatalf("%v error = %v, want the missing --tenant refused", args, err)
		}
	}
	if fake.call != "" {
		t.Fatalf("a refused command still called %s", fake.call)
	}
}

func TestSetPosturePolicyRefusesAnUnreadableModule(t *testing.T) {
	fake := &fakeCLIClient{}
	withFakeClient(t, fake)

	missing := filepath.Join(t.TempDir(), "missing.rego")
	err := execute(t, "posture-policy", "set", "corp", "--tenant", "acme", "--file", missing)
	var wrapped *WrappedError
	if !errors.As(err, &wrapped) || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("set error = %v, want a WrappedError around fs.ErrNotExist", err)
	}
	if fake.call != "" {
		t.Fatalf("an unreadable module still called %s", fake.call)
	}
}

func TestServiceStateNamesEachGatewayState(t *testing.T) {
	cases := map[string]*platformv1.VPNGatewayStatus{
		"not configured": {},
		"running":        {Reporting: true, Running: true},
		"stopped":        {Reporting: true},
	}
	for want, gw := range cases {
		if got := serviceState(gw); got != want {
			t.Errorf("serviceState(%v) = %q, want %q", gw, got, want)
		}
	}
}

func TestPeersTableNamesUnrestrictedZonesAndUnsetTimes(t *testing.T) {
	table := peersTable([]*platformv1.VPNPeer{{TenantId: "acme", DeviceId: "laptop-1"}})
	if got := table.Rows[0]; got[2] != "all allowed" || got[3] != "never" {
		t.Fatalf("row = %v, want unrestricted zones and an unset enrolment time", got)
	}

	table = peersTable([]*platformv1.VPNPeer{{Zones: []string{"a", "b"}, EnrolledAtUnix: 1}})
	if got := table.Rows[0]; got[2] != "a,b" || got[3] != "1970-01-01T00:00:01Z" {
		t.Fatalf("row = %v, want the zones and the RFC 3339 time", got)
	}
}

func TestIsStructuredOutputHandlesMissingFlags(t *testing.T) {
	if isStructuredOutput(nil) {
		t.Fatal("nil flags reported structured output")
	}
	if !isStructuredOutput(&cli.CommonFlags{OutputFormat: cli.OutputFormatYAML}) {
		t.Fatal("YAML was not reported as structured output")
	}
}

func TestWrappedErrorKeepsTheCause(t *testing.T) {
	err := &WrappedError{Msg: "failed to list VPN peers", Err: errFakeClient}
	if err.Error() != "failed to list VPN peers: fake client failure" || !errors.Is(err, errFakeClient) {
		t.Fatalf("WrappedError = %q, want the message and the cause", err)
	}
}
