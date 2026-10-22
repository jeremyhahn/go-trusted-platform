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

package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

var errFakeClient = errors.New("orchestrator unreachable")

// fakeClient answers every OrchestratorService RPC with a fixed response, or
// with err when it is set, and records the last request.
type fakeClient struct {
	platformv1.OrchestratorServiceClient

	err     error
	request proto.Message
}

func answer[Resp proto.Message](f *fakeClient, req proto.Message, resp Resp) (Resp, error) {
	f.request = req
	if f.err != nil {
		var zero Resp
		return zero, f.err
	}
	return resp, nil
}

func (f *fakeClient) Health(_ context.Context, in *platformv1.OrchestratorHealthRequest, _ ...grpc.CallOption) (*platformv1.OrchestratorHealthResponse, error) {
	return answer(f, in, &platformv1.OrchestratorHealthResponse{Healthy: true, Status: "ok"})
}

func (f *fakeClient) ListAgents(_ context.Context, in *platformv1.ListOrchestratorAgentsRequest, _ ...grpc.CallOption) (*platformv1.ListOrchestratorAgentsResponse, error) {
	return answer(f, in, &platformv1.ListOrchestratorAgentsResponse{Agents: []*platformv1.OrchestratorAgent{{Id: "a1"}}})
}

func (f *fakeClient) GetAgent(_ context.Context, in *platformv1.GetOrchestratorAgentRequest, _ ...grpc.CallOption) (*platformv1.GetOrchestratorAgentResponse, error) {
	return answer(f, in, &platformv1.GetOrchestratorAgentResponse{Agent: &platformv1.OrchestratorAgent{Id: "a1"}})
}

func (f *fakeClient) DisableAgent(_ context.Context, in *platformv1.DisableOrchestratorAgentRequest, _ ...grpc.CallOption) (*platformv1.DisableOrchestratorAgentResponse, error) {
	return answer(f, in, &platformv1.DisableOrchestratorAgentResponse{AgentId: "a1", Disabled: true})
}

func (f *fakeClient) EnableAgent(_ context.Context, in *platformv1.EnableOrchestratorAgentRequest, _ ...grpc.CallOption) (*platformv1.EnableOrchestratorAgentResponse, error) {
	return answer(f, in, &platformv1.EnableOrchestratorAgentResponse{AgentId: "a1", Enabled: true})
}

func (f *fakeClient) ListSessions(_ context.Context, in *platformv1.ListOrchestratorSessionsRequest, _ ...grpc.CallOption) (*platformv1.ListOrchestratorSessionsResponse, error) {
	return answer(f, in, &platformv1.ListOrchestratorSessionsResponse{Sessions: []*platformv1.OrchestratorSession{{SessionId: "s1"}}})
}

func (f *fakeClient) CloseSession(_ context.Context, in *platformv1.CloseOrchestratorSessionRequest, _ ...grpc.CallOption) (*platformv1.CloseOrchestratorSessionResponse, error) {
	return answer(f, in, &platformv1.CloseOrchestratorSessionResponse{SessionId: "s1", Closed: true})
}

func (f *fakeClient) ListJobs(_ context.Context, in *platformv1.ListOrchestratorJobsRequest, _ ...grpc.CallOption) (*platformv1.ListOrchestratorJobsResponse, error) {
	return answer(f, in, &platformv1.ListOrchestratorJobsResponse{Jobs: []*platformv1.OrchestratorJob{{JobId: "j1"}}})
}

func (f *fakeClient) GetJob(_ context.Context, in *platformv1.GetOrchestratorJobRequest, _ ...grpc.CallOption) (*platformv1.GetOrchestratorJobResponse, error) {
	return answer(f, in, &platformv1.GetOrchestratorJobResponse{Job: &platformv1.OrchestratorJob{JobId: "j1"}})
}

func (f *fakeClient) CancelJob(_ context.Context, in *platformv1.CancelOrchestratorJobRequest, _ ...grpc.CallOption) (*platformv1.CancelOrchestratorJobResponse, error) {
	return answer(f, in, &platformv1.CancelOrchestratorJobResponse{JobId: "j1", Cancelled: true})
}

// withFakeClient points the command at fake and captures what it renders.
func withFakeClient(t *testing.T, fake *fakeClient) *any {
	t.Helper()
	origFactory := newOrchestratorClient
	origOutput := output
	var lastOutput any
	newOrchestratorClient = func(*cli.CommonFlags) (platformv1.OrchestratorServiceClient, func() error, error) {
		return fake, func() error { return nil }, nil
	}
	output = func(_ *cli.CommonFlags, v any) error {
		lastOutput = v
		return nil
	}
	t.Cleanup(func() {
		newOrchestratorClient = origFactory
		output = origOutput
	})
	return &lastOutput
}

func execute(t *testing.T, flags *cli.CommonFlags, args ...string) error {
	t.Helper()
	cmd := NewCommand(func() *cli.CommonFlags { return flags })
	cmd.SetArgs(args)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	return cmd.Execute()
}

// commandCase is one command line, the request the daemon must receive, the
// response the fake answers with, and the failure message it wraps errors in.
type commandCase struct {
	args     []string
	request  proto.Message
	response proto.Message
	failure  string
}

var commandCases = map[string]commandCase{
	"health": {
		args:     []string{"health"},
		request:  &platformv1.OrchestratorHealthRequest{},
		response: &platformv1.OrchestratorHealthResponse{Healthy: true, Status: "ok"},
		failure:  "failed to get orchestrator health",
	},
	"agent list": {
		args: []string{"agent", "list", "--tenant", "acme", "--status", "active", "--host", "h1",
			"--backend", "claude", "--limit", "10", "--offset", "20"},
		request: &platformv1.ListOrchestratorAgentsRequest{
			TenantId: "acme", Status: "active", Host: "h1", Backend: "claude",
			Page: &platformv1.OrchestratorPage{Limit: 10, Offset: 20},
		},
		response: &platformv1.ListOrchestratorAgentsResponse{Agents: []*platformv1.OrchestratorAgent{{Id: "a1"}}},
		failure:  "failed to list agents",
	},
	"agent get": {
		args:     []string{"agent", "get", "a1", "--tenant", "acme"},
		request:  &platformv1.GetOrchestratorAgentRequest{TenantId: "acme", AgentId: "a1"},
		response: &platformv1.GetOrchestratorAgentResponse{Agent: &platformv1.OrchestratorAgent{Id: "a1"}},
		failure:  "failed to get agent",
	},
	"agent disable": {
		args:     []string{"agent", "disable", "a1", "--tenant", "acme"},
		request:  &platformv1.DisableOrchestratorAgentRequest{TenantId: "acme", AgentId: "a1"},
		response: &platformv1.DisableOrchestratorAgentResponse{AgentId: "a1", Disabled: true},
		failure:  "failed to disable agent",
	},
	"agent enable": {
		args:     []string{"agent", "enable", "a1", "--tenant", "acme"},
		request:  &platformv1.EnableOrchestratorAgentRequest{TenantId: "acme", AgentId: "a1"},
		response: &platformv1.EnableOrchestratorAgentResponse{AgentId: "a1", Enabled: true},
		failure:  "failed to enable agent",
	},
	"session list": {
		// No --limit/--offset: the request carries no page.
		args:     []string{"session", "list", "--status", "open", "--job", "j1", "--agent", "a1"},
		request:  &platformv1.ListOrchestratorSessionsRequest{Status: "open", JobId: "j1", AgentId: "a1"},
		response: &platformv1.ListOrchestratorSessionsResponse{Sessions: []*platformv1.OrchestratorSession{{SessionId: "s1"}}},
		failure:  "failed to list sessions",
	},
	"session close": {
		args:     []string{"session", "close", "s1"},
		request:  &platformv1.CloseOrchestratorSessionRequest{SessionId: "s1"},
		response: &platformv1.CloseOrchestratorSessionResponse{SessionId: "s1", Closed: true},
		failure:  "failed to close session",
	},
	"job list": {
		args:     []string{"job", "list", "--tenant", "acme", "--status", "running", "--status", "failed"},
		request:  &platformv1.ListOrchestratorJobsRequest{TenantId: "acme", Statuses: []string{"running", "failed"}},
		response: &platformv1.ListOrchestratorJobsResponse{Jobs: []*platformv1.OrchestratorJob{{JobId: "j1"}}},
		failure:  "failed to list jobs",
	},
	"job get": {
		args:     []string{"job", "get", "j1", "--tenant", "acme"},
		request:  &platformv1.GetOrchestratorJobRequest{TenantId: "acme", JobId: "j1"},
		response: &platformv1.GetOrchestratorJobResponse{Job: &platformv1.OrchestratorJob{JobId: "j1"}},
		failure:  "failed to get job",
	},
	"job cancel": {
		args:     []string{"job", "cancel", "j1", "--tenant", "acme"},
		request:  &platformv1.CancelOrchestratorJobRequest{TenantId: "acme", JobId: "j1"},
		response: &platformv1.CancelOrchestratorJobResponse{JobId: "j1", Cancelled: true},
		failure:  "failed to cancel job",
	},
}

func TestOrchestratorCommandsSendTheRequestAndRenderATable(t *testing.T) {
	for name, tc := range commandCases {
		t.Run(name, func(t *testing.T) {
			fake := &fakeClient{}
			rendered := withFakeClient(t, fake)

			if err := execute(t, &cli.CommonFlags{}, tc.args...); err != nil {
				t.Fatalf("%s error = %v", name, err)
			}
			if !proto.Equal(fake.request, tc.request) {
				t.Fatalf("daemon received %v, want %v", fake.request, tc.request)
			}
			table, ok := (*rendered).(*cli.TableData)
			if !ok {
				t.Fatalf("rendered %T, want *cli.TableData", *rendered)
			}
			if len(table.Rows) == 0 {
				t.Fatalf("%s rendered an empty table", name)
			}
		})
	}
}

func TestOrchestratorCommandsEmitTheResponseMessageForStructuredOutput(t *testing.T) {
	for _, format := range []cli.OutputFormat{cli.OutputFormatJSON, cli.OutputFormatYAML} {
		for name, tc := range commandCases {
			t.Run(string(format)+"/"+name, func(t *testing.T) {
				rendered := withFakeClient(t, &fakeClient{})

				if err := execute(t, &cli.CommonFlags{OutputFormat: format}, tc.args...); err != nil {
					t.Fatalf("%s error = %v", name, err)
				}
				got, ok := (*rendered).(proto.Message)
				if !ok || !proto.Equal(got, tc.response) {
					t.Fatalf("rendered %v, want the response message %v", *rendered, tc.response)
				}
			})
		}
	}
}

func TestOrchestratorCommandsWrapClientFailures(t *testing.T) {
	for name, tc := range commandCases {
		t.Run(name, func(t *testing.T) {
			rendered := withFakeClient(t, &fakeClient{err: errFakeClient})

			err := execute(t, &cli.CommonFlags{}, tc.args...)
			if !errors.Is(err, errFakeClient) {
				t.Fatalf("%s error = %v, want it to unwrap to the client failure", name, err)
			}
			var wrapped *WrappedError
			if !errors.As(err, &wrapped) || wrapped.Msg != tc.failure {
				t.Fatalf("%s error = %q, want it wrapped as %q", name, err, tc.failure)
			}
			if *rendered != nil {
				t.Fatalf("%s rendered %v on failure", name, *rendered)
			}
		})
	}
}

func TestOrchestratorCommandsSurfaceFactoryFailures(t *testing.T) {
	factoryErr := errors.New("no daemon endpoint configured")
	origFactory := newOrchestratorClient
	newOrchestratorClient = func(*cli.CommonFlags) (platformv1.OrchestratorServiceClient, func() error, error) {
		return nil, nil, factoryErr
	}
	t.Cleanup(func() { newOrchestratorClient = origFactory })

	for name, tc := range commandCases {
		t.Run(name, func(t *testing.T) {
			if err := execute(t, &cli.CommonFlags{}, tc.args...); !errors.Is(err, factoryErr) {
				t.Fatalf("%s error = %v, want the factory error", name, err)
			}
		})
	}
}

func TestOrchestratorCommandsRefuseWrongArgumentCounts(t *testing.T) {
	cases := [][]string{
		{"health", "extra"},
		{"agent", "list", "extra"},
		{"agent", "get"},
		{"agent", "disable"},
		{"agent", "enable", "a1", "a2"},
		{"session", "close"},
		{"job", "get"},
		{"job", "cancel"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			fake := &fakeClient{}
			withFakeClient(t, fake)

			if err := execute(t, &cli.CommonFlags{}, args...); err == nil {
				t.Fatalf("%v = nil error, want an argument error", args)
			}
			if fake.request != nil {
				t.Fatalf("%v reached the daemon with %v", args, fake.request)
			}
		})
	}
}

func TestHealthTableListsComponentsInNameOrderAndFlagsUnhealthy(t *testing.T) {
	table := healthTable(&platformv1.OrchestratorHealthResponse{
		Healthy:    false,
		Status:     "degraded",
		Components: map[string]string{"scheduler": "ok", "registry": "down"},
	})

	want := [][]string{
		{"orchestrator", "degraded (unhealthy)"},
		{"registry", "down"},
		{"scheduler", "ok"},
	}
	if len(table.Rows) != len(want) {
		t.Fatalf("rows = %v, want %v", table.Rows, want)
	}
	for i, row := range want {
		if strings.Join(table.Rows[i], "|") != strings.Join(row, "|") {
			t.Fatalf("row %d = %v, want %v", i, table.Rows[i], row)
		}
	}
}

func TestFormatUnixRendersUTCAndAPlaceholderForUnset(t *testing.T) {
	if got := formatUnix(0); got != "-" {
		t.Fatalf("formatUnix(0) = %q, want -", got)
	}
	if got := formatUnix(-5); got != "-" {
		t.Fatalf("formatUnix(-5) = %q, want -", got)
	}
	if got := formatUnix(1700000000); got != "2023-11-14T22:13:20Z" {
		t.Fatalf("formatUnix(1700000000) = %q, want 2023-11-14T22:13:20Z", got)
	}
}

func TestPageFlagsSendNoPageUntilOneIsSet(t *testing.T) {
	if page := (&pageFlags{}).page(); page != nil {
		t.Fatalf("page() = %v, want nil for unset flags", page)
	}
	page := (&pageFlags{offset: 40}).page()
	if page == nil || page.GetOffset() != 40 || page.GetLimit() != 0 {
		t.Fatalf("page() = %v, want offset 40 with the default limit", page)
	}
}

func TestRenderWritesTheTableAndRefusesAnUnknownFormat(t *testing.T) {
	table := cli.NewTableData("JOB", "STATE")
	table.AddRow("j1", "running")

	var buf bytes.Buffer
	if err := render(&buf, &cli.CommonFlags{OutputFormat: cli.OutputFormatTable, NoColor: true}, table); err != nil {
		t.Fatalf("render(table) error = %v", err)
	}
	if !strings.Contains(buf.String(), "running") {
		t.Fatalf("render(table) = %q, want the row", buf.String())
	}

	var refused cli.ErrInvalidOutputFormat
	if err := render(&bytes.Buffer{}, &cli.CommonFlags{OutputFormat: "xml"}, table); !errors.As(err, &refused) {
		t.Fatalf("render(xml) error = %v, want cli.ErrInvalidOutputFormat", err)
	}
}
