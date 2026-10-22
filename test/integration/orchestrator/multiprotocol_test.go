// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build integration

// Package orchestrator provides multi-protocol integration tests for the
// platformd OrchestratorService, the platform's view of the go-quicbaas agent
// fleet. The suite drives the operator CLI plus all five SDK transports
// (REST, gRPC, QUIC, MCP, Unix) against a live daemon and asserts feature
// parity: every transport must answer the same ten operations with the same
// shape, honour the same filters and paging, and refuse the same bad input.
//
// Run via:
//
//	make integration-test-orchestrator
package orchestrator

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// suiteTenant is the tenant the list and lookup cases run under.
const suiteTenant = "orchestrator-integration"

// TestOrchestratorMultiProtocol runs the shared scenario against every
// protocol.
func TestOrchestratorMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	adapters := []OrchestratorCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "orchestrator", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			t.Cleanup(func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			})
			runOrchestratorScenario(t, ctx, adapter)
		})
	}
}

// requireOK fails the test on err, naming a missing orchestrator client as
// the prerequisite it is rather than as a transport failure.
func requireOK(t *testing.T, cmd OrchestratorCommands, op string, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if IsNotConfigured(err) {
		t.Fatalf("missing prerequisite: %v", ErrOrchestratorNotConfigured{Transport: cmd.Name(), Err: err})
	}
	t.Fatalf("%s %s: %v", cmd.Name(), op, err)
}

// requireRefusal fails unless err is a refusal whose class is matched by
// accept.
func requireRefusal(t *testing.T, cmd OrchestratorCommands, op string, err error, class string, accept func(error) bool) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s %s: succeeded, want a %s refusal", cmd.Name(), op, class)
	}
	if IsNotConfigured(err) {
		t.Fatalf("missing prerequisite: %v", ErrOrchestratorNotConfigured{Transport: cmd.Name(), Err: err})
	}
	if !accept(err) {
		t.Fatalf("%s %s: %v, want a %s refusal", cmd.Name(), op, err, class)
	}
}

// invalidField returns a matcher for invalid-argument refusals that name
// field.
func invalidField(field string) func(error) bool {
	return func(err error) bool {
		return IsInvalidArgument(err) && strings.Contains(err.Error(), field)
	}
}

// requirePage checks the page info a list answered with: the server reports
// the page it applied, and never returns more records than the page holds or
// more than matched.
func requirePage(t *testing.T, cmd OrchestratorCommands, op string, page *platformv1.OrchestratorPageInfo, want *platformv1.OrchestratorPage, records int) {
	t.Helper()
	if page == nil {
		t.Fatalf("%s %s: response carries no page info", cmd.Name(), op)
	}
	if int(page.GetTotal()) < records {
		t.Fatalf("%s %s: total %d is below the %d records returned", cmd.Name(), op, page.GetTotal(), records)
	}
	if want == nil {
		return
	}
	if page.GetLimit() != want.GetLimit() || page.GetOffset() != want.GetOffset() {
		t.Fatalf("%s %s: applied page limit=%d offset=%d, want limit=%d offset=%d",
			cmd.Name(), op, page.GetLimit(), page.GetOffset(), want.GetLimit(), want.GetOffset())
	}
	if records > int(want.GetLimit()) {
		t.Fatalf("%s %s: %d records returned for a page of %d", cmd.Name(), op, records, want.GetLimit())
	}
}

// requireMatch fails when a listed record's field differs from a filter that
// was set.
func requireMatch(t *testing.T, cmd OrchestratorCommands, record, field, filter, got string) {
	t.Helper()
	if filter != "" && got != filter {
		t.Fatalf("%s: %s has %s %q, outside the %q filter", cmd.Name(), record, field, got, filter)
	}
}

// singlePage is the paging case every list runs.
var singlePage = &platformv1.OrchestratorPage{Limit: 1, Offset: 0}

// runOrchestratorScenario exercises the full orchestrator surface over one
// transport.
func runOrchestratorScenario(t *testing.T, ctx context.Context, cmd OrchestratorCommands) {
	t.Helper()

	// Identifiers no fleet holds, distinct per transport so one transport's
	// lookup cannot be satisfied by another's side effect.
	missing := "orchestrator-it-missing-" + strings.ToLower(cmd.Name())

	t.Run("Health", func(t *testing.T) {
		cctx, cancel := ShortContext(ctx)
		defer cancel()

		health, err := cmd.Health(cctx)
		requireOK(t, cmd, "Health", err)
		if health.GetStatus() == "" {
			t.Fatalf("%s: health carries no status", cmd.Name())
		}
		for component, status := range health.GetComponents() {
			if component == "" || status == "" {
				t.Fatalf("%s: health component %q has status %q", cmd.Name(), component, status)
			}
		}
	})

	t.Run("ListAgents", func(t *testing.T) {
		requests := map[string]*platformv1.ListOrchestratorAgentsRequest{
			"tenant":  {TenantId: suiteTenant},
			"filters": {TenantId: suiteTenant, Status: "active", Host: "orchestrator-it-host", Backend: "claude"},
			"page":    {TenantId: suiteTenant, Page: singlePage},
		}
		for name, req := range requests {
			t.Run(name, func(t *testing.T) {
				cctx, cancel := ShortContext(ctx)
				defer cancel()

				resp, err := cmd.ListAgents(cctx, req)
				requireOK(t, cmd, "ListAgents", err)
				requirePage(t, cmd, "ListAgents", resp.GetPage(), req.GetPage(), len(resp.GetAgents()))
				for _, agent := range resp.GetAgents() {
					if agent.GetId() == "" {
						t.Fatalf("%s: listed agent %+v has no id", cmd.Name(), agent)
					}
					record := "agent " + agent.GetId()
					requireMatch(t, cmd, record, "tenant", req.GetTenantId(), agent.GetTenantId())
					requireMatch(t, cmd, record, "status", req.GetStatus(), agent.GetStatus())
					requireMatch(t, cmd, record, "host", req.GetHost(), agent.GetHost())
					requireMatch(t, cmd, record, "backend", req.GetBackend(), agent.GetBackend())
				}
			})
		}
	})

	t.Run("ListSessions", func(t *testing.T) {
		requests := map[string]*platformv1.ListOrchestratorSessionsRequest{
			"all":     {},
			"filters": {Status: "active", JobId: "orchestrator-it-job", AgentId: "orchestrator-it-agent"},
			"page":    {Page: singlePage},
		}
		for name, req := range requests {
			t.Run(name, func(t *testing.T) {
				cctx, cancel := ShortContext(ctx)
				defer cancel()

				resp, err := cmd.ListSessions(cctx, req)
				requireOK(t, cmd, "ListSessions", err)
				requirePage(t, cmd, "ListSessions", resp.GetPage(), req.GetPage(), len(resp.GetSessions()))
				for _, session := range resp.GetSessions() {
					if session.GetSessionId() == "" {
						t.Fatalf("%s: listed session %+v has no id", cmd.Name(), session)
					}
					record := "session " + session.GetSessionId()
					requireMatch(t, cmd, record, "status", req.GetStatus(), session.GetStatus())
					requireMatch(t, cmd, record, "job", req.GetJobId(), session.GetJobId())
					requireMatch(t, cmd, record, "agent", req.GetAgentId(), session.GetAgentId())
				}
			})
		}
	})

	t.Run("ListJobs", func(t *testing.T) {
		requests := map[string]*platformv1.ListOrchestratorJobsRequest{
			"tenant":   {TenantId: suiteTenant},
			"statuses": {TenantId: suiteTenant, Statuses: []string{"running", "failed"}},
			"page":     {TenantId: suiteTenant, Page: singlePage},
		}
		for name, req := range requests {
			t.Run(name, func(t *testing.T) {
				cctx, cancel := ShortContext(ctx)
				defer cancel()

				resp, err := cmd.ListJobs(cctx, req)
				requireOK(t, cmd, "ListJobs", err)
				requirePage(t, cmd, "ListJobs", resp.GetPage(), req.GetPage(), len(resp.GetJobs()))
				for _, job := range resp.GetJobs() {
					if job.GetJobId() == "" {
						t.Fatalf("%s: listed job %+v has no id", cmd.Name(), job)
					}
					if len(req.GetStatuses()) > 0 && !slices.Contains(req.GetStatuses(), job.GetState()) {
						t.Fatalf("%s: job %s is %q, outside the %v filter",
							cmd.Name(), job.GetJobId(), job.GetState(), req.GetStatuses())
					}
				}
			})
		}
	})

	// Every lookup and mutation of a record the fleet does not hold answers
	// NotFound on every transport.
	t.Run("UnknownRecords", func(t *testing.T) {
		calls := map[string]func(context.Context) error{
			"GetAgent": func(ctx context.Context) error {
				_, err := cmd.GetAgent(ctx, &platformv1.GetOrchestratorAgentRequest{TenantId: suiteTenant, AgentId: missing})
				return err
			},
			"DisableAgent": func(ctx context.Context) error {
				_, err := cmd.DisableAgent(ctx, &platformv1.DisableOrchestratorAgentRequest{TenantId: suiteTenant, AgentId: missing})
				return err
			},
			"EnableAgent": func(ctx context.Context) error {
				_, err := cmd.EnableAgent(ctx, &platformv1.EnableOrchestratorAgentRequest{TenantId: suiteTenant, AgentId: missing})
				return err
			},
			"CloseSession": func(ctx context.Context) error {
				_, err := cmd.CloseSession(ctx, &platformv1.CloseOrchestratorSessionRequest{SessionId: missing})
				return err
			},
			"GetJob": func(ctx context.Context) error {
				_, err := cmd.GetJob(ctx, &platformv1.GetOrchestratorJobRequest{TenantId: suiteTenant, JobId: missing})
				return err
			},
			"CancelJob": func(ctx context.Context) error {
				_, err := cmd.CancelJob(ctx, &platformv1.CancelOrchestratorJobRequest{TenantId: suiteTenant, JobId: missing})
				return err
			},
		}
		for op, call := range calls {
			t.Run(op, func(t *testing.T) {
				cctx, cancel := ShortContext(ctx)
				defer cancel()
				requireRefusal(t, cmd, op, call(cctx), "not-found", IsNotFound)
			})
		}
	})

	// Bad input is refused before the fleet is reached, as InvalidArgument
	// naming the offending field, on every transport. The service layer
	// refuses it; the REST SDK refuses an empty path field before sending.
	t.Run("InvalidInput", func(t *testing.T) {
		calls := map[string]struct {
			call  func(context.Context) error
			field string
		}{
			"GetAgentWithoutTenant": {
				call: func(ctx context.Context) error {
					_, err := cmd.GetAgent(ctx, &platformv1.GetOrchestratorAgentRequest{AgentId: missing})
					return err
				},
				field: "tenant_id",
			},
			"ListJobsWithoutTenant": {
				call: func(ctx context.Context) error {
					_, err := cmd.ListJobs(ctx, &platformv1.ListOrchestratorJobsRequest{})
					return err
				},
				field: "tenant_id",
			},
			"CloseSessionWithoutID": {
				call: func(ctx context.Context) error {
					_, err := cmd.CloseSession(ctx, &platformv1.CloseOrchestratorSessionRequest{})
					return err
				},
				field: "session_id",
			},
			"ListAgentsWithNegativePage": {
				call: func(ctx context.Context) error {
					_, err := cmd.ListAgents(ctx, &platformv1.ListOrchestratorAgentsRequest{
						TenantId: suiteTenant,
						Page:     &platformv1.OrchestratorPage{Limit: -1},
					})
					return err
				},
				field: "limit",
			},
		}
		for op, tc := range calls {
			t.Run(op, func(t *testing.T) {
				cctx, cancel := ShortContext(ctx)
				defer cancel()
				requireRefusal(t, cmd, op, tc.call(cctx), "invalid-argument", invalidField(tc.field))
			})
		}
	})
}
