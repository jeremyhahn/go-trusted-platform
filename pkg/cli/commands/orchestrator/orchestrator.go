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

// Package orchestrator implements `platformctl orchestrator`: the operator's
// view of the go-quicbaas agent fleet (health, agents, sessions and jobs).
// Every command calls the platform OrchestratorService through the sdk/go
// client, so it works over every transport the context selects.
package orchestrator

import (
	"context"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// defaultCLITimeout bounds a single orchestrator command end to end.
const defaultCLITimeout = 30 * time.Second

func newCLIContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), defaultCLITimeout)
}

// clientFactory returns an OrchestratorService client for the configured
// context plus the function that closes its connection. Tests replace it.
type clientFactory func(flags *cli.CommonFlags) (platformv1.OrchestratorServiceClient, func() error, error)

// newOrchestratorClient connects through the sdk/go client, which picks the
// transport (embedded, REST, gRPC, QUIC, MCP or Unix) from the context.
var newOrchestratorClient clientFactory = func(flags *cli.CommonFlags) (platformv1.OrchestratorServiceClient, func() error, error) {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return nil, nil, err
	}
	return base.Client().Orchestrator(), base.Close, nil
}

// outputFunc renders a command result. Tests replace output to capture it.
type outputFunc func(flags *cli.CommonFlags, v any) error

var output outputFunc = func(flags *cli.CommonFlags, v any) error {
	return render(os.Stdout, flags, v)
}

func render(w io.Writer, flags *cli.CommonFlags, v any) error {
	return cli.NewPrinterWithWriter(flags.OutputFormat, flags.NoColor, w).Print(v)
}

// NewCommand returns the `orchestrator` command group.
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "orchestrator",
		Short: "Inspect and control the go-quicbaas agent fleet",
		Long: `Inspect and control the go-quicbaas agent fleet: orchestrator health,
registered agents, agent sessions and orchestration jobs.

The platform holds no fleet state; every answer comes from the go-quicbaas
orchestrator. Reads need the orchestrator:read scope; disable, enable,
session close and job cancel need orchestrator:write.

Examples:
  platformctl orchestrator health
  platformctl orchestrator agent list --tenant acme --status active
  platformctl orchestrator agent disable a1 --tenant acme
  platformctl orchestrator session list --agent a1
  platformctl orchestrator session close s1
  platformctl orchestrator job list --tenant acme --status running --status failed
  platformctl orchestrator job cancel j1 --tenant acme -o json`,
	}

	cmd.AddCommand(newHealthCommand(getFlags))
	cmd.AddCommand(newAgentCommand(getFlags))
	cmd.AddCommand(newSessionCommand(getFlags))
	cmd.AddCommand(newJobCommand(getFlags))

	return cmd
}

// run executes one OrchestratorService RPC and renders its response: the
// response message itself for JSON/YAML, otherwise its table.
func run[Resp proto.Message](
	flags *cli.CommonFlags,
	failure string,
	call func(context.Context, platformv1.OrchestratorServiceClient) (Resp, error),
	table func(Resp) *cli.TableData,
) error {
	client, closeFn, err := newOrchestratorClient(flags)
	if err != nil {
		return err
	}
	defer closeFn()

	ctx, cancel := newCLIContext()
	defer cancel()

	resp, err := call(ctx, client)
	if err != nil {
		return &WrappedError{Msg: failure, Err: err}
	}
	if isStructuredOutput(flags) {
		return output(flags, resp)
	}
	return output(flags, table(resp))
}

func isStructuredOutput(flags *cli.CommonFlags) bool {
	if flags == nil {
		return false
	}
	return flags.OutputFormat == cli.OutputFormatJSON || flags.OutputFormat == cli.OutputFormatYAML
}

// pageFlags are the --limit / --offset flags of a listing.
type pageFlags struct {
	limit  int32
	offset int32
}

func (p *pageFlags) register(cmd *cobra.Command) {
	cmd.Flags().Int32Var(&p.limit, "limit", 0, "page size; 0 takes the server's default")
	cmd.Flags().Int32Var(&p.offset, "offset", 0, "how many records to skip")
}

// page returns nil when neither flag was set, which takes the server's
// default page.
func (p *pageFlags) page() *platformv1.OrchestratorPage {
	if p.limit == 0 && p.offset == 0 {
		return nil
	}
	return &platformv1.OrchestratorPage{Limit: p.limit, Offset: p.offset}
}

// =============================================================================
// health
// =============================================================================

func newHealthCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:          "health",
		Short:        "Show the orchestrator's health and the status of each component",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(getFlags(), "failed to get orchestrator health",
				func(ctx context.Context, c platformv1.OrchestratorServiceClient) (*platformv1.OrchestratorHealthResponse, error) {
					return c.Health(ctx, &platformv1.OrchestratorHealthRequest{})
				}, healthTable)
		},
	}
}

// =============================================================================
// agent
// =============================================================================

func newAgentCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "List, inspect, disable and enable fleet agents",
	}
	cmd.AddCommand(newAgentListCommand(getFlags))
	cmd.AddCommand(newAgentGetCommand(getFlags))
	cmd.AddCommand(newAgentDisableCommand(getFlags))
	cmd.AddCommand(newAgentEnableCommand(getFlags))
	return cmd
}

func newAgentListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var req platformv1.ListOrchestratorAgentsRequest
	var page pageFlags
	cmd := &cobra.Command{
		Use:          "list",
		Short:        "List one page of a tenant's registered agents",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			req.Page = page.page()
			return run(getFlags(), "failed to list agents",
				func(ctx context.Context, c platformv1.OrchestratorServiceClient) (*platformv1.ListOrchestratorAgentsResponse, error) {
					return c.ListAgents(ctx, &req)
				}, func(resp *platformv1.ListOrchestratorAgentsResponse) *cli.TableData {
					return agentsTable(resp.GetAgents())
				})
		},
	}
	cmd.Flags().StringVar(&req.TenantId, "tenant", "", "tenant that owns the agents (required)")
	cmd.Flags().StringVar(&req.Status, "status", "", "only agents in this status")
	cmd.Flags().StringVar(&req.Host, "host", "", "only agents on this host")
	cmd.Flags().StringVar(&req.Backend, "backend", "", "only agents of this backend")
	page.register(cmd)
	return cmd
}

func newAgentGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenant string
	cmd := &cobra.Command{
		Use:          "get <agent-id>",
		Short:        "Show one registered agent",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &platformv1.GetOrchestratorAgentRequest{TenantId: tenant, AgentId: args[0]}
			return run(getFlags(), "failed to get agent",
				func(ctx context.Context, c platformv1.OrchestratorServiceClient) (*platformv1.GetOrchestratorAgentResponse, error) {
					return c.GetAgent(ctx, req)
				}, func(resp *platformv1.GetOrchestratorAgentResponse) *cli.TableData {
					return agentsTable([]*platformv1.OrchestratorAgent{resp.GetAgent()})
				})
		},
	}
	cmd.Flags().StringVar(&tenant, "tenant", "", "tenant that owns the agent (required)")
	return cmd
}

func newAgentDisableCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenant string
	cmd := &cobra.Command{
		Use:          "disable <agent-id>",
		Short:        "Disable an agent and revoke its credentials",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &platformv1.DisableOrchestratorAgentRequest{TenantId: tenant, AgentId: args[0]}
			return run(getFlags(), "failed to disable agent",
				func(ctx context.Context, c platformv1.OrchestratorServiceClient) (*platformv1.DisableOrchestratorAgentResponse, error) {
					return c.DisableAgent(ctx, req)
				}, func(resp *platformv1.DisableOrchestratorAgentResponse) *cli.TableData {
					table := cli.NewTableData("AGENT", "DISABLED", "DISABLED AT")
					table.AddRow(resp.GetAgentId(), strconv.FormatBool(resp.GetDisabled()), formatUnix(resp.GetDisabledAt()))
					return table
				})
		},
	}
	cmd.Flags().StringVar(&tenant, "tenant", "", "tenant that owns the agent (required)")
	return cmd
}

func newAgentEnableCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenant string
	cmd := &cobra.Command{
		Use:          "enable <agent-id>",
		Short:        "Re-activate a disabled agent",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &platformv1.EnableOrchestratorAgentRequest{TenantId: tenant, AgentId: args[0]}
			return run(getFlags(), "failed to enable agent",
				func(ctx context.Context, c platformv1.OrchestratorServiceClient) (*platformv1.EnableOrchestratorAgentResponse, error) {
					return c.EnableAgent(ctx, req)
				}, func(resp *platformv1.EnableOrchestratorAgentResponse) *cli.TableData {
					table := cli.NewTableData("AGENT", "ENABLED")
					table.AddRow(resp.GetAgentId(), strconv.FormatBool(resp.GetEnabled()))
					return table
				})
		},
	}
	cmd.Flags().StringVar(&tenant, "tenant", "", "tenant that owns the agent (required)")
	return cmd
}

// =============================================================================
// session
// =============================================================================

func newSessionCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "List and close agent sessions",
	}
	cmd.AddCommand(newSessionListCommand(getFlags))
	cmd.AddCommand(newSessionCloseCommand(getFlags))
	return cmd
}

func newSessionListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var req platformv1.ListOrchestratorSessionsRequest
	var page pageFlags
	cmd := &cobra.Command{
		Use:          "list",
		Short:        "List one page of agent sessions",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			req.Page = page.page()
			return run(getFlags(), "failed to list sessions",
				func(ctx context.Context, c platformv1.OrchestratorServiceClient) (*platformv1.ListOrchestratorSessionsResponse, error) {
					return c.ListSessions(ctx, &req)
				}, func(resp *platformv1.ListOrchestratorSessionsResponse) *cli.TableData {
					return sessionsTable(resp.GetSessions())
				})
		},
	}
	cmd.Flags().StringVar(&req.Status, "status", "", "only sessions in this status")
	cmd.Flags().StringVar(&req.JobId, "job", "", "only sessions of this job")
	cmd.Flags().StringVar(&req.AgentId, "agent", "", "only sessions of this agent")
	page.register(cmd)
	return cmd
}

func newSessionCloseCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:          "close <session-id>",
		Short:        "Terminate an agent session",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &platformv1.CloseOrchestratorSessionRequest{SessionId: args[0]}
			return run(getFlags(), "failed to close session",
				func(ctx context.Context, c platformv1.OrchestratorServiceClient) (*platformv1.CloseOrchestratorSessionResponse, error) {
					return c.CloseSession(ctx, req)
				}, func(resp *platformv1.CloseOrchestratorSessionResponse) *cli.TableData {
					table := cli.NewTableData("SESSION", "CLOSED")
					table.AddRow(resp.GetSessionId(), strconv.FormatBool(resp.GetClosed()))
					return table
				})
		},
	}
}

// =============================================================================
// job
// =============================================================================

func newJobCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "job",
		Short: "List, inspect and cancel orchestration jobs",
	}
	cmd.AddCommand(newJobListCommand(getFlags))
	cmd.AddCommand(newJobGetCommand(getFlags))
	cmd.AddCommand(newJobCancelCommand(getFlags))
	return cmd
}

func newJobListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var req platformv1.ListOrchestratorJobsRequest
	var page pageFlags
	cmd := &cobra.Command{
		Use:          "list",
		Short:        "List one page of a tenant's orchestration jobs",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			req.Page = page.page()
			return run(getFlags(), "failed to list jobs",
				func(ctx context.Context, c platformv1.OrchestratorServiceClient) (*platformv1.ListOrchestratorJobsResponse, error) {
					return c.ListJobs(ctx, &req)
				}, func(resp *platformv1.ListOrchestratorJobsResponse) *cli.TableData {
					return jobsTable(resp.GetJobs())
				})
		},
	}
	cmd.Flags().StringVar(&req.TenantId, "tenant", "", "tenant that owns the jobs (required)")
	cmd.Flags().StringSliceVar(&req.Statuses, "status", nil, "only jobs in this state (repeatable)")
	page.register(cmd)
	return cmd
}

func newJobGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenant string
	cmd := &cobra.Command{
		Use:          "get <job-id>",
		Short:        "Show the current status of one orchestration job",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &platformv1.GetOrchestratorJobRequest{TenantId: tenant, JobId: args[0]}
			return run(getFlags(), "failed to get job",
				func(ctx context.Context, c platformv1.OrchestratorServiceClient) (*platformv1.GetOrchestratorJobResponse, error) {
					return c.GetJob(ctx, req)
				}, func(resp *platformv1.GetOrchestratorJobResponse) *cli.TableData {
					return jobsTable([]*platformv1.OrchestratorJob{resp.GetJob()})
				})
		},
	}
	cmd.Flags().StringVar(&tenant, "tenant", "", "tenant that owns the job (required)")
	return cmd
}

func newJobCancelCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenant string
	cmd := &cobra.Command{
		Use:          "cancel <job-id>",
		Short:        "Cancel a running orchestration job",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &platformv1.CancelOrchestratorJobRequest{TenantId: tenant, JobId: args[0]}
			return run(getFlags(), "failed to cancel job",
				func(ctx context.Context, c platformv1.OrchestratorServiceClient) (*platformv1.CancelOrchestratorJobResponse, error) {
					return c.CancelJob(ctx, req)
				}, func(resp *platformv1.CancelOrchestratorJobResponse) *cli.TableData {
					table := cli.NewTableData("JOB", "CANCELLED")
					table.AddRow(resp.GetJobId(), strconv.FormatBool(resp.GetCancelled()))
					return table
				})
		},
	}
	cmd.Flags().StringVar(&tenant, "tenant", "", "tenant that owns the job (required)")
	return cmd
}

// =============================================================================
// tables
// =============================================================================

// healthTable lists the overall status first, then each component in name
// order so the output is stable.
func healthTable(resp *platformv1.OrchestratorHealthResponse) *cli.TableData {
	table := cli.NewTableData("COMPONENT", "STATUS")
	overall := resp.GetStatus()
	if !resp.GetHealthy() {
		overall += " (unhealthy)"
	}
	table.AddRow("orchestrator", overall)

	components := resp.GetComponents()
	names := make([]string, 0, len(components))
	for name := range components {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		table.AddRow(name, components[name])
	}
	return table
}

func agentsTable(agents []*platformv1.OrchestratorAgent) *cli.TableData {
	table := cli.NewTableData("ID", "NAME", "HOST", "BACKEND", "MODEL", "STATUS", "LAST SEEN")
	for _, agent := range agents {
		table.AddRow(
			agent.GetId(),
			agent.GetName(),
			agent.GetHost(),
			agent.GetBackend(),
			agent.GetModel(),
			agent.GetStatus(),
			formatUnix(agent.GetLastSeen()),
		)
	}
	return table
}

func sessionsTable(sessions []*platformv1.OrchestratorSession) *cli.TableData {
	table := cli.NewTableData("SESSION", "AGENT", "JOB", "BACKEND", "MODEL", "STATUS", "LAST ACTIVE")
	for _, session := range sessions {
		table.AddRow(
			session.GetSessionId(),
			session.GetAgentId(),
			session.GetJobId(),
			session.GetBackend(),
			session.GetModel(),
			session.GetStatus(),
			formatUnix(session.GetLastActive()),
		)
	}
	return table
}

func jobsTable(jobs []*platformv1.OrchestratorJob) *cli.TableData {
	table := cli.NewTableData("JOB", "STATE", "TASKS", "COMPLETED", "FAILED", "UPDATED", "DESCRIPTION")
	for _, job := range jobs {
		table.AddRow(
			job.GetJobId(),
			job.GetState(),
			strconv.FormatInt(int64(job.GetTaskCount()), 10),
			strconv.FormatInt(int64(job.GetCompleted()), 10),
			strconv.FormatInt(int64(job.GetFailed()), 10),
			formatUnix(job.GetUpdatedAt()),
			strings.TrimSpace(job.GetDescription()),
		)
	}
	return table
}

// formatUnix renders a Unix time in UTC, or "-" when it is unset.
func formatUnix(seconds int64) string {
	if seconds <= 0 {
		return "-"
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}
