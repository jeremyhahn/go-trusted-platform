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

package appsvc

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The enums the scheduler flags take.
var (
	jobTypeEnum   = platformv1.SchedulerJobType(0).Descriptor()
	jobStatusEnum = platformv1.SchedulerJobStatus(0).Descriptor()
	ownerTypeEnum = platformv1.SchedulerOwnerType(0).Descriptor()
)

// NewSchedulerCommand creates the scheduler command group.
func NewSchedulerCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scheduler",
		Short: "Create, inspect and control scheduled jobs",
		Long: `Create, inspect and control the jobs of the distributed scheduler.

A job runs a registered handler once (one-shot), after a delay (delayed) or
on a cron schedule (recurring). Job IDs are decimal.

Examples:
  # A recurring job, then its next runs and history
  platformctl scheduler create nightly-backup --type recurring \
      --handler backup --schedule "0 2 * * *" --tag team=storage
  platformctl scheduler list --status pending
  platformctl scheduler history 42 --since 2026-10-01T00:00:00Z

  # Run it now, hold it, release it, stop it
  platformctl scheduler trigger 42
  platformctl scheduler pause 42
  platformctl scheduler resume 42
  platformctl scheduler cancel 42 --reason "replaced by job 43"

  # Scheduler health
  platformctl scheduler status`,
	}

	cmd.AddCommand(
		newSchedulerCreateCommand(getFlags),
		newSchedulerListCommand(getFlags),
		newCommand(getFlags, "get JOB_ID", "Show one job", cobra.ExactArgs(1),
			func(flags *cli.CommonFlags, args []string) error {
				return call(flags, newSchedulerClient, "failed to get the job",
					platformv1.SchedulerServiceClient.GetJob, &platformv1.GetSchedulerJobRequest{JobId: args[0]},
					func(reply *platformv1.GetSchedulerJobResponse) *cli.TableData { return fieldsTable(reply.GetJob()) })
			}),
		newSchedulerUpdateCommand(getFlags),
		newCommand(getFlags, "delete JOB_ID", "Delete a job", cobra.ExactArgs(1),
			func(flags *cli.CommonFlags, args []string) error {
				return call(flags, newSchedulerClient, "failed to delete the job",
					platformv1.SchedulerServiceClient.DeleteJob, &platformv1.DeleteSchedulerJobRequest{JobId: args[0]},
					confirmation[*platformv1.DeleteSchedulerJobResponse]("job id", args[0], "deleted"))
			}),
		newCommand(getFlags, "trigger JOB_ID", "Run a job now, outside its schedule", cobra.ExactArgs(1),
			func(flags *cli.CommonFlags, args []string) error {
				return call(flags, newSchedulerClient, "failed to trigger the job",
					platformv1.SchedulerServiceClient.TriggerJob, &platformv1.TriggerSchedulerJobRequest{JobId: args[0]},
					fieldsTable[*platformv1.TriggerSchedulerJobResponse])
			}),
		newCommand(getFlags, "pause JOB_ID", "Hold a job: it does not run until resumed", cobra.ExactArgs(1),
			func(flags *cli.CommonFlags, args []string) error {
				return call(flags, newSchedulerClient, "failed to pause the job",
					platformv1.SchedulerServiceClient.PauseJob, &platformv1.PauseSchedulerJobRequest{JobId: args[0]},
					fieldsTable[*platformv1.PauseSchedulerJobResponse])
			}),
		newCommand(getFlags, "resume JOB_ID", "Release a paused job", cobra.ExactArgs(1),
			func(flags *cli.CommonFlags, args []string) error {
				return call(flags, newSchedulerClient, "failed to resume the job",
					platformv1.SchedulerServiceClient.ResumeJob, &platformv1.ResumeSchedulerJobRequest{JobId: args[0]},
					fieldsTable[*platformv1.ResumeSchedulerJobResponse])
			}),
		newSchedulerCancelCommand(getFlags),
		newSchedulerHistoryCommand(getFlags),
		newCommand(getFlags, "status", "Show the scheduler's health, job counts and queue depth", cobra.NoArgs,
			func(flags *cli.CommonFlags, _ []string) error {
				return call(flags, newSchedulerClient, "failed to get the scheduler status",
					platformv1.SchedulerServiceClient.GetStatus, &platformv1.GetSchedulerStatusRequest{},
					fieldsTable[*platformv1.GetSchedulerStatusResponse])
			}),
	)
	return cmd
}

// jobCreateOptions are the flags of `scheduler create`.
type jobCreateOptions struct {
	description  string
	jobType      string
	handler      string
	schedule     string
	executeAt    string
	delay        time.Duration
	payload      string
	ownerType    string
	ownerID      string
	maxRetries   int32
	timeout      time.Duration
	tags         map[string]string
	nodeAffinity string
}

// request builds the CreateJob request for a job named name.
func (o *jobCreateOptions) request(name string) (*platformv1.CreateSchedulerJobRequest, error) {
	jobType, err := parseEnum("type", jobTypeEnum, o.jobType)
	if err != nil {
		return nil, err
	}
	ownerType, err := parseEnum("owner-type", ownerTypeEnum, o.ownerType)
	if err != nil {
		return nil, err
	}
	executeAt, err := parseTime("execute-at", o.executeAt)
	if err != nil {
		return nil, err
	}
	return &platformv1.CreateSchedulerJobRequest{
		Name:            name,
		Description:     o.description,
		JobType:         platformv1.SchedulerJobType(jobType),
		Handler:         o.handler,
		Schedule:        o.schedule,
		ExecuteAtUnixMs: executeAt,
		DelayMs:         o.delay.Milliseconds(),
		Payload:         []byte(o.payload),
		OwnerType:       platformv1.SchedulerOwnerType(ownerType),
		OwnerId:         o.ownerID,
		MaxRetries:      o.maxRetries,
		TimeoutMs:       o.timeout.Milliseconds(),
		Tags:            o.tags,
		NodeAffinity:    o.nodeAffinity,
	}, nil
}

func newSchedulerCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &jobCreateOptions{}
	cmd := newCommand(getFlags, "create NAME", "Create a job", cobra.ExactArgs(1),
		func(flags *cli.CommonFlags, args []string) error {
			request, err := opts.request(args[0])
			if err != nil {
				return err
			}
			return call(flags, newSchedulerClient, "failed to create the job",
				platformv1.SchedulerServiceClient.CreateJob, request, fieldsTable[*platformv1.CreateSchedulerJobResponse])
		})
	f := cmd.Flags()
	f.StringVar(&opts.jobType, "type", "", enumUsage("job type (required)", jobTypeEnum))
	f.StringVar(&opts.handler, "handler", "", "registered handler that runs the job")
	f.StringVar(&opts.description, "description", "", "job description")
	f.StringVar(&opts.schedule, "schedule", "", "cron expression of a recurring job")
	f.StringVar(&opts.executeAt, "execute-at", "", "when a one-shot job runs, RFC 3339 (default now)")
	f.DurationVar(&opts.delay, "delay", 0, "how long after creation a delayed job runs")
	f.StringVar(&opts.payload, "payload", "", "payload handed to the handler")
	f.StringVar(&opts.ownerType, "owner-type", "", enumUsage("owner type (default system)", ownerTypeEnum))
	f.StringVar(&opts.ownerID, "owner-id", "", "owning tenant or delegate")
	f.Int32Var(&opts.maxRetries, "max-retries", 0, "retries after a failed run")
	f.DurationVar(&opts.timeout, "timeout", 0, "how long one run may take")
	f.StringToStringVar(&opts.tags, "tag", nil, "tag as key=value; repeatable")
	f.StringVar(&opts.nodeAffinity, "node-affinity", "", "node that runs the job (default the Raft leader)")
	markRequired(cmd, "type")
	return cmd
}

// jobListOptions are the flags of `scheduler list`.
type jobListOptions struct {
	status    string
	jobType   string
	ownerType string
	ownerID   string
	tags      map[string]string
	limit     int32
	offset    int32
}

// request builds the ListJobs request.
func (o *jobListOptions) request() (*platformv1.ListSchedulerJobsRequest, error) {
	status, err := parseEnum("status", jobStatusEnum, o.status)
	if err != nil {
		return nil, err
	}
	jobType, err := parseEnum("type", jobTypeEnum, o.jobType)
	if err != nil {
		return nil, err
	}
	ownerType, err := parseEnum("owner-type", ownerTypeEnum, o.ownerType)
	if err != nil {
		return nil, err
	}
	return &platformv1.ListSchedulerJobsRequest{
		OwnerType: platformv1.SchedulerOwnerType(ownerType),
		OwnerId:   o.ownerID,
		Status:    platformv1.SchedulerJobStatus(status),
		JobType:   platformv1.SchedulerJobType(jobType),
		Tags:      o.tags,
		Limit:     o.limit,
		Offset:    o.offset,
	}, nil
}

func newSchedulerListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &jobListOptions{}
	cmd := newCommand(getFlags, "list", "List jobs", cobra.NoArgs,
		func(flags *cli.CommonFlags, _ []string) error {
			request, err := opts.request()
			if err != nil {
				return err
			}
			return call(flags, newSchedulerClient, "failed to list the jobs",
				platformv1.SchedulerServiceClient.ListJobs, request,
				func(reply *platformv1.ListSchedulerJobsResponse) *cli.TableData {
					return listTable(reply.GetJobs(), "job_id", "name", "job_type", "status", "schedule", "next_run_at_unix_ms")
				})
		})
	f := cmd.Flags()
	f.StringVar(&opts.status, "status", "", enumUsage("only jobs in this status", jobStatusEnum))
	f.StringVar(&opts.jobType, "type", "", enumUsage("only jobs of this type", jobTypeEnum))
	f.StringVar(&opts.ownerType, "owner-type", "", enumUsage("only jobs of this owner type", ownerTypeEnum))
	f.StringVar(&opts.ownerID, "owner-id", "", "only jobs of this owner")
	f.StringToStringVar(&opts.tags, "tag", nil, "only jobs with this key=value tag; repeatable")
	f.Int32Var(&opts.limit, "limit", 0, "most jobs to return")
	f.Int32Var(&opts.offset, "offset", 0, "jobs to skip")
	return cmd
}

// jobUpdateOptions are the flags of `scheduler update`. Only the fields set
// to a non-zero value change.
type jobUpdateOptions struct {
	name        string
	description string
	schedule    string
	delay       time.Duration
	payload     string
	maxRetries  int32
	timeout     time.Duration
	tags        map[string]string
}

func newSchedulerUpdateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &jobUpdateOptions{}
	cmd := newCommand(getFlags, "update JOB_ID", "Change a job; only the settings given change", cobra.ExactArgs(1),
		func(flags *cli.CommonFlags, args []string) error {
			request := &platformv1.UpdateSchedulerJobRequest{
				JobId:       args[0],
				Name:        opts.name,
				Description: opts.description,
				Schedule:    opts.schedule,
				DelayMs:     opts.delay.Milliseconds(),
				Payload:     []byte(opts.payload),
				MaxRetries:  opts.maxRetries,
				TimeoutMs:   opts.timeout.Milliseconds(),
				Tags:        opts.tags,
			}
			return call(flags, newSchedulerClient, "failed to update the job",
				platformv1.SchedulerServiceClient.UpdateJob, request,
				func(reply *platformv1.UpdateSchedulerJobResponse) *cli.TableData { return fieldsTable(reply.GetJob()) })
		})
	f := cmd.Flags()
	f.StringVar(&opts.name, "name", "", "new name")
	f.StringVar(&opts.description, "description", "", "new description")
	f.StringVar(&opts.schedule, "schedule", "", "new cron expression")
	f.DurationVar(&opts.delay, "delay", 0, "new delay")
	f.StringVar(&opts.payload, "payload", "", "new payload")
	f.Int32Var(&opts.maxRetries, "max-retries", 0, "new retry limit")
	f.DurationVar(&opts.timeout, "timeout", 0, "new run timeout")
	f.StringToStringVar(&opts.tags, "tag", nil, "new tags as key=value; repeatable")
	return cmd
}

func newSchedulerCancelCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var reason string
	cmd := newCommand(getFlags, "cancel JOB_ID", "Stop a job for good", cobra.ExactArgs(1),
		func(flags *cli.CommonFlags, args []string) error {
			return call(flags, newSchedulerClient, "failed to cancel the job",
				platformv1.SchedulerServiceClient.CancelJob,
				&platformv1.CancelSchedulerJobRequest{JobId: args[0], Reason: reason},
				fieldsTable[*platformv1.CancelSchedulerJobResponse])
		})
	cmd.Flags().StringVar(&reason, "reason", "", "why the job is canceled")
	return cmd
}

// jobHistoryOptions are the flags of `scheduler history`.
type jobHistoryOptions struct {
	limit  int32
	offset int32
	since  string
	until  string
	status string
}

// request builds the GetJobHistory request for one job.
func (o *jobHistoryOptions) request(jobID string) (*platformv1.GetSchedulerJobHistoryRequest, error) {
	since, err := parseTime("since", o.since)
	if err != nil {
		return nil, err
	}
	until, err := parseTime("until", o.until)
	if err != nil {
		return nil, err
	}
	status, err := parseEnum("status", jobStatusEnum, o.status)
	if err != nil {
		return nil, err
	}
	return &platformv1.GetSchedulerJobHistoryRequest{
		JobId:           jobID,
		Limit:           o.limit,
		Offset:          o.offset,
		StartTimeUnixMs: since,
		EndTimeUnixMs:   until,
		Status:          platformv1.SchedulerJobStatus(status),
	}, nil
}

func newSchedulerHistoryCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &jobHistoryOptions{}
	cmd := newCommand(getFlags, "history JOB_ID", "List the runs of a job", cobra.ExactArgs(1),
		func(flags *cli.CommonFlags, args []string) error {
			request, err := opts.request(args[0])
			if err != nil {
				return err
			}
			return call(flags, newSchedulerClient, "failed to get the job history",
				platformv1.SchedulerServiceClient.GetJobHistory, request,
				func(reply *platformv1.GetSchedulerJobHistoryResponse) *cli.TableData {
					return listTable(reply.GetExecutions(),
						"execution_id", "status", "started_at_unix_ms", "duration_ms", "retry_count", "error")
				})
		})
	f := cmd.Flags()
	f.Int32Var(&opts.limit, "limit", 0, "most runs to return")
	f.Int32Var(&opts.offset, "offset", 0, "runs to skip")
	f.StringVar(&opts.since, "since", "", "only runs started at or after this RFC 3339 time")
	f.StringVar(&opts.until, "until", "", "only runs started before this RFC 3339 time")
	f.StringVar(&opts.status, "status", "", enumUsage("only runs in this status", jobStatusEnum))
	return cmd
}

// markRequired marks a flag the command cannot run without. The flag is
// declared right before, so a failure is a programming error.
func markRequired(cmd *cobra.Command, name string) {
	if err := cmd.MarkFlagRequired(name); err != nil {
		panic(err)
	}
}
