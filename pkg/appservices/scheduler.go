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

package appservices

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/scheduler"
)

// SchedulerService manages the jobs of the composed SDK's scheduler.
type SchedulerService struct {
	resolver Resolver[scheduler.Client]
}

// NewSchedulerService returns a SchedulerService that reaches the SDK's
// Scheduler group through resolver.
func NewSchedulerService(resolver Resolver[scheduler.Client]) *SchedulerService {
	return &SchedulerService{resolver: resolver}
}

// CreateJob schedules a job. A recurring job needs a schedule and a delayed
// job a positive delay.
func (s *SchedulerService) CreateJob(ctx context.Context, req *scheduler.CreateJobRequest) (*scheduler.CreateJobResponse, error) {
	if err := validateCreateJob(req); err != nil {
		return nil, err
	}
	client, err := resolve(ServiceScheduler, s.resolver)
	if err != nil {
		return nil, err
	}
	resp, err := client.CreateJob(ctx, req)
	return resp, callFailed(ServiceScheduler, "create job", err)
}

// GetJob returns one job.
func (s *SchedulerService) GetJob(ctx context.Context, jobID uint64) (*scheduler.JobInfo, error) {
	client, err := resolve(ServiceScheduler, s.resolver)
	if err != nil {
		return nil, err
	}
	job, err := client.GetJob(ctx, jobID)
	return job, callFailed(ServiceScheduler, "get job", err)
}

// UpdateJob changes the fields of a job that are set.
func (s *SchedulerService) UpdateJob(ctx context.Context, req *scheduler.UpdateJobRequest) (*scheduler.JobInfo, error) {
	if err := validateUpdateJob(req); err != nil {
		return nil, err
	}
	client, err := resolve(ServiceScheduler, s.resolver)
	if err != nil {
		return nil, err
	}
	job, err := client.UpdateJob(ctx, req)
	return job, callFailed(ServiceScheduler, "update job", err)
}

// DeleteJob removes a job.
func (s *SchedulerService) DeleteJob(ctx context.Context, jobID uint64) error {
	client, err := resolve(ServiceScheduler, s.resolver)
	if err != nil {
		return err
	}
	return callFailed(ServiceScheduler, "delete job", client.DeleteJob(ctx, jobID))
}

// ListJobs lists the jobs that match every filter that is set.
func (s *SchedulerService) ListJobs(ctx context.Context, opts *scheduler.ListJobsOptions) (*scheduler.ListJobsResponse, error) {
	if opts == nil {
		opts = &scheduler.ListJobsOptions{}
	}
	if err := validatePage(opts.Limit, opts.Offset); err != nil {
		return nil, err
	}
	client, err := resolve(ServiceScheduler, s.resolver)
	if err != nil {
		return nil, err
	}
	resp, err := client.ListJobs(ctx, opts)
	return resp, callFailed(ServiceScheduler, "list jobs", err)
}

// TriggerJob runs a job now.
func (s *SchedulerService) TriggerJob(ctx context.Context, jobID uint64) (*scheduler.TriggerJobResponse, error) {
	client, err := resolve(ServiceScheduler, s.resolver)
	if err != nil {
		return nil, err
	}
	resp, err := client.TriggerJob(ctx, jobID)
	return resp, callFailed(ServiceScheduler, "trigger job", err)
}

// PauseJob stops a job from running until it is resumed.
func (s *SchedulerService) PauseJob(ctx context.Context, jobID uint64) (*scheduler.PauseJobResponse, error) {
	client, err := resolve(ServiceScheduler, s.resolver)
	if err != nil {
		return nil, err
	}
	resp, err := client.PauseJob(ctx, jobID)
	return resp, callFailed(ServiceScheduler, "pause job", err)
}

// ResumeJob schedules a paused job again.
func (s *SchedulerService) ResumeJob(ctx context.Context, jobID uint64) (*scheduler.ResumeJobResponse, error) {
	client, err := resolve(ServiceScheduler, s.resolver)
	if err != nil {
		return nil, err
	}
	resp, err := client.ResumeJob(ctx, jobID)
	return resp, callFailed(ServiceScheduler, "resume job", err)
}

// CancelJob cancels a job for good.
func (s *SchedulerService) CancelJob(ctx context.Context, jobID uint64, reason string) (*scheduler.CancelJobResponse, error) {
	client, err := resolve(ServiceScheduler, s.resolver)
	if err != nil {
		return nil, err
	}
	resp, err := client.CancelJob(ctx, jobID, reason)
	return resp, callFailed(ServiceScheduler, "cancel job", err)
}

// JobHistory returns the executions of a job.
func (s *SchedulerService) JobHistory(ctx context.Context, jobID uint64, opts *scheduler.HistoryOptions) (*scheduler.JobHistoryResponse, error) {
	if opts == nil {
		opts = &scheduler.HistoryOptions{}
	}
	if err := validatePage(opts.Limit, opts.Offset); err != nil {
		return nil, err
	}
	if opts.StartTime != nil && opts.EndTime != nil && opts.EndTime.Before(*opts.StartTime) {
		return nil, ErrInvalidArgument{Service: ServiceScheduler, Field: "end_time", Reason: "is before start_time"}
	}
	client, err := resolve(ServiceScheduler, s.resolver)
	if err != nil {
		return nil, err
	}
	resp, err := client.GetJobHistory(ctx, jobID, opts)
	return resp, callFailed(ServiceScheduler, "job history", err)
}

// Status returns the scheduler's health and counters.
func (s *SchedulerService) Status(ctx context.Context) (*scheduler.SchedulerStatus, error) {
	client, err := resolve(ServiceScheduler, s.resolver)
	if err != nil {
		return nil, err
	}
	status, err := client.GetStatus(ctx)
	return status, callFailed(ServiceScheduler, "status", err)
}

func validateCreateJob(req *scheduler.CreateJobRequest) error {
	if req == nil {
		return ErrInvalidArgument{Service: ServiceScheduler, Field: "request", Reason: "is required"}
	}
	if err := requireName(ServiceScheduler, "name", req.Name); err != nil {
		return err
	}
	switch req.JobType {
	case scheduler.JobTypeOneShot:
	case scheduler.JobTypeRecurring:
		if req.Schedule == "" {
			return ErrInvalidArgument{Service: ServiceScheduler, Field: "schedule", Reason: "a recurring job needs a cron schedule"}
		}
	case scheduler.JobTypeDelayed:
		if req.Delay <= 0 {
			return ErrInvalidArgument{Service: ServiceScheduler, Field: "delay", Reason: "a delayed job needs a positive delay"}
		}
	default:
		return ErrInvalidArgument{Service: ServiceScheduler, Field: "job_type", Reason: "is not a known job type"}
	}
	if req.OwnerType < scheduler.OwnerTypeSystem || req.OwnerType > scheduler.OwnerTypeDelegated {
		return ErrInvalidArgument{Service: ServiceScheduler, Field: "owner_type", Reason: "is not a known owner type"}
	}
	return validateJobLimits(req.Delay, req.MaxRetries, req.Timeout)
}

func validateUpdateJob(req *scheduler.UpdateJobRequest) error {
	if req == nil {
		return ErrInvalidArgument{Service: ServiceScheduler, Field: "request", Reason: "is required"}
	}
	return validateJobLimits(req.Delay, req.MaxRetries, req.Timeout)
}

func validateJobLimits[D ~int64](delay D, maxRetries int, timeout D) error {
	if err := requireNotNegative(ServiceScheduler, "delay", delay); err != nil {
		return err
	}
	if err := requireNotNegative(ServiceScheduler, "max_retries", maxRetries); err != nil {
		return err
	}
	return requireNotNegative(ServiceScheduler, "timeout", timeout)
}

func validatePage(limit, offset int) error {
	if err := requireNotNegative(ServiceScheduler, "limit", limit); err != nil {
		return err
	}
	return requireNotNegative(ServiceScheduler, "offset", offset)
}
