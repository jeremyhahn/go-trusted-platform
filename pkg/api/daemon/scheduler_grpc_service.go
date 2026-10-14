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

package daemon

import (
	"context"
	"strconv"

	"github.com/jeremyhahn/go-trusted-platform/pkg/appservices"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/scheduler"
)

var (
	schedulerJobTypesFromPb = map[platformv1.SchedulerJobType]scheduler.JobType{
		platformv1.SchedulerJobType_SCHEDULER_JOB_TYPE_ONE_SHOT:  scheduler.JobTypeOneShot,
		platformv1.SchedulerJobType_SCHEDULER_JOB_TYPE_RECURRING: scheduler.JobTypeRecurring,
		platformv1.SchedulerJobType_SCHEDULER_JOB_TYPE_DELAYED:   scheduler.JobTypeDelayed,
	}
	schedulerJobTypesToPb = invertMap(schedulerJobTypesFromPb)

	schedulerStatusesFromPb = map[platformv1.SchedulerJobStatus]scheduler.JobStatus{
		platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_PENDING:   scheduler.JobStatusPending,
		platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_RUNNING:   scheduler.JobStatusRunning,
		platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_COMPLETED: scheduler.JobStatusCompleted,
		platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_FAILED:    scheduler.JobStatusFailed,
		platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_PAUSED:    scheduler.JobStatusPaused,
		platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_CANCELED:  scheduler.JobStatusCanceled,
	}
	schedulerStatusesToPb = invertMap(schedulerStatusesFromPb)

	schedulerOwnerTypesFromPb = map[platformv1.SchedulerOwnerType]scheduler.OwnerType{
		platformv1.SchedulerOwnerType_SCHEDULER_OWNER_TYPE_SYSTEM:    scheduler.OwnerTypeSystem,
		platformv1.SchedulerOwnerType_SCHEDULER_OWNER_TYPE_TENANT:    scheduler.OwnerTypeTenant,
		platformv1.SchedulerOwnerType_SCHEDULER_OWNER_TYPE_DELEGATED: scheduler.OwnerTypeDelegated,
	}
	schedulerOwnerTypesToPb = invertMap(schedulerOwnerTypesFromPb)
)

func invertMap[K, V comparable](in map[K]V) map[V]K {
	out := make(map[V]K, len(in))
	for k, v := range in {
		out[v] = k
	}
	return out
}

// SchedulerGRPCService implements platformv1.SchedulerServiceServer over
// the appservices scheduler service.
type SchedulerGRPCService struct {
	platformv1.UnimplementedSchedulerServiceServer

	service *appservices.SchedulerService
	logger  *logging.Logger
}

// NewSchedulerGRPCService returns the scheduler gRPC service. A nil service
// answers every call with the not-configured status.
func NewSchedulerGRPCService(logger *logging.Logger, service *appservices.SchedulerService) *SchedulerGRPCService {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	if service == nil {
		service = appservices.NewSchedulerService(nil)
	}
	return &SchedulerGRPCService{service: service, logger: logger}
}

// CreateJob schedules a job.
func (s *SchedulerGRPCService) CreateJob(ctx context.Context, req *platformv1.CreateSchedulerJobRequest) (*platformv1.CreateSchedulerJobResponse, error) {
	jobType, ok := schedulerJobTypesFromPb[req.GetJobType()]
	if !ok {
		return nil, appServiceError(s.logger, "scheduler create job", invalidScheduler("job_type", "is required"))
	}
	ownerType := scheduler.OwnerTypeSystem
	if owner, err := schedulerEnumFilter(schedulerOwnerTypesFromPb, req.GetOwnerType(), "owner_type"); err != nil {
		return nil, appServiceError(s.logger, "scheduler create job", err)
	} else if owner != nil {
		ownerType = *owner
	}
	resp, err := s.service.CreateJob(ctx, &scheduler.CreateJobRequest{
		Name:         req.GetName(),
		Description:  req.GetDescription(),
		JobType:      jobType,
		Handler:      req.GetHandler(),
		Schedule:     req.GetSchedule(),
		ExecuteAt:    appTime(req.GetExecuteAtUnixMs()),
		Delay:        appDuration(req.GetDelayMs()),
		Payload:      req.GetPayload(),
		OwnerType:    ownerType,
		OwnerID:      req.GetOwnerId(),
		MaxRetries:   int(req.GetMaxRetries()),
		Timeout:      appDuration(req.GetTimeoutMs()),
		Tags:         req.GetTags(),
		NodeAffinity: req.GetNodeAffinity(),
	})
	if err != nil {
		return nil, appServiceError(s.logger, "scheduler create job", err)
	}
	return &platformv1.CreateSchedulerJobResponse{
		JobId:           formatSchedulerID(resp.JobID),
		NextRunAtUnixMs: appUnixMillis(resp.NextRunAt),
	}, nil
}

// GetJob returns one job.
func (s *SchedulerGRPCService) GetJob(ctx context.Context, req *platformv1.GetSchedulerJobRequest) (*platformv1.GetSchedulerJobResponse, error) {
	jobID, err := parseSchedulerID(req.GetJobId())
	if err != nil {
		return nil, appServiceError(s.logger, "scheduler get job", err)
	}
	job, err := s.service.GetJob(ctx, jobID)
	if err != nil {
		return nil, appServiceError(s.logger, "scheduler get job", err)
	}
	return &platformv1.GetSchedulerJobResponse{Job: schedulerJobToPb(job)}, nil
}

// UpdateJob changes the fields of a job that are set.
func (s *SchedulerGRPCService) UpdateJob(ctx context.Context, req *platformv1.UpdateSchedulerJobRequest) (*platformv1.UpdateSchedulerJobResponse, error) {
	jobID, err := parseSchedulerID(req.GetJobId())
	if err != nil {
		return nil, appServiceError(s.logger, "scheduler update job", err)
	}
	job, err := s.service.UpdateJob(ctx, &scheduler.UpdateJobRequest{
		JobID:       jobID,
		Name:        req.GetName(),
		Description: req.GetDescription(),
		Schedule:    req.GetSchedule(),
		Delay:       appDuration(req.GetDelayMs()),
		Payload:     req.GetPayload(),
		MaxRetries:  int(req.GetMaxRetries()),
		Timeout:     appDuration(req.GetTimeoutMs()),
		Tags:        req.GetTags(),
	})
	if err != nil {
		return nil, appServiceError(s.logger, "scheduler update job", err)
	}
	return &platformv1.UpdateSchedulerJobResponse{Job: schedulerJobToPb(job)}, nil
}

// DeleteJob removes a job.
func (s *SchedulerGRPCService) DeleteJob(ctx context.Context, req *platformv1.DeleteSchedulerJobRequest) (*platformv1.DeleteSchedulerJobResponse, error) {
	jobID, err := parseSchedulerID(req.GetJobId())
	if err == nil {
		err = s.service.DeleteJob(ctx, jobID)
	}
	if err != nil {
		return nil, appServiceError(s.logger, "scheduler delete job", err)
	}
	return &platformv1.DeleteSchedulerJobResponse{}, nil
}

// ListJobs lists the jobs that match every filter that is set.
func (s *SchedulerGRPCService) ListJobs(ctx context.Context, req *platformv1.ListSchedulerJobsRequest) (*platformv1.ListSchedulerJobsResponse, error) {
	opts, err := schedulerListOptions(req)
	if err != nil {
		return nil, appServiceError(s.logger, "scheduler list jobs", err)
	}
	resp, err := s.service.ListJobs(ctx, opts)
	if err != nil {
		return nil, appServiceError(s.logger, "scheduler list jobs", err)
	}
	jobs := make([]*platformv1.SchedulerJob, 0, len(resp.Jobs))
	for i := range resp.Jobs {
		jobs = append(jobs, schedulerJobToPb(&resp.Jobs[i]))
	}
	return &platformv1.ListSchedulerJobsResponse{
		Jobs:       jobs,
		TotalCount: appInt32(resp.TotalCount),
		HasMore:    resp.HasMore,
	}, nil
}

// TriggerJob runs a job now.
func (s *SchedulerGRPCService) TriggerJob(ctx context.Context, req *platformv1.TriggerSchedulerJobRequest) (*platformv1.TriggerSchedulerJobResponse, error) {
	jobID, err := parseSchedulerID(req.GetJobId())
	if err != nil {
		return nil, appServiceError(s.logger, "scheduler trigger job", err)
	}
	resp, err := s.service.TriggerJob(ctx, jobID)
	if err != nil {
		return nil, appServiceError(s.logger, "scheduler trigger job", err)
	}
	return &platformv1.TriggerSchedulerJobResponse{
		JobId:           formatSchedulerID(resp.JobID),
		ExecutionId:     formatSchedulerID(resp.ExecutionID),
		StartedAtUnixMs: appUnixMillis(resp.StartedAt),
	}, nil
}

// PauseJob stops a job from running until it is resumed.
func (s *SchedulerGRPCService) PauseJob(ctx context.Context, req *platformv1.PauseSchedulerJobRequest) (*platformv1.PauseSchedulerJobResponse, error) {
	jobID, err := parseSchedulerID(req.GetJobId())
	if err != nil {
		return nil, appServiceError(s.logger, "scheduler pause job", err)
	}
	resp, err := s.service.PauseJob(ctx, jobID)
	if err != nil {
		return nil, appServiceError(s.logger, "scheduler pause job", err)
	}
	return &platformv1.PauseSchedulerJobResponse{
		JobId:          formatSchedulerID(resp.JobID),
		PausedAtUnixMs: appUnixMillis(resp.PausedAt),
	}, nil
}

// ResumeJob schedules a paused job again.
func (s *SchedulerGRPCService) ResumeJob(ctx context.Context, req *platformv1.ResumeSchedulerJobRequest) (*platformv1.ResumeSchedulerJobResponse, error) {
	jobID, err := parseSchedulerID(req.GetJobId())
	if err != nil {
		return nil, appServiceError(s.logger, "scheduler resume job", err)
	}
	resp, err := s.service.ResumeJob(ctx, jobID)
	if err != nil {
		return nil, appServiceError(s.logger, "scheduler resume job", err)
	}
	return &platformv1.ResumeSchedulerJobResponse{
		JobId:           formatSchedulerID(resp.JobID),
		ResumedAtUnixMs: appUnixMillis(resp.ResumedAt),
		NextRunAtUnixMs: appUnixMillis(resp.NextRunAt),
	}, nil
}

// CancelJob cancels a job for good.
func (s *SchedulerGRPCService) CancelJob(ctx context.Context, req *platformv1.CancelSchedulerJobRequest) (*platformv1.CancelSchedulerJobResponse, error) {
	jobID, err := parseSchedulerID(req.GetJobId())
	if err != nil {
		return nil, appServiceError(s.logger, "scheduler cancel job", err)
	}
	resp, err := s.service.CancelJob(ctx, jobID, req.GetReason())
	if err != nil {
		return nil, appServiceError(s.logger, "scheduler cancel job", err)
	}
	return &platformv1.CancelSchedulerJobResponse{
		JobId:            formatSchedulerID(resp.JobID),
		CanceledAtUnixMs: appUnixMillis(resp.CanceledAt),
		Reason:           resp.Reason,
	}, nil
}

// GetJobHistory returns the executions of a job.
func (s *SchedulerGRPCService) GetJobHistory(ctx context.Context, req *platformv1.GetSchedulerJobHistoryRequest) (*platformv1.GetSchedulerJobHistoryResponse, error) {
	jobID, err := parseSchedulerID(req.GetJobId())
	if err != nil {
		return nil, appServiceError(s.logger, "scheduler job history", err)
	}
	opts, err := schedulerHistoryOptions(req)
	if err != nil {
		return nil, appServiceError(s.logger, "scheduler job history", err)
	}
	resp, err := s.service.JobHistory(ctx, jobID, opts)
	if err != nil {
		return nil, appServiceError(s.logger, "scheduler job history", err)
	}
	executions := make([]*platformv1.SchedulerJobExecution, 0, len(resp.Executions))
	for _, execution := range resp.Executions {
		executions = append(executions, &platformv1.SchedulerJobExecution{
			ExecutionId:       formatSchedulerID(execution.ExecutionID),
			JobId:             formatSchedulerID(execution.JobID),
			Status:            schedulerStatusesToPb[execution.Status],
			StartedAtUnixMs:   appUnixMillis(execution.StartedAt),
			CompletedAtUnixMs: appUnixMillis(execution.CompletedAt),
			DurationMs:        execution.Duration.Milliseconds(),
			RetryCount:        appInt32(execution.RetryCount),
			Error:             execution.Error,
			Result:            execution.Result,
		})
	}
	return &platformv1.GetSchedulerJobHistoryResponse{
		JobId:      formatSchedulerID(resp.JobID),
		Executions: executions,
		TotalCount: appInt32(resp.TotalCount),
		HasMore:    resp.HasMore,
	}, nil
}

// GetStatus returns the scheduler's health and counters.
func (s *SchedulerGRPCService) GetStatus(ctx context.Context, _ *platformv1.GetSchedulerStatusRequest) (*platformv1.GetSchedulerStatusResponse, error) {
	st, err := s.service.Status(ctx)
	if err != nil {
		return nil, appServiceError(s.logger, "scheduler status", err)
	}
	return &platformv1.GetSchedulerStatusResponse{
		Healthy:             st.Healthy,
		TotalJobs:           st.TotalJobs,
		PendingJobs:         st.PendingJobs,
		RunningJobs:         st.RunningJobs,
		CompletedJobs:       st.CompletedJobs,
		FailedJobs:          st.FailedJobs,
		PausedJobs:          st.PausedJobs,
		CanceledJobs:        st.CanceledJobs,
		ExecutionsToday:     st.ExecutionsToday,
		FailuresToday:       st.FailuresToday,
		AverageLatencyMs:    st.AverageLatency.Milliseconds(),
		WorkerCount:         appInt32(st.WorkerCount),
		QueueDepth:          appInt32(st.QueueDepth),
		LastHeartbeatUnixMs: appUnixMillis(st.LastHeartbeat),
		UptimeMs:            st.UptimeDuration.Milliseconds(),
	}, nil
}

func schedulerListOptions(req *platformv1.ListSchedulerJobsRequest) (*scheduler.ListJobsOptions, error) {
	ownerType, err := schedulerEnumFilter(schedulerOwnerTypesFromPb, req.GetOwnerType(), "owner_type")
	if err != nil {
		return nil, err
	}
	jobStatus, err := schedulerEnumFilter(schedulerStatusesFromPb, req.GetStatus(), "status")
	if err != nil {
		return nil, err
	}
	jobType, err := schedulerEnumFilter(schedulerJobTypesFromPb, req.GetJobType(), "job_type")
	if err != nil {
		return nil, err
	}
	return &scheduler.ListJobsOptions{
		OwnerType: ownerType,
		OwnerID:   req.GetOwnerId(),
		Status:    jobStatus,
		JobType:   jobType,
		Tags:      req.GetTags(),
		Limit:     int(req.GetLimit()),
		Offset:    int(req.GetOffset()),
	}, nil
}

func schedulerHistoryOptions(req *platformv1.GetSchedulerJobHistoryRequest) (*scheduler.HistoryOptions, error) {
	jobStatus, err := schedulerEnumFilter(schedulerStatusesFromPb, req.GetStatus(), "status")
	if err != nil {
		return nil, err
	}
	opts := &scheduler.HistoryOptions{
		Limit:  int(req.GetLimit()),
		Offset: int(req.GetOffset()),
		Status: jobStatus,
	}
	if ms := req.GetStartTimeUnixMs(); ms != 0 {
		start := appTime(ms)
		opts.StartTime = &start
	}
	if ms := req.GetEndTimeUnixMs(); ms != 0 {
		end := appTime(ms)
		opts.EndTime = &end
	}
	return opts, nil
}

// schedulerEnumFilter converts an optional enum: the unspecified value is
// nil, a value outside the map is refused.
func schedulerEnumFilter[P ~int32, D any](values map[P]D, value P, field string) (*D, error) {
	if value == 0 {
		return nil, nil
	}
	converted, ok := values[value]
	if !ok {
		return nil, invalidScheduler(field, "is not a known value")
	}
	return &converted, nil
}

func schedulerJobToPb(job *scheduler.JobInfo) *platformv1.SchedulerJob {
	if job == nil {
		return nil
	}
	return &platformv1.SchedulerJob{
		JobId:           formatSchedulerID(job.JobID),
		Name:            job.Name,
		Description:     job.Description,
		JobType:         schedulerJobTypesToPb[job.JobType],
		Status:          schedulerStatusesToPb[job.Status],
		Schedule:        job.Schedule,
		DelayMs:         job.Delay.Milliseconds(),
		Payload:         job.Payload,
		OwnerType:       schedulerOwnerTypesToPb[job.OwnerType],
		OwnerId:         job.OwnerID,
		MaxRetries:      appInt32(job.MaxRetries),
		RetryCount:      appInt32(job.RetryCount),
		TimeoutMs:       job.Timeout.Milliseconds(),
		NextRunAtUnixMs: appUnixMillis(job.NextRunAt),
		LastRunAtUnixMs: appUnixMillis(job.LastRunAt),
		CreatedAtUnixMs: appUnixMillis(job.CreatedAt),
		UpdatedAtUnixMs: appUnixMillis(job.UpdatedAt),
		ExecutionCount:  job.ExecutionCount,
		FailureCount:    job.FailureCount,
		Tags:            job.Tags,
	}
}

// parseSchedulerID parses the decimal job ID the wire carries.
func parseSchedulerID(id string) (uint64, error) {
	if id == "" {
		return 0, invalidScheduler("job_id", "is required")
	}
	parsed, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return 0, invalidScheduler("job_id", "must be a decimal job ID")
	}
	return parsed, nil
}

func formatSchedulerID(id uint64) string {
	return strconv.FormatUint(id, 10)
}

func invalidScheduler(field, reason string) error {
	return appservices.ErrInvalidArgument{Service: appservices.ServiceScheduler, Field: field, Reason: reason}
}
