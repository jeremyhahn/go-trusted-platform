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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/transport/embedded"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/scheduler"
)

// fakeSchedulerClient answers every call with err when it is set, and
// records the job ID and options it was called with.
type fakeSchedulerClient struct {
	err        error
	jobID      uint64
	reason     string
	createReq  *scheduler.CreateJobRequest
	updateReq  *scheduler.UpdateJobRequest
	listOpts   *scheduler.ListJobsOptions
	historyOpt *scheduler.HistoryOptions
}

func (f *fakeSchedulerClient) CreateJob(_ context.Context, req *scheduler.CreateJobRequest) (*scheduler.CreateJobResponse, error) {
	f.createReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &scheduler.CreateJobResponse{JobID: 42}, nil
}

func (f *fakeSchedulerClient) GetJob(_ context.Context, jobID uint64) (*scheduler.JobInfo, error) {
	f.jobID = jobID
	if f.err != nil {
		return nil, f.err
	}
	return &scheduler.JobInfo{JobID: jobID}, nil
}

func (f *fakeSchedulerClient) UpdateJob(_ context.Context, req *scheduler.UpdateJobRequest) (*scheduler.JobInfo, error) {
	f.updateReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &scheduler.JobInfo{JobID: req.JobID, Name: req.Name}, nil
}

func (f *fakeSchedulerClient) DeleteJob(_ context.Context, jobID uint64) error {
	f.jobID = jobID
	return f.err
}

func (f *fakeSchedulerClient) ListJobs(_ context.Context, opts *scheduler.ListJobsOptions) (*scheduler.ListJobsResponse, error) {
	f.listOpts = opts
	if f.err != nil {
		return nil, f.err
	}
	return &scheduler.ListJobsResponse{TotalCount: 1, Jobs: []scheduler.JobInfo{{JobID: 1}}}, nil
}

func (f *fakeSchedulerClient) TriggerJob(_ context.Context, jobID uint64) (*scheduler.TriggerJobResponse, error) {
	f.jobID = jobID
	if f.err != nil {
		return nil, f.err
	}
	return &scheduler.TriggerJobResponse{JobID: jobID, ExecutionID: 9}, nil
}

func (f *fakeSchedulerClient) PauseJob(_ context.Context, jobID uint64) (*scheduler.PauseJobResponse, error) {
	f.jobID = jobID
	if f.err != nil {
		return nil, f.err
	}
	return &scheduler.PauseJobResponse{JobID: jobID}, nil
}

func (f *fakeSchedulerClient) ResumeJob(_ context.Context, jobID uint64) (*scheduler.ResumeJobResponse, error) {
	f.jobID = jobID
	if f.err != nil {
		return nil, f.err
	}
	return &scheduler.ResumeJobResponse{JobID: jobID}, nil
}

func (f *fakeSchedulerClient) CancelJob(_ context.Context, jobID uint64, reason string) (*scheduler.CancelJobResponse, error) {
	f.jobID, f.reason = jobID, reason
	if f.err != nil {
		return nil, f.err
	}
	return &scheduler.CancelJobResponse{JobID: jobID, Reason: reason}, nil
}

func (f *fakeSchedulerClient) GetJobHistory(_ context.Context, jobID uint64, opts *scheduler.HistoryOptions) (*scheduler.JobHistoryResponse, error) {
	f.jobID, f.historyOpt = jobID, opts
	if f.err != nil {
		return nil, f.err
	}
	return &scheduler.JobHistoryResponse{JobID: jobID, TotalCount: 2}, nil
}

func (f *fakeSchedulerClient) GetStatus(context.Context) (*scheduler.SchedulerStatus, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &scheduler.SchedulerStatus{Healthy: true, TotalJobs: 3}, nil
}

func schedulerServiceWith(client *fakeSchedulerClient) *SchedulerService {
	return NewSchedulerService(func() scheduler.Client { return client })
}

// schedulerCalls runs every SchedulerService method once with a valid
// request and returns the errors, keyed by the op name ErrCallFailed carries.
func schedulerCalls(svc *SchedulerService) map[string]error {
	ctx := context.Background()
	errs := map[string]error{}
	_, errs["create job"] = svc.CreateJob(ctx, &scheduler.CreateJobRequest{Name: "backup", JobType: scheduler.JobTypeOneShot})
	_, errs["get job"] = svc.GetJob(ctx, 5)
	_, errs["update job"] = svc.UpdateJob(ctx, &scheduler.UpdateJobRequest{JobID: 5, Name: "renamed"})
	errs["delete job"] = svc.DeleteJob(ctx, 5)
	_, errs["list jobs"] = svc.ListJobs(ctx, nil)
	_, errs["trigger job"] = svc.TriggerJob(ctx, 5)
	_, errs["pause job"] = svc.PauseJob(ctx, 5)
	_, errs["resume job"] = svc.ResumeJob(ctx, 5)
	_, errs["cancel job"] = svc.CancelJob(ctx, 5, "done")
	_, errs["job history"] = svc.JobHistory(ctx, 5, nil)
	_, errs["status"] = svc.Status(ctx)
	return errs
}

func TestSchedulerService_NotConfigured(t *testing.T) {
	for op, err := range schedulerCalls(NewSchedulerService(nil)) {
		assert.Equal(t, ErrNotConfigured{Service: ServiceScheduler}, err, op)
	}
	for op, err := range schedulerCalls(NewSchedulerService(func() scheduler.Client { return nil })) {
		assert.Equal(t, ErrNotConfigured{Service: ServiceScheduler}, err, op)
	}
}

func TestSchedulerService_EveryCallReachesTheSDK(t *testing.T) {
	client := &fakeSchedulerClient{}
	for op, err := range schedulerCalls(schedulerServiceWith(client)) {
		assert.NoError(t, err, op)
	}
	assert.Equal(t, uint64(5), client.jobID)
	assert.Equal(t, "done", client.reason)
	assert.Equal(t, "renamed", client.updateReq.Name)
	assert.NotNil(t, client.listOpts, "a nil list filter is sent as an empty one")
	assert.NotNil(t, client.historyOpt, "nil history options are sent as empty ones")
}

func TestSchedulerService_EveryCallWrapsSDKErrors(t *testing.T) {
	for op, err := range schedulerCalls(schedulerServiceWith(&fakeSchedulerClient{err: errSDK})) {
		assertCallFailed(t, err, ServiceScheduler, op)
	}
}

// The embedded transport of go-quicbaas sdk/go v0.12.0-alpha registers no
// quicbaas.Scheduler handler, so every call there fails with
// UnknownMethodError: the service is not served, not a failed call.
func TestSchedulerService_UnservedMethodIsNotConfigured(t *testing.T) {
	unserved := embedded.NewUnknownMethodError("quicbaas.Scheduler", "GetJob")
	for op, err := range schedulerCalls(schedulerServiceWith(&fakeSchedulerClient{err: unserved})) {
		assert.Equal(t, ErrNotConfigured{Service: ServiceScheduler}, err, op)
	}
}

func TestSchedulerService_CreateJob(t *testing.T) {
	client := &fakeSchedulerClient{}
	req := &scheduler.CreateJobRequest{
		Name:      "hourly",
		JobType:   scheduler.JobTypeRecurring,
		Schedule:  "0 * * * *",
		OwnerType: scheduler.OwnerTypeTenant,
	}
	resp, err := schedulerServiceWith(client).CreateJob(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, uint64(42), resp.JobID)
	assert.Same(t, req, client.createReq)
}

func TestSchedulerService_CreateJobRefusesInvalidRequest(t *testing.T) {
	cases := map[string]struct {
		req   *scheduler.CreateJobRequest
		field string
	}{
		"nil request":        {nil, "request"},
		"no name":            {&scheduler.CreateJobRequest{}, "name"},
		"recurring, no cron": {&scheduler.CreateJobRequest{Name: "j", JobType: scheduler.JobTypeRecurring}, "schedule"},
		"delayed, no delay":  {&scheduler.CreateJobRequest{Name: "j", JobType: scheduler.JobTypeDelayed}, "delay"},
		"unknown job type":   {&scheduler.CreateJobRequest{Name: "j", JobType: 9}, "job_type"},
		"unknown owner type": {&scheduler.CreateJobRequest{Name: "j", OwnerType: 9}, "owner_type"},
		"negative retries":   {&scheduler.CreateJobRequest{Name: "j", MaxRetries: -1}, "max_retries"},
		"negative timeout":   {&scheduler.CreateJobRequest{Name: "j", Timeout: -time.Second}, "timeout"},
		"negative delay":     {&scheduler.CreateJobRequest{Name: "j", Delay: -time.Second}, "delay"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			client := &fakeSchedulerClient{}
			_, err := schedulerServiceWith(client).CreateJob(context.Background(), tc.req)
			assertInvalid(t, err, tc.field)
			assert.Nil(t, client.createReq, "an invalid job must not reach the SDK")
		})
	}
}

func TestSchedulerService_UpdateJobRefusesInvalidRequest(t *testing.T) {
	svc := schedulerServiceWith(&fakeSchedulerClient{})
	_, err := svc.UpdateJob(context.Background(), nil)
	assertInvalid(t, err, "request")
	_, err = svc.UpdateJob(context.Background(), &scheduler.UpdateJobRequest{JobID: 1, MaxRetries: -2})
	assertInvalid(t, err, "max_retries")
}

func TestSchedulerService_ListJobsPassesFilters(t *testing.T) {
	client := &fakeSchedulerClient{}
	status := scheduler.JobStatusPaused
	opts := &scheduler.ListJobsOptions{Status: &status, Limit: 10}
	resp, err := schedulerServiceWith(client).ListJobs(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, 1, resp.TotalCount)
	assert.Same(t, opts, client.listOpts)

	_, err = schedulerServiceWith(client).ListJobs(context.Background(), &scheduler.ListJobsOptions{Offset: -1})
	assertInvalid(t, err, "offset")
}

func TestSchedulerService_JobHistory(t *testing.T) {
	client := &fakeSchedulerClient{}
	start := time.Unix(1000, 0)
	end := start.Add(time.Hour)
	resp, err := schedulerServiceWith(client).JobHistory(context.Background(), 8,
		&scheduler.HistoryOptions{StartTime: &start, EndTime: &end, Limit: 5})
	require.NoError(t, err)
	assert.Equal(t, 2, resp.TotalCount)
	assert.Equal(t, uint64(8), client.jobID)
}

func TestSchedulerService_JobHistoryRefusesInvalidRange(t *testing.T) {
	start := time.Unix(1000, 0)
	end := start.Add(-time.Hour)
	svc := schedulerServiceWith(&fakeSchedulerClient{})
	_, err := svc.JobHistory(context.Background(), 8, &scheduler.HistoryOptions{StartTime: &start, EndTime: &end})
	assertInvalid(t, err, "end_time")
	_, err = svc.JobHistory(context.Background(), 8, &scheduler.HistoryOptions{Limit: -1})
	assertInvalid(t, err, "limit")
}
