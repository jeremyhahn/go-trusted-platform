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

package scheduler

import (
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/scheduler"
)

// Client is the job scheduler client returned by
// quicbaas.Client.Scheduler().
type Client = upstream.Client

// Job records and the value types they carry.
type (
	// JobInfo is a scheduled job as the server stores it.
	JobInfo = upstream.JobInfo
	// JobExecution is one run of a job.
	JobExecution = upstream.JobExecution
	// JobStatus is the current status of a job.
	JobStatus = upstream.JobStatus
	// JobType is how a job is scheduled: once, recurring or delayed.
	JobType = upstream.JobType
	// OwnerType is the kind of principal that owns a job.
	OwnerType = upstream.OwnerType
	// SchedulerStatus is the state of the scheduler itself.
	SchedulerStatus = upstream.SchedulerStatus
)

// Requests, options and responses of the Client verbs.
type (
	CreateJobRequest   = upstream.CreateJobRequest
	CreateJobResponse  = upstream.CreateJobResponse
	UpdateJobRequest   = upstream.UpdateJobRequest
	ListJobsOptions    = upstream.ListJobsOptions
	ListJobsResponse   = upstream.ListJobsResponse
	HistoryOptions     = upstream.HistoryOptions
	JobHistoryResponse = upstream.JobHistoryResponse
	PauseJobResponse   = upstream.PauseJobResponse
	ResumeJobResponse  = upstream.ResumeJobResponse
	TriggerJobResponse = upstream.TriggerJobResponse
	CancelJobResponse  = upstream.CancelJobResponse
)

// Job statuses.
const (
	JobStatusPending   = upstream.JobStatusPending
	JobStatusRunning   = upstream.JobStatusRunning
	JobStatusCompleted = upstream.JobStatusCompleted
	JobStatusFailed    = upstream.JobStatusFailed
	JobStatusPaused    = upstream.JobStatusPaused
	JobStatusCanceled  = upstream.JobStatusCanceled
)

// Job types.
const (
	JobTypeOneShot   = upstream.JobTypeOneShot
	JobTypeRecurring = upstream.JobTypeRecurring
	JobTypeDelayed   = upstream.JobTypeDelayed
)

// Job owner types.
const (
	OwnerTypeSystem    = upstream.OwnerTypeSystem
	OwnerTypeTenant    = upstream.OwnerTypeTenant
	OwnerTypeDelegated = upstream.OwnerTypeDelegated
)
