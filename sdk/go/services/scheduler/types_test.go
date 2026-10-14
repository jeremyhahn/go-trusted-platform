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
	"reflect"
	"testing"

	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/scheduler"
)

// TestTypes_AreUpstreamAliases proves every re-exported type IS the upstream
// type, so a value crosses the boundary without conversion. A defined type
// in place of an alias would be a distinct reflect.Type.
func TestTypes_AreUpstreamAliases(t *testing.T) {
	cases := []struct {
		name     string
		got      reflect.Type
		upstream reflect.Type
	}{
		{"Client", reflect.TypeFor[Client](), reflect.TypeFor[upstream.Client]()},
		{"JobInfo", reflect.TypeFor[JobInfo](), reflect.TypeFor[upstream.JobInfo]()},
		{"JobExecution", reflect.TypeFor[JobExecution](), reflect.TypeFor[upstream.JobExecution]()},
		{"JobStatus", reflect.TypeFor[JobStatus](), reflect.TypeFor[upstream.JobStatus]()},
		{"JobType", reflect.TypeFor[JobType](), reflect.TypeFor[upstream.JobType]()},
		{"OwnerType", reflect.TypeFor[OwnerType](), reflect.TypeFor[upstream.OwnerType]()},
		{"SchedulerStatus", reflect.TypeFor[SchedulerStatus](), reflect.TypeFor[upstream.SchedulerStatus]()},
		{"CreateJobRequest", reflect.TypeFor[CreateJobRequest](), reflect.TypeFor[upstream.CreateJobRequest]()},
		{"CreateJobResponse", reflect.TypeFor[CreateJobResponse](), reflect.TypeFor[upstream.CreateJobResponse]()},
		{"UpdateJobRequest", reflect.TypeFor[UpdateJobRequest](), reflect.TypeFor[upstream.UpdateJobRequest]()},
		{"ListJobsOptions", reflect.TypeFor[ListJobsOptions](), reflect.TypeFor[upstream.ListJobsOptions]()},
		{"ListJobsResponse", reflect.TypeFor[ListJobsResponse](), reflect.TypeFor[upstream.ListJobsResponse]()},
		{"HistoryOptions", reflect.TypeFor[HistoryOptions](), reflect.TypeFor[upstream.HistoryOptions]()},
		{"JobHistoryResponse", reflect.TypeFor[JobHistoryResponse](), reflect.TypeFor[upstream.JobHistoryResponse]()},
		{"PauseJobResponse", reflect.TypeFor[PauseJobResponse](), reflect.TypeFor[upstream.PauseJobResponse]()},
		{"ResumeJobResponse", reflect.TypeFor[ResumeJobResponse](), reflect.TypeFor[upstream.ResumeJobResponse]()},
		{"TriggerJobResponse", reflect.TypeFor[TriggerJobResponse](), reflect.TypeFor[upstream.TriggerJobResponse]()},
		{"CancelJobResponse", reflect.TypeFor[CancelJobResponse](), reflect.TypeFor[upstream.CancelJobResponse]()},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %v, want the upstream type %v", tc.name, tc.got, tc.upstream)
		}
	}
}

// TestConstants_MatchUpstream proves each re-exported enum value carries the
// upstream value and type, so a job created through this package is scheduled
// the way the server reads it.
func TestConstants_MatchUpstream(t *testing.T) {
	cases := []struct {
		name     string
		got      any
		upstream any
	}{
		{"JobStatusPending", JobStatusPending, upstream.JobStatusPending},
		{"JobStatusRunning", JobStatusRunning, upstream.JobStatusRunning},
		{"JobStatusCompleted", JobStatusCompleted, upstream.JobStatusCompleted},
		{"JobStatusFailed", JobStatusFailed, upstream.JobStatusFailed},
		{"JobStatusPaused", JobStatusPaused, upstream.JobStatusPaused},
		{"JobStatusCanceled", JobStatusCanceled, upstream.JobStatusCanceled},
		{"JobTypeOneShot", JobTypeOneShot, upstream.JobTypeOneShot},
		{"JobTypeRecurring", JobTypeRecurring, upstream.JobTypeRecurring},
		{"JobTypeDelayed", JobTypeDelayed, upstream.JobTypeDelayed},
		{"OwnerTypeSystem", OwnerTypeSystem, upstream.OwnerTypeSystem},
		{"OwnerTypeTenant", OwnerTypeTenant, upstream.OwnerTypeTenant},
		{"OwnerTypeDelegated", OwnerTypeDelegated, upstream.OwnerTypeDelegated},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %#v, want %#v", tc.name, tc.got, tc.upstream)
		}
	}
}
