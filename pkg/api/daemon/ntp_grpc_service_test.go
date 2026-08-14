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
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ntp"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeNTPBackend is a scripted NTPBackend for the transport tests. The API
// layers must never talk to a real chronyd, so every test drives this.
type fakeNTPBackend struct {
	status     *ntp.Status
	statusErr  error
	sources    []ntp.Source
	sourcesErr error
	stepStatus *ntp.Status
	stepErr    error
	stepCalls  int
}

// Status returns the scripted status.
func (f *fakeNTPBackend) Status(context.Context) (*ntp.Status, error) {
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	return f.status, nil
}

// Sources returns the scripted sources.
func (f *fakeNTPBackend) Sources(context.Context) ([]ntp.Source, error) {
	if f.sourcesErr != nil {
		return nil, f.sourcesErr
	}
	return f.sources, nil
}

// Step records the call and returns the scripted result.
func (f *fakeNTPBackend) Step(context.Context) (*ntp.Status, error) {
	f.stepCalls++
	if f.stepErr != nil {
		return nil, f.stepErr
	}
	return f.stepStatus, nil
}

// syncedNTPStatus is a converged clock reading shared by the transport tests.
func syncedNTPStatus() *ntp.Status {
	return &ntp.Status{
		Synced:           true,
		Stratum:          3,
		LeapStatus:       "Normal",
		OffsetSeconds:    -0.000012,
		RootDispersion:   0.045,
		RootDelay:        0.023,
		LastSync:         time.Unix(1755000000, 0).UTC(),
		Mode:             "both",
		ReferenceID:      "CB00710F",
		ReferenceName:    "198.18.0.1",
		SourcesReachable: 1,
		SourcesTotal:     2,
	}
}

// ntpTestSources is the source list shared by the transport tests.
func ntpTestSources() []ntp.Source {
	return []ntp.Source{
		{
			Address:       "198.18.0.1",
			Mode:          ntp.SourceModeServer,
			State:         ntp.SourceStateSelected,
			Stratum:       2,
			PollSeconds:   64,
			Reach:         377,
			LastRxSeconds: 23,
			OffsetSeconds: -0.000021,
			Reachable:     true,
		},
		{
			Address:   "203.0.113.9",
			Mode:      ntp.SourceModeServer,
			State:     ntp.SourceStateUnreachable,
			Reachable: false,
		},
	}
}

// newNTPTestService builds an NTP gRPC service over the fake backend.
func newNTPTestService(backend NTPBackend) *NTPGRPCService {
	return NewNTPGRPCService(nil, backend)
}

func TestNTPGRPCServiceReportsSynchronizationState(t *testing.T) {
	backend := &fakeNTPBackend{status: syncedNTPStatus(), sources: ntpTestSources()}
	service := newNTPTestService(backend)
	ctx := context.Background()

	resp, err := service.GetStatus(ctx, &platformv1.GetNTPStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}
	got := resp.GetStatus()
	if !got.GetSynced() || got.GetStratum() != 3 {
		t.Fatalf("status = %+v, want synced stratum 3", got)
	}
	if got.GetReferenceId() != "CB00710F" || got.GetReferenceName() != "198.18.0.1" {
		t.Fatalf("reference = %q/%q, want CB00710F/198.18.0.1", got.GetReferenceId(), got.GetReferenceName())
	}
	if got.GetLastSyncUnix() != 1755000000 {
		t.Fatalf("LastSyncUnix = %d, want 1755000000", got.GetLastSyncUnix())
	}
	if got.GetSourcesReachable() != 1 || got.GetSourcesTotal() != 2 {
		t.Fatalf("sources = %d/%d, want 1/2", got.GetSourcesReachable(), got.GetSourcesTotal())
	}

	listResp, err := service.ListSources(ctx, &platformv1.ListNTPSourcesRequest{})
	if err != nil {
		t.Fatalf("ListSources() error = %v", err)
	}
	if len(listResp.GetSources()) != 2 {
		t.Fatalf("len(sources) = %d, want 2", len(listResp.GetSources()))
	}
	first := listResp.GetSources()[0]
	if first.GetState() != string(ntp.SourceStateSelected) || !first.GetReachable() {
		t.Fatalf("source[0] = %+v, want selected and reachable", first)
	}
	if first.GetPollSeconds() != 64 || first.GetReach() != 377 {
		t.Fatalf("source[0] poll/reach = %d/%d, want 64/377", first.GetPollSeconds(), first.GetReach())
	}
}

func TestNTPGRPCServiceStepsTheClock(t *testing.T) {
	backend := &fakeNTPBackend{stepStatus: syncedNTPStatus()}
	service := newNTPTestService(backend)

	resp, err := service.Step(context.Background(), &platformv1.StepNTPClockRequest{})
	if err != nil {
		t.Fatalf("Step() error = %v", err)
	}
	if !resp.GetStatus().GetSynced() {
		t.Fatalf("status = %+v, want synced", resp.GetStatus())
	}
	if backend.stepCalls != 1 {
		t.Fatalf("step calls = %d, want 1", backend.stepCalls)
	}
}

func TestNTPGRPCServiceReturnsUnavailableWithoutABackend(t *testing.T) {
	service := newNTPTestService(nil)
	ctx := context.Background()

	if _, err := service.GetStatus(ctx, &platformv1.GetNTPStatusRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("GetStatus() code = %v, want Unavailable", status.Code(err))
	}
	if _, err := service.ListSources(ctx, &platformv1.ListNTPSourcesRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("ListSources() code = %v, want Unavailable", status.Code(err))
	}
	if _, err := service.Step(ctx, &platformv1.StepNTPClockRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("Step() code = %v, want Unavailable", status.Code(err))
	}
	if service.Backend() != nil {
		t.Fatal("Backend() should be nil before wiring")
	}

	service.SetBackend(&fakeNTPBackend{status: syncedNTPStatus()})
	if service.Backend() == nil {
		t.Fatal("SetBackend() did not wire the backend")
	}
}

func TestNTPGRPCServiceMapsDomainErrorsToStatusCodes(t *testing.T) {
	cases := map[string]struct {
		err  error
		want codes.Code
	}{
		"no reachable source is a conflict": {
			err:  ntp.ErrNoReachableSource{Total: 2},
			want: codes.Aborted,
		},
		"control socket down is unavailable": {
			err:  ntp.ErrControlUnavailable{Command: "tracking", Cause: errors.New("no socket")},
			want: codes.Unavailable,
		},
		"disabled section is unavailable": {
			err:  ntp.ErrDisabled{},
			want: codes.Unavailable,
		},
		"malformed control output is internal": {
			err:  ntp.ErrMalformedControlOutput{Command: "sources", Want: 10, Got: 2},
			want: codes.Internal,
		},
		"sync timeout is deadline exceeded": {
			err:  ntp.ErrSyncTimeout{Seconds: 120},
			want: codes.DeadlineExceeded,
		},
		"unknown failures are internal": {
			err:  errors.New("boom"),
			want: codes.Internal,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			service := newNTPTestService(&fakeNTPBackend{statusErr: tc.err, sourcesErr: tc.err, stepErr: tc.err})
			ctx := context.Background()

			if _, err := service.GetStatus(ctx, &platformv1.GetNTPStatusRequest{}); status.Code(err) != tc.want {
				t.Fatalf("GetStatus() code = %v, want %v", status.Code(err), tc.want)
			}
			if _, err := service.ListSources(ctx, &platformv1.ListNTPSourcesRequest{}); status.Code(err) != tc.want {
				t.Fatalf("ListSources() code = %v, want %v", status.Code(err), tc.want)
			}
			if _, err := service.Step(ctx, &platformv1.StepNTPClockRequest{}); status.Code(err) != tc.want {
				t.Fatalf("Step() code = %v, want %v", status.Code(err), tc.want)
			}
		})
	}

	if ntpErrToGRPC(nil) != nil {
		t.Fatal("ntpErrToGRPC(nil) should be nil")
	}
}

func TestNTPProjectionHandlesEmptyValues(t *testing.T) {
	if ntpStatusToPb(nil) != nil {
		t.Fatal("ntpStatusToPb(nil) should be nil")
	}

	// An unsynchronized node has never had a reference; LastSyncUnix must
	// stay zero so clients can render "never" rather than the epoch.
	pb := ntpStatusToPb(&ntp.Status{Mode: "consume"})
	if pb.GetLastSyncUnix() != 0 {
		t.Fatalf("LastSyncUnix = %d, want 0 for a node that never synced", pb.GetLastSyncUnix())
	}

	if got := ntpSourcesToPb(nil); len(got) != 0 {
		t.Fatalf("ntpSourcesToPb(nil) = %v, want empty", got)
	}
}
