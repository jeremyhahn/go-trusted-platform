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

package ntp

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
)

// stubGRPC is a scripted NTPServiceClient.
type stubGRPC struct {
	status  *platformv1.NTPStatus
	sources []*platformv1.NTPSource
	err     error
}

// GetStatus returns the scripted status.
func (s *stubGRPC) GetStatus(context.Context, *platformv1.GetNTPStatusRequest, ...grpc.CallOption) (*platformv1.GetNTPStatusResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.GetNTPStatusResponse{Status: s.status}, nil
}

// ListSources returns the scripted sources.
func (s *stubGRPC) ListSources(context.Context, *platformv1.ListNTPSourcesRequest, ...grpc.CallOption) (*platformv1.ListNTPSourcesResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.ListNTPSourcesResponse{Sources: s.sources}, nil
}

// Step returns the scripted status.
func (s *stubGRPC) Step(context.Context, *platformv1.StepNTPClockRequest, ...grpc.CallOption) (*platformv1.StepNTPClockResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.StepNTPClockResponse{Status: s.status}, nil
}

func TestClientUnwrapsTheResponseEnvelopes(t *testing.T) {
	client := NewClientFromGRPC(&stubGRPC{
		status:  &platformv1.NTPStatus{Synced: true, Stratum: 3},
		sources: []*platformv1.NTPSource{{Address: "198.18.0.1", Reachable: true}},
	})
	ctx := context.Background()

	status, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if !status.GetSynced() || status.GetStratum() != 3 {
		t.Fatalf("status = %+v, want synced stratum 3", status)
	}

	sources, err := client.Sources(ctx)
	if err != nil {
		t.Fatalf("Sources() error = %v", err)
	}
	if len(sources) != 1 || sources[0].GetAddress() != "198.18.0.1" {
		t.Fatalf("sources = %+v", sources)
	}

	stepped, err := client.Step(ctx)
	if err != nil {
		t.Fatalf("Step() error = %v", err)
	}
	if !stepped.GetSynced() {
		t.Fatalf("stepped = %+v, want synced", stepped)
	}
}

func TestClientWrapsTransportFailuresWithTypedErrors(t *testing.T) {
	cause := errors.New("connection closed")
	client := NewClientFromGRPC(&stubGRPC{err: cause})
	ctx := context.Background()

	var statusErr *ErrGetStatusFailed
	if _, err := client.Status(ctx); !errors.As(err, &statusErr) || !errors.Is(err, cause) {
		t.Fatalf("Status() error = %v, want ErrGetStatusFailed wrapping the cause", err)
	}

	var sourcesErr *ErrListSourcesFailed
	if _, err := client.Sources(ctx); !errors.As(err, &sourcesErr) || !errors.Is(err, cause) {
		t.Fatalf("Sources() error = %v, want ErrListSourcesFailed wrapping the cause", err)
	}

	var stepErr *ErrStepFailed
	if _, err := client.Step(ctx); !errors.As(err, &stepErr) || !errors.Is(err, cause) {
		t.Fatalf("Step() error = %v, want ErrStepFailed wrapping the cause", err)
	}
}

func TestNewClientRejectsANilTransport(t *testing.T) {
	if _, err := NewClient(nil); !errors.Is(err, common.ErrNilConnection) {
		t.Fatalf("NewClient(nil) error = %v, want ErrNilConnection", err)
	}
}

// fakeAdapter is a transport.Adapter whose Connection may be nil, covering
// both branches of NewClient's validation.
type fakeAdapter struct{ conn grpc.ClientConnInterface }

// Connection returns the configured connection.
func (f *fakeAdapter) Connection() grpc.ClientConnInterface { return f.conn }

// Close is a no-op.
func (f *fakeAdapter) Close() error { return nil }

// IsConnected always reports true.
func (f *fakeAdapter) IsConnected() bool { return true }

// Target reports a fixed test target.
func (f *fakeAdapter) Target() string { return "test" }

// nopConn satisfies grpc.ClientConnInterface without doing any I/O.
type nopConn struct{}

// Invoke reports that the test connection carries no RPCs.
func (nopConn) Invoke(context.Context, string, any, any, ...grpc.CallOption) error {
	return errors.New("not connected")
}

// NewStream reports that the test connection carries no streams.
func (nopConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("not connected")
}

func TestNewClientBuildsFromATransportAdapter(t *testing.T) {
	client, err := NewClient(&fakeAdapter{conn: nopConn{}})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if client == nil {
		t.Fatal("NewClient() = nil client")
	}

	if _, err := NewClient(&fakeAdapter{}); !errors.Is(err, common.ErrNilConnection) {
		t.Fatalf("NewClient(adapter with nil connection) error = %v, want ErrNilConnection", err)
	}
}
