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

package embedded

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// verdictServer answers PollDeviceVerdicts from a script of pages and
// records each poll; an exhausted script answers the missed-verdicts error.
type verdictServer struct {
	platformv1.UnimplementedAttestationServiceServer
	pages []*platformv1.PollDeviceVerdictsResponse
	polls []*platformv1.PollDeviceVerdictsRequest
}

func (s *verdictServer) PollDeviceVerdicts(_ context.Context, req *platformv1.PollDeviceVerdictsRequest) (*platformv1.PollDeviceVerdictsResponse, error) {
	s.polls = append(s.polls, proto.Clone(req).(*platformv1.PollDeviceVerdictsRequest))
	if len(s.pages) == 0 {
		return nil, status.Error(codes.ResourceExhausted, "attestation: verdicts were missed")
	}
	page := s.pages[0]
	s.pages = s.pages[1:]
	return page, nil
}

// TestStreamDeviceVerdictsEmbedded opens StreamDeviceVerdicts in process: the
// connection long-polls PollDeviceVerdicts, each poll waiting the longest the
// daemon allows, since no transport timeout bounds an in-process call.
func TestStreamDeviceVerdictsEmbedded(t *testing.T) {
	svc := &verdictServer{pages: []*platformv1.PollDeviceVerdictsResponse{
		{Cursor: "18f.0"},
		{Cursor: "18f.1", Verdicts: []*platformv1.DeviceVerdictEvent{{EventId: "ev-1", DeviceId: 7}}},
	}}
	conn := newEmbeddedClientConn(&ServiceRegistry{Attestation: svc})

	stream, err := platformv1.NewAttestationServiceClient(conn).
		StreamDeviceVerdicts(context.Background(), &platformv1.StreamDeviceVerdictsRequest{})
	if err != nil {
		t.Fatalf("StreamDeviceVerdicts: %v", err)
	}
	got, err := stream.Recv()
	if err != nil || got.GetEventId() != "ev-1" || got.GetDeviceId() != 7 {
		t.Fatalf("Recv = %+v, %v", got, err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("Recv = %v, want ResourceExhausted", err)
	}
	if len(svc.polls) != 3 || svc.polls[0].GetWaitMs() != 0 ||
		svc.polls[1].GetCursor() != "18f.0" || svc.polls[1].GetWaitMs() != 20000 ||
		svc.polls[2].GetCursor() != "18f.1" {
		t.Fatalf("polls = %+v", svc.polls)
	}
}

func TestStreamDeviceVerdictsEmbeddedWithoutAttestation(t *testing.T) {
	conn := newEmbeddedClientConn(&ServiceRegistry{})
	_, err := platformv1.NewAttestationServiceClient(conn).
		StreamDeviceVerdicts(context.Background(), &platformv1.StreamDeviceVerdictsRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("StreamDeviceVerdicts = %v, want Unimplemented", err)
	}
}
