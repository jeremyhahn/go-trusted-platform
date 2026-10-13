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

package pollstream

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// pollAnswer is one scripted answer to PollDeviceVerdicts.
type pollAnswer struct {
	resp *platformv1.PollDeviceVerdictsResponse
	err  error
}

// scriptedConn answers PollDeviceVerdicts from a script and records every
// request it was sent.
type scriptedConn struct {
	answers  []pollAnswer
	requests []*platformv1.PollDeviceVerdictsRequest
}

func (c *scriptedConn) Invoke(_ context.Context, method string, args, reply any, _ ...grpc.CallOption) error {
	if method != platformv1.AttestationService_PollDeviceVerdicts_FullMethodName {
		return status.Errorf(codes.Unimplemented, "unexpected method %s", method)
	}
	c.requests = append(c.requests, proto.Clone(args.(*platformv1.PollDeviceVerdictsRequest)).(*platformv1.PollDeviceVerdictsRequest))
	if len(c.answers) == 0 {
		return status.Error(codes.Unavailable, "script exhausted")
	}
	answer := c.answers[0]
	c.answers = c.answers[1:]
	if answer.err != nil {
		return answer.err
	}
	proto.Merge(reply.(proto.Message), answer.resp)
	return nil
}

func (c *scriptedConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, status.Error(codes.Unimplemented, "scriptedConn has no streams")
}

func page(cursor string, eventIDs ...string) pollAnswer {
	resp := &platformv1.PollDeviceVerdictsResponse{Cursor: cursor}
	for _, id := range eventIDs {
		resp.Verdicts = append(resp.Verdicts, &platformv1.DeviceVerdictEvent{EventId: id, DeviceId: 7})
	}
	return pollAnswer{resp: resp}
}

// openVerdicts opens the stream through the generated client, exactly as the
// SDK attestation client does.
func openVerdicts(ctx context.Context, conn *scriptedConn, wait time.Duration) (grpc.ServerStreamingClient[platformv1.DeviceVerdictEvent], error) {
	client := platformv1.NewAttestationServiceClient(&streamingConn{scriptedConn: conn, timeout: wait})
	return client.StreamDeviceVerdicts(ctx, &platformv1.StreamDeviceVerdictsRequest{})
}

// streamingConn is a unary transport whose NewStream is this package, as in
// the REST, QUIC, MCP and embedded adapters.
type streamingConn struct {
	*scriptedConn
	timeout time.Duration
}

func (c *streamingConn) NewStream(ctx context.Context, _ *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return NewStream(ctx, c, method, c.timeout, opts...)
}

func TestStreamDeviceVerdictsLongPollsFromTheHead(t *testing.T) {
	conn := &scriptedConn{answers: []pollAnswer{
		page("e.0"),
		page("e.0"), // an expired wait
		page("e.2", "ev-1", "ev-2"),
		page("e.3", "ev-3"),
	}}
	stream, err := openVerdicts(context.Background(), conn, 10*time.Second)
	if err != nil {
		t.Fatalf("StreamDeviceVerdicts: %v", err)
	}
	if len(conn.requests) != 1 || conn.requests[0].GetCursor() != "" || conn.requests[0].GetWaitMs() != 0 {
		t.Fatalf("opening the stream takes the head at once: %+v", conn.requests)
	}
	for _, want := range []string{"ev-1", "ev-2", "ev-3"} {
		got, err := stream.Recv()
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		if got.GetEventId() != want || got.GetDeviceId() != 7 {
			t.Fatalf("got %+v, want %s", got, want)
		}
	}
	wantCursors := []string{"", "e.0", "e.0", "e.2"}
	for i, req := range conn.requests {
		if req.GetCursor() != wantCursors[i] {
			t.Fatalf("poll %d cursor = %q, want %q", i, req.GetCursor(), wantCursors[i])
		}
		if i > 0 && req.GetWaitMs() != 5000 {
			t.Fatalf("poll %d waits %dms, want half the 10s transport timeout", i, req.GetWaitMs())
		}
	}
}

func TestStreamDeviceVerdictsEndsOnAPollError(t *testing.T) {
	conn := &scriptedConn{answers: []pollAnswer{
		page("e.0"),
		{err: status.Error(codes.ResourceExhausted, "fell behind")},
	}}
	stream, err := openVerdicts(context.Background(), conn, time.Second)
	if err != nil {
		t.Fatalf("StreamDeviceVerdicts: %v", err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("Recv = %v, want ResourceExhausted", err)
	}
}

func TestStreamDeviceVerdictsFailsToOpenWhenTheHeadPollFails(t *testing.T) {
	conn := &scriptedConn{answers: []pollAnswer{{err: status.Error(codes.PermissionDenied, "attestation:read is required")}}}
	if _, err := openVerdicts(context.Background(), conn, time.Second); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("StreamDeviceVerdicts = %v, want PermissionDenied", err)
	}
}

func TestStreamDeviceVerdictsEndsWithItsContext(t *testing.T) {
	conn := &scriptedConn{answers: []pollAnswer{page("e.0")}}
	ctx, cancel := context.WithCancel(context.Background())
	stream, err := openVerdicts(ctx, conn, time.Second)
	if err != nil {
		t.Fatalf("StreamDeviceVerdicts: %v", err)
	}
	cancel()
	if _, err := stream.Recv(); status.Code(err) != codes.Canceled {
		t.Fatalf("Recv = %v, want Canceled", err)
	}
	if len(conn.requests) != 1 {
		t.Fatalf("a cancelled stream must not poll again: %d polls", len(conn.requests))
	}
}

func TestNewStreamRefusesAMethodWithoutAUnaryTwin(t *testing.T) {
	_, err := NewStream(context.Background(), &scriptedConn{}, "/platform.v1.PlatformDaemon/StreamEvents", time.Second)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("NewStream = %v, want Unimplemented", err)
	}
}

func TestDeviceVerdictStreamRefusesTheWrongMessage(t *testing.T) {
	conn := &scriptedConn{answers: []pollAnswer{page("e.0", "ev-1")}}
	stream, err := NewStream(context.Background(), conn, platformv1.AttestationService_StreamDeviceVerdicts_FullMethodName, time.Second)
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	if err := stream.SendMsg(&platformv1.PollDeviceVerdictsRequest{}); status.Code(err) != codes.Internal {
		t.Fatalf("SendMsg(wrong type) = %v, want Internal", err)
	}
	if err := stream.RecvMsg(&platformv1.PollDeviceVerdictsResponse{}); status.Code(err) != codes.Internal {
		t.Fatalf("RecvMsg(wrong type) = %v, want Internal", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	if md, err := stream.Header(); err != nil || len(md) != 0 {
		t.Fatalf("Header = %v, %v", md, err)
	}
	if stream.Trailer() != nil || stream.Context() == nil {
		t.Fatal("the stream has no trailer and keeps its context")
	}
}

func TestWait(t *testing.T) {
	tests := []struct {
		timeout, want time.Duration
	}{
		{timeout: 0, want: MaxWait},
		{timeout: -time.Second, want: MaxWait},
		{timeout: 5 * time.Second, want: 2500 * time.Millisecond},
		{timeout: time.Minute, want: MaxWait},
	}
	for _, tt := range tests {
		if got := Wait(tt.timeout); got != tt.want {
			t.Errorf("Wait(%s) = %s, want %s", tt.timeout, got, tt.want)
		}
	}
}
