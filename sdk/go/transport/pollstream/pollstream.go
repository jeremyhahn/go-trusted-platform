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

// Package pollstream serves server-streaming RPCs over the SDK transports
// that carry only unary calls — REST, QUIC, MCP and embedded — by
// long-polling the RPC's unary twin. A caller of the generated client sees
// the same stream it would over gRPC.
package pollstream

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// MaxWait is the longest one poll asks the daemon to wait; the daemon clamps
// every poll to it.
const MaxWait = 20 * time.Second

// ErrNotStreamable is returned for a streaming method with no unary twin to
// poll.
type ErrNotStreamable struct {
	Method string
}

func (e ErrNotStreamable) Error() string {
	return "streaming " + e.Method + " is not supported over this transport"
}

// ErrUnexpectedMessage is returned when the stream is handed a message of
// the wrong type.
type ErrUnexpectedMessage struct {
	Method string
	Got    any
}

func (e ErrUnexpectedMessage) Error() string {
	return e.Method + ": unexpected message type " + typeName(e.Got)
}

func typeName(m any) string {
	if msg, ok := m.(proto.Message); ok {
		return string(msg.ProtoReflect().Descriptor().FullName())
	}
	return "non-protobuf value"
}

// opener opens one streaming method by polling its unary twin over cc.
type opener func(ctx context.Context, cc grpc.ClientConnInterface, wait time.Duration, opts []grpc.CallOption) (grpc.ClientStream, error)

// openers maps each streaming method served here to its opener.
var openers = map[string]opener{
	platformv1.AttestationService_StreamDeviceVerdicts_FullMethodName: openDeviceVerdicts,
}

// Wait is how long a poll may wait on a transport whose requests time out
// after timeout: half of it, so the daemon always answers first, and at most
// MaxWait. A transport with no timeout waits MaxWait.
func Wait(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return MaxWait
	}
	return min(timeout/2, MaxWait)
}

// NewStream opens method over the unary transport cc, whose requests time
// out after timeout. A method with no unary twin is Unimplemented.
func NewStream(ctx context.Context, cc grpc.ClientConnInterface, method string, timeout time.Duration, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	open, ok := openers[method]
	if !ok {
		return nil, status.Error(codes.Unimplemented, ErrNotStreamable{Method: method}.Error())
	}
	return open(ctx, cc, Wait(timeout), opts)
}

// deviceVerdictStream serves AttestationService.StreamDeviceVerdicts by
// long-polling PollDeviceVerdicts from a cursor.
type deviceVerdictStream struct {
	ctx     context.Context
	cc      grpc.ClientConnInterface
	opts    []grpc.CallOption
	wait    time.Duration
	cursor  string
	pending []*platformv1.DeviceVerdictEvent
}

// openDeviceVerdicts takes the head of the daemon's verdict feed before it
// returns, so the stream sees every verdict recorded once it is open, as the
// gRPC stream does.
func openDeviceVerdicts(ctx context.Context, cc grpc.ClientConnInterface, wait time.Duration, opts []grpc.CallOption) (grpc.ClientStream, error) {
	s := &deviceVerdictStream{ctx: ctx, cc: cc, opts: opts, wait: wait}
	if err := s.poll(0); err != nil {
		return nil, err
	}
	return s, nil
}

// poll asks the daemon for the verdicts after the cursor, waiting up to wait.
func (s *deviceVerdictStream) poll(wait time.Duration) error {
	if err := s.ctx.Err(); err != nil {
		return status.FromContextError(err).Err()
	}
	req := &platformv1.PollDeviceVerdictsRequest{Cursor: s.cursor, WaitMs: uint32(wait.Milliseconds())}
	var resp platformv1.PollDeviceVerdictsResponse
	if err := s.cc.Invoke(s.ctx, platformv1.AttestationService_PollDeviceVerdicts_FullMethodName, req, &resp, s.opts...); err != nil {
		return err
	}
	s.cursor = resp.GetCursor()
	s.pending = resp.GetVerdicts()
	return nil
}

// RecvMsg returns the next verdict, polling until there is one. A poll error
// ends the stream with that error.
func (s *deviceVerdictStream) RecvMsg(m any) error {
	out, ok := m.(*platformv1.DeviceVerdictEvent)
	if !ok {
		return status.Error(codes.Internal, ErrUnexpectedMessage{Method: platformv1.AttestationService_StreamDeviceVerdicts_FullMethodName, Got: m}.Error())
	}
	for len(s.pending) == 0 {
		if err := s.poll(s.wait); err != nil {
			return err
		}
	}
	proto.Reset(out)
	proto.Merge(out, s.pending[0])
	s.pending = s.pending[1:]
	return nil
}

// SendMsg accepts the stream's only request, which carries nothing.
func (s *deviceVerdictStream) SendMsg(m any) error {
	if _, ok := m.(*platformv1.StreamDeviceVerdictsRequest); !ok {
		return status.Error(codes.Internal, ErrUnexpectedMessage{Method: platformv1.AttestationService_StreamDeviceVerdicts_FullMethodName, Got: m}.Error())
	}
	return nil
}

// CloseSend implements grpc.ClientStream; the stream sends nothing more.
func (s *deviceVerdictStream) CloseSend() error {
	return nil
}

// Header implements grpc.ClientStream; a polled stream carries no headers.
func (s *deviceVerdictStream) Header() (metadata.MD, error) {
	return metadata.MD{}, nil
}

// Trailer implements grpc.ClientStream; a polled stream carries no trailer.
func (s *deviceVerdictStream) Trailer() metadata.MD {
	return nil
}

// Context returns the stream's context.
func (s *deviceVerdictStream) Context() context.Context {
	return s.ctx
}
