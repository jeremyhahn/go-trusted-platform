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

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRecoveryUnaryInterceptor_RecoversPanic(t *testing.T) {
	interceptor := RecoveryUnaryInterceptor(nil)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	resp, err := interceptor(context.Background(), nil, info, func(context.Context, interface{}) (interface{}, error) {
		panic("boom")
	})
	if resp != nil {
		t.Errorf("expected nil response after panic, got %v", resp)
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("expected codes.Internal, got %v (err=%v)", status.Code(err), err)
	}
}

func TestRecoveryUnaryInterceptor_PassesThrough(t *testing.T) {
	interceptor := RecoveryUnaryInterceptor(nil)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	want := errors.New("handler error")
	resp, err := interceptor(context.Background(), "req", info, func(_ context.Context, req interface{}) (interface{}, error) {
		return req, want
	})
	if resp != "req" {
		t.Errorf("expected handler response passthrough, got %v", resp)
	}
	if !errors.Is(err, want) {
		t.Errorf("expected handler error passthrough, got %v", err)
	}
}

// fakeServerStream is a minimal grpc.ServerStream for interceptor tests.
type fakeServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (f *fakeServerStream) Context() context.Context { return f.ctx }

func TestRecoveryStreamInterceptor_RecoversPanic(t *testing.T) {
	interceptor := RecoveryStreamInterceptor(nil)
	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Stream"}

	err := interceptor(nil, &fakeServerStream{ctx: context.Background()}, info, func(interface{}, grpc.ServerStream) error {
		panic("stream boom")
	})
	if status.Code(err) != codes.Internal {
		t.Errorf("expected codes.Internal, got %v (err=%v)", status.Code(err), err)
	}
}

func TestRecoveryStreamInterceptor_PassesThrough(t *testing.T) {
	interceptor := RecoveryStreamInterceptor(nil)
	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Stream"}

	want := errors.New("stream handler error")
	err := interceptor(nil, &fakeServerStream{ctx: context.Background()}, info, func(interface{}, grpc.ServerStream) error {
		return want
	})
	if !errors.Is(err, want) {
		t.Errorf("expected handler error passthrough, got %v", err)
	}
}
