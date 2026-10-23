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

package surface

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errPlain is an error whose text names every phrase the retired substring
// lists matched on; it must not read as a declaration.
type errPlain struct{ msg string }

func (e errPlain) Error() string { return e.msg }

// recordingFataler captures Fatalf calls instead of stopping the test.
type recordingFataler struct {
	failed  bool
	message string
}

func (r *recordingFataler) Helper() {}

func (r *recordingFataler) Fatalf(format string, args ...any) {
	r.failed = true
	r.message = fmt.Sprintf(format, args...)
}

func TestIsNotImplemented_TypedDeclarations(t *testing.T) {
	noSurface := ErrNoSurface{Transport: "QUIC", Operation: "ListTemplates"}
	cases := map[string]error{
		"no surface":                    noSurface,
		"no surface wrapped":            fmt.Errorf("adapter: %w", noSurface),
		"no surface joined":             errors.Join(errPlain{msg: "cleanup"}, noSurface),
		"grpc unimplemented":            status.Error(codes.Unimplemented, "unknown method"),
		"grpc unimplemented wrapped":    fmt.Errorf("call: %w", status.Error(codes.Unimplemented, "")),
		"grpc unimplemented wrapped x2": fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", status.Error(codes.Unimplemented, ""))),
		"no surface with reason":        ErrNoSurface{Transport: "MCP", Operation: "Get", Reason: "docs/x.md §3"},
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			if !IsNotImplemented(err) {
				t.Fatalf("IsNotImplemented(%v) = false, want true", err)
			}
		})
	}
}

// TestIsNotImplemented_TextIsNeverADeclaration pins #487: every phrase the
// retired substring lists tolerated is an ordinary failure now.
func TestIsNotImplemented_TextIsNeverADeclaration(t *testing.T) {
	cases := map[string]error{
		"nil":                       nil,
		"not implemented text":      errPlain{msg: "gRPC method CreateTemplate not implemented"},
		"unimplemented text":        errPlain{msg: "rpc error: code = Unimplemented desc = x"},
		"not supported":             errPlain{msg: "operation not supported"},
		"service unavailable":       errPlain{msg: "503 Service Unavailable"},
		"404":                       errPlain{msg: "404 page not found"},
		"status 404":                errPlain{msg: "request failed, status: 404"},
		"unknown flag":              errPlain{msg: "Error: unknown flag: --template"},
		"unknown service":           errPlain{msg: "unknown service platform.v1.Device"},
		"context canceled":          context.Canceled,
		"context deadline exceeded": fmt.Errorf("dial: %w", context.DeadlineExceeded),
		"grpc unavailable":          status.Error(codes.Unavailable, "connection refused"),
		"grpc not found":            status.Error(codes.NotFound, "not implemented here"),
		"grpc internal":             status.Error(codes.Internal, "handshake failed"),
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			if IsNotImplemented(err) {
				t.Fatalf("IsNotImplemented(%v) = true, want false", err)
			}
		})
	}
}

func TestErrNoSurface_Error(t *testing.T) {
	cases := []struct {
		name string
		err  ErrNoSurface
		want string
	}{
		{
			name: "without reason",
			err:  ErrNoSurface{Transport: "gRPC", Operation: "CreateTemplate"},
			want: "gRPC has no surface for CreateTemplate",
		},
		{
			name: "with reason",
			err:  ErrNoSurface{Transport: "QUIC", Operation: "GetTemplate", Reason: "docs/device/api.md §3"},
			want: "QUIC has no surface for GetTemplate: docs/device/api.md §3",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Fatalf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}

var errBackendNotConfigured = errors.New("fido2: backend not configured")

func TestIsDeclaredRefusal_MatchesSentinel(t *testing.T) {
	cases := map[string]error{
		"sentinel":              errBackendNotConfigured,
		"sentinel wrapped":      fmt.Errorf("embedded: %w", errBackendNotConfigured),
		"rest body":             errPlain{msg: `HTTP 503: {"error":"fido2: backend not configured"}`},
		"grpc status message":   status.Error(codes.Unavailable, "fido2: backend not configured"),
		"second of two refusal": errPlain{msg: "piv: backend not configured"},
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			if !IsDeclaredRefusal(err, errors.New("piv: backend not configured"), errBackendNotConfigured) {
				t.Fatalf("IsDeclaredRefusal(%v) = false, want true", err)
			}
		})
	}
}

func TestIsDeclaredRefusal_RejectsOtherErrors(t *testing.T) {
	cases := map[string]error{
		"nil":                   nil,
		"generic unavailable":   status.Error(codes.Unavailable, "connection refused"),
		"same prefix":           errPlain{msg: "fido2: credential not found"},
		"status 503":            errPlain{msg: "HTTP 503 Service Unavailable"},
		"not implemented text":  errPlain{msg: "not implemented"},
		"permission denied":     errPlain{msg: "open /dev/hidraw0: permission denied"},
		"partial sentinel text": errPlain{msg: "backend not configured"},
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			if IsDeclaredRefusal(err, errBackendNotConfigured, nil) {
				t.Fatalf("IsDeclaredRefusal(%v) = true, want false", err)
			}
		})
	}
}

func TestIsDeclaredRefusal_NoSentinels(t *testing.T) {
	if IsDeclaredRefusal(errBackendNotConfigured) {
		t.Fatal("IsDeclaredRefusal with no sentinels = true, want false")
	}
}

func TestRequireImplemented_FailsOnDeclaration(t *testing.T) {
	fataler := &recordingFataler{}
	err := fmt.Errorf("adapter: %w", ErrNoSurface{Transport: "Unix", Operation: "ListTemplates"})

	RequireImplemented(fataler, err)

	if !fataler.failed {
		t.Fatal("expected a failure for a typed declaration")
	}
	want := "declared surface gap: adapter: Unix has no surface for ListTemplates"
	if fataler.message != want {
		t.Fatalf("failure message = %q, want %q", fataler.message, want)
	}
}

func TestRequireImplemented_LeavesOtherErrorsToCaller(t *testing.T) {
	cases := map[string]error{
		"nil":            nil,
		"text only":      errPlain{msg: "not implemented"},
		"grpc not found": status.Error(codes.NotFound, "no such template"),
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			fataler := &recordingFataler{}
			RequireImplemented(fataler, err)
			if fataler.failed {
				t.Fatalf("RequireImplemented(%v) failed the test; only a typed declaration may", err)
			}
		})
	}
}
