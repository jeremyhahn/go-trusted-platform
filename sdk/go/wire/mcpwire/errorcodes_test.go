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

package mcpwire

import (
	"testing"

	"google.golang.org/grpc/codes"
)

// TestCodeForClass_EveryClassHasItsOwnCode pins the server-side table: each
// platform error class answers a distinct code, and none of them is
// InternalError.
func TestCodeForClass_EveryClassHasItsOwnCode(t *testing.T) {
	want := map[codes.Code]int{
		codes.NotFound:           NotFound,
		codes.InvalidArgument:    InvalidParams,
		codes.PermissionDenied:   PermissionDenied,
		codes.Unauthenticated:    AuthenticationRequired,
		codes.Unavailable:        ServiceUnavailable,
		codes.AlreadyExists:      AlreadyExists,
		codes.FailedPrecondition: FailedPrecondition,
		codes.Unimplemented:      MethodNotFound,
	}
	seen := make(map[int]codes.Code, len(want))
	for class, code := range want {
		got := CodeForClass(class)
		if got != code {
			t.Errorf("CodeForClass(%s) = %d, want %d", class, got, code)
		}
		if other, dup := seen[got]; dup {
			t.Errorf("%s and %s share code %d", class, other, got)
		}
		seen[got] = class
	}
}

// TestCodeForClass_UnlistedClassIsInternal keeps InternalError for a class
// the table does not name, OK included.
func TestCodeForClass_UnlistedClassIsInternal(t *testing.T) {
	for _, class := range []codes.Code{codes.OK, codes.Unknown, codes.Internal, codes.Aborted} {
		if got := CodeForClass(class); got != InternalError {
			t.Errorf("CodeForClass(%s) = %d, want InternalError", class, got)
		}
	}
}

// TestClassForCode_RoundTrip is the transport-parity contract: whatever
// class the server encodes, the client decodes back to the same class, and
// an unclassified failure decodes as Internal.
func TestClassForCode_RoundTrip(t *testing.T) {
	for class := range codeForClass {
		code := CodeForClass(class)
		if got := ClassForCode(code); got != class {
			t.Errorf("class %s encodes as %d and decodes as %s", class, code, got)
		}
	}
	if got := ClassForCode(CodeForClass(codes.Unknown)); got != codes.Internal {
		t.Errorf("unclassified decodes as %s, want Internal", got)
	}
}

// TestClassForCode_UnknownCode returns Unknown for a code the platform
// does not define.
func TestClassForCode_UnknownCode(t *testing.T) {
	for _, code := range []int{0, -32000, -32099, 42} {
		if got := ClassForCode(code); got != codes.Unknown {
			t.Errorf("ClassForCode(%d) = %s, want Unknown", code, got)
		}
	}
}
