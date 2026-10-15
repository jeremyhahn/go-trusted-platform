//go:build integration

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

package vtpm

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// TestCheckSurface_DeclarationIsMissingSurface proves a missing-surface
// declaration from any transport becomes ErrMissingSurface, so the suite
// fails on it instead of skipping.
func TestCheckSurface_DeclarationIsMissingSurface(t *testing.T) {
	declarations := map[string]error{
		"ErrNoSurface":      surface.ErrNoSurface{Transport: "QUIC", Operation: "Quote"},
		"gRPCUnimplemented": status.Error(codes.Unimplemented, "unknown method QuoteVTPM"),
	}
	for name, declaration := range declarations {
		t.Run(name, func(t *testing.T) {
			err := checkSurface("Quote", declaration)

			var missing ErrMissingSurface
			if !errors.As(err, &missing) {
				t.Fatalf("checkSurface(%v) = %v, want ErrMissingSurface", declaration, err)
			}
			if missing.Operation != "Quote" {
				t.Fatalf("Operation = %q, want %q", missing.Operation, "Quote")
			}
			if !errors.Is(err, declaration) {
				t.Fatalf("ErrMissingSurface does not unwrap to the declaration %v", declaration)
			}
		})
	}
}

// TestCheckSurface_OtherErrorsPass proves checkSurface leaves nil and every
// error that is not a declaration to the caller's own assertions.
func TestCheckSurface_OtherErrorsPass(t *testing.T) {
	others := map[string]error{
		"nil":             nil,
		"plain":           errors.New("hostname is required"),
		"gRPCInvalidArgs": status.Error(codes.InvalidArgument, "hostname is required"),
	}
	for name, other := range others {
		t.Run(name, func(t *testing.T) {
			if err := checkSurface("CreateBundle", other); err != nil {
				t.Fatalf("checkSurface(%v) = %v, want nil", other, err)
			}
		})
	}
}
