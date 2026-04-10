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

//go:build !attestation_grpc

package daemon

import (
	"context"
	"log/slog"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewAttestationServiceServer(t *testing.T) {
	server := NewAttestationServiceServer(nil, slog.Default())
	if server == nil {
		t.Fatal("NewAttestationServiceServer returned nil")
	}
	if server.logger == nil {
		t.Error("expected logger to be set")
	}
}

func TestAttestationServiceServer_AllMethodsReturnUnimplemented(t *testing.T) {
	server := NewAttestationServiceServer(nil, slog.Default())
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "GetManifest",
			call: func() error {
				_, err := server.GetManifest(ctx, &platformv1.GetManifestRequest{})
				return err
			},
		},
		{
			name: "BuildManifest",
			call: func() error {
				_, err := server.BuildManifest(ctx, &platformv1.BuildManifestRequest{})
				return err
			},
		},
		{
			name: "VerifyManifest",
			call: func() error {
				_, err := server.VerifyManifest(ctx, &platformv1.VerifyManifestRequest{})
				return err
			},
		},
		{
			name: "ListManifests",
			call: func() error {
				_, err := server.ListManifests(ctx, &platformv1.ListManifestsRequest{})
				return err
			},
		},
		{
			name: "DeleteManifest",
			call: func() error {
				_, err := server.DeleteManifest(ctx, &platformv1.DeleteManifestRequest{})
				return err
			},
		},
		{
			name: "GetAttestationQuote",
			call: func() error {
				_, err := server.GetAttestationQuote(ctx, &platformv1.GetAttestationQuoteRequest{})
				return err
			},
		},
		{
			name: "VerifyAttestationQuote",
			call: func() error {
				_, err := server.VerifyAttestationQuote(ctx, &platformv1.VerifyAttestationQuoteRequest{})
				return err
			},
		},
		{
			name: "CollectHostAttestation",
			call: func() error {
				_, err := server.CollectHostAttestation(ctx, &platformv1.CollectHostAttestationRequest{})
				return err
			},
		},
		{
			name: "CollectVMAttestation",
			call: func() error {
				_, err := server.CollectVMAttestation(ctx, &platformv1.CollectVMAttestationRequest{})
				return err
			},
		},
		{
			name: "CollectContainerAttestation",
			call: func() error {
				_, err := server.CollectContainerAttestation(ctx, &platformv1.CollectContainerAttestationRequest{})
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("expected gRPC status error, got %T: %v", err, err)
			}
			if st.Code() != codes.Unimplemented {
				t.Errorf("expected code Unimplemented, got %v", st.Code())
			}
		})
	}
}
