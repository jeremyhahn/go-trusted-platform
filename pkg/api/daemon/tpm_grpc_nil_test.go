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
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"io"
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newTPMTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, io.Discard)
}

// TestTPMGRPC_NewAndSet verifies constructor and setter.
func TestTPMGRPC_NewAndSet(t *testing.T) {
	svc := NewTPMGRPCService(newTPMTestLogger())
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	svc.SetTPM2Service(nil)
}

// TestTPMGRPC_NilTPM verifies all methods return Unavailable when TPM is nil.
func TestTPMGRPC_NilTPM(t *testing.T) {
	svc := NewTPMGRPCService(newTPMTestLogger())
	ctx := context.Background()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"Info", func() error { _, err := svc.Info(ctx, &platformv1.TPMInfoRequest{}); return err }},
		{"Provision", func() error { _, err := svc.Provision(ctx, &platformv1.TPMProvisionRequest{}); return err }},
		{"Clear", func() error { _, err := svc.Clear(ctx, &platformv1.TPMClearRequest{}); return err }},
		{"CreateEK", func() error { _, err := svc.CreateEK(ctx, &platformv1.CreateEKRequest{}); return err }},
		{"GetEK", func() error { _, err := svc.GetEK(ctx, &platformv1.GetEKRequest{}); return err }},
		{"DeleteEK", func() error { _, err := svc.DeleteEK(ctx, &platformv1.DeleteEKRequest{}); return err }},
		{"GetEKCertificate", func() error {
			_, err := svc.GetEKCertificate(ctx, &platformv1.GetEKCertificateRequest{})
			return err
		}},
		{"ImportEKCertificate", func() error {
			_, err := svc.ImportEKCertificate(ctx, &platformv1.ImportEKCertificateRequest{Certificate: []byte("cert")})
			return err
		}},
		{"CreateSRK", func() error { _, err := svc.CreateSRK(ctx, &platformv1.CreateSRKRequest{}); return err }},
		{"GetSRK", func() error { _, err := svc.GetSRK(ctx, &platformv1.GetSRKRequest{}); return err }},
		{"DeleteSRK", func() error { _, err := svc.DeleteSRK(ctx, &platformv1.DeleteSRKRequest{}); return err }},
		{"CreateAK", func() error { _, err := svc.CreateAK(ctx, &platformv1.CreateAKRequest{}); return err }},
		{"GetAK", func() error { _, err := svc.GetAK(ctx, &platformv1.GetAKRequest{}); return err }},
		{"DeleteAK", func() error { _, err := svc.DeleteAK(ctx, &platformv1.DeleteAKRequest{}); return err }},
		{"Quote", func() error {
			_, err := svc.Quote(ctx, &platformv1.QuoteRequest{Nonce: []byte("n"), PcrIndices: []uint32{0}})
			return err
		}},
		{"VerifyQuote", func() error {
			_, err := svc.VerifyQuote(ctx, &platformv1.VerifyQuoteRequest{})
			return err
		}},
		{"GetPCRs", func() error {
			_, err := svc.GetPCRs(ctx, &platformv1.GetPCRsRequest{Indices: []uint32{0}})
			return err
		}},
		{"Seal", func() error {
			_, err := svc.Seal(ctx, &platformv1.SealRequest{Data: []byte("d")})
			return err
		}},
		{"Unseal", func() error {
			_, err := svc.Unseal(ctx, &platformv1.UnsealRequest{Cn: "test"})
			return err
		}},
		{"GetRandom", func() error {
			_, err := svc.GetRandom(ctx, &platformv1.GetRandomRequest{NumBytes: 32})
			return err
		}},
		{"GetEventLog", func() error {
			_, err := svc.GetEventLog(ctx, &platformv1.GetEventLogRequest{})
			return err
		}},
		{"DefineNVRAM", func() error {
			_, err := svc.DefineNVRAM(ctx, &platformv1.DefineNVRAMRequest{Index: 1, Size: 32})
			return err
		}},
		{"ReadNVRAM", func() error {
			_, err := svc.ReadNVRAM(ctx, &platformv1.ReadNVRAMRequest{Index: 1, Size: 32})
			return err
		}},
		{"WriteNVRAM", func() error {
			_, err := svc.WriteNVRAM(ctx, &platformv1.WriteNVRAMRequest{Index: 1, Data: []byte("d")})
			return err
		}},
		{"UndefineNVRAM", func() error {
			_, err := svc.UndefineNVRAM(ctx, &platformv1.UndefineNVRAMRequest{Index: 1})
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err == nil {
				t.Fatal("expected error")
			}
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("expected gRPC status error, got %T: %v", err, err)
			}
			if st.Code() != codes.Unavailable {
				t.Errorf("expected Unavailable, got %v", st.Code())
			}
		})
	}
}
