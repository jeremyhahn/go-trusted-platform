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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// infoOnlyTPM is a minimal xkmssdk.TrustedPlatformModule implementation
// that supports only Info() + FixedProperties() + Config() — enough for
// the TPMGRPCService.Info path. All other methods panic to surface any
// incorrect reliance on them from the Info handler.
//
// This test exists to prevent a regression observed on lab-node-2
// 2026-04-08 where NewTPMGRPCService was called without ever calling
// SetTPM2Service, so every `platformctl tpm info` request returned
// codes.Unavailable "TPM service not available" even though the live
// TPM was present on the daemon host. The daemon wiring path now
// injects config.App.TPM immediately; this test locks in that contract
// at the service level.
type infoOnlyTPM struct {
	xkmssdk.TrustedPlatformModule // embedded for method-set completion; unused methods panic via nil deref
	info                          string
	infoErr                       error
}

func (t *infoOnlyTPM) Info() (string, error) {
	return t.info, t.infoErr
}

// Config returns a minimal config so the service can build a response.
func (t *infoOnlyTPM) Config() *xkmssdk.TPMConfig {
	return &xkmssdk.TPMConfig{UseSimulator: true}
}

// FixedProperties returns nil to exercise the partial-response path.
func (t *infoOnlyTPM) FixedProperties() (*xkmssdk.PropertiesFixed, error) {
	return nil, nil
}

func TestTPMGRPCService_Info_UnavailableBeforeInjection(t *testing.T) {
	svc := NewTPMGRPCService(logging.NewLogger(0, nil))
	// Service created but SetTPM2Service has NOT been called.
	_, err := svc.Info(context.Background(), &platformv1.TPMInfoRequest{})
	if err == nil {
		t.Fatal("Info on unwired service: want error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Info on unwired service: not a gRPC status error: %v", err)
	}
	if st.Code() != codes.Unavailable {
		t.Fatalf("Info on unwired service: want codes.Unavailable, got %v", st.Code())
	}
}

func TestTPMGRPCService_Info_SucceedsAfterInjection(t *testing.T) {
	svc := NewTPMGRPCService(logging.NewLogger(0, nil))
	svc.SetTPM2Service(&infoOnlyTPM{info: "mock-tpm-info"})

	resp, err := svc.Info(context.Background(), &platformv1.TPMInfoRequest{})
	if err != nil {
		t.Fatalf("Info after injection: %v", err)
	}
	if resp == nil {
		t.Fatal("Info after injection: nil response")
	}
	if resp.Properties["info"] != "mock-tpm-info" {
		t.Errorf("Info properties: want mock-tpm-info, got %q", resp.Properties["info"])
	}
	if !resp.IsSimulator {
		t.Errorf("Info.IsSimulator: want true, got false")
	}
}

func TestTPMGRPCService_Info_PropagatesBackendError(t *testing.T) {
	svc := NewTPMGRPCService(logging.NewLogger(0, nil))
	svc.SetTPM2Service(&infoOnlyTPM{infoErr: errors.New("boom")})

	_, err := svc.Info(context.Background(), &platformv1.TPMInfoRequest{})
	if err == nil {
		t.Fatal("want error propagation, got nil")
	}
}
