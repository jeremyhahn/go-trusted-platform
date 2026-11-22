// Copyright (c) 2025 Jeremy Hahn

package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// An artifact the registry never pulled, updated or pushed is listed with
// those times unset, not as 0001-01-01 (#2063).
func TestRegistryGRPCList_ZeroTimesAreUnset(t *testing.T) {
	t0 := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	mockSvc := newMockRegistryService()
	mockSvc.listResp = &RegistryListResponse{
		Artifacts: []*RegistryArtifact{{
			ID:         "a1",
			Repository: "team/app",
			Tag:        "v1",
			CreatedAt:  t0,
		}},
		Total: 1,
	}
	svc := NewRegistryGRPCService(logging.DefaultLogger(), mockSvc)

	resp, err := svc.List(context.Background(), &platformv1.ListArtifactsRequest{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(resp.Artifacts) != 1 {
		t.Fatalf("List returned %d artifacts, want 1", len(resp.Artifacts))
	}
	a := resp.Artifacts[0]
	if got := a.GetLastPulledAt(); got != nil {
		t.Errorf("LastPulledAt = %v, want unset", got.AsTime())
	}
	if got := a.GetUpdatedAt(); got != nil {
		t.Errorf("UpdatedAt = %v, want unset", got.AsTime())
	}
	if got := a.GetPushedAt(); got != nil {
		t.Errorf("PushedAt = %v, want unset", got.AsTime())
	}
	if got := a.GetCreatedAt(); got == nil || !got.AsTime().Equal(t0) {
		t.Errorf("CreatedAt = %v, want %v", got, t0)
	}
}

// A registry status with no start time reports StartedAt unset (#2063).
func TestRegistryGRPCStatus_ZeroStartedAtIsUnset(t *testing.T) {
	mockSvc := newMockRegistryService()
	mockSvc.statusResp = &RegistryStatusResponse{
		Version:   "1.0.0",
		Timestamp: time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC),
	}
	svc := NewRegistryGRPCService(logging.DefaultLogger(), mockSvc)

	resp, err := svc.Status(context.Background(), &platformv1.RegistryStatusRequest{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if got := resp.GetStartedAt(); got != nil {
		t.Errorf("StartedAt = %v, want unset", got.AsTime())
	}
}
