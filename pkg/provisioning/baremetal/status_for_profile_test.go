package baremetal

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestService_StatusForProfile_NotFound(t *testing.T) {
	svc, err := NewService(ServiceParams{
		BMC:      newMockBMC(),
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	_, err = svc.StatusForProfile(context.Background(), 1)
	var target ErrProvisionNotFound
	if !errors.As(err, &target) {
		t.Fatalf("StatusForProfile() error = %v, want ErrProvisionNotFound", err)
	}
}

func TestService_StatusForProfile_Latest(t *testing.T) {
	svc, err := NewService(ServiceParams{
		BMC:      newMockBMC(),
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	ctx := context.Background()

	result1, err := svc.Provision(ctx, &ProvisionRequest{ProfileID: 1})
	if err != nil {
		t.Fatalf("first Provision() error = %v", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	t.Cleanup(cancel)

	if _, err = waitForStatus(waitCtx, svc, result1.ProvisionID, StatusInstalling); err != nil {
		t.Fatalf("failed to reach installing: %v", err)
	}

	got, err := svc.StatusForProfile(ctx, 1)
	if err != nil {
		t.Fatalf("StatusForProfile() error = %v", err)
	}
	if got.ProvisionID != result1.ProvisionID {
		t.Fatalf("StatusForProfile() ProvisionID = %q, want %q", got.ProvisionID, result1.ProvisionID)
	}

	if err := svc.CompleteInstall(result1.ProvisionID); err != nil {
		t.Fatalf("CompleteInstall() error = %v", err)
	}
	if _, err = waitForStatus(waitCtx, svc, result1.ProvisionID, StatusComplete); err != nil {
		t.Fatalf("failed to reach complete: %v", err)
	}

	result2, err := svc.Provision(ctx, &ProvisionRequest{ProfileID: 1})
	if err != nil {
		t.Fatalf("second Provision() error = %v", err)
	}

	got, err = svc.StatusForProfile(ctx, 1)
	if err != nil {
		t.Fatalf("StatusForProfile() after second Provision error = %v", err)
	}
	if got.ProvisionID != result2.ProvisionID {
		t.Fatalf("StatusForProfile() ProvisionID = %q, want newest %q", got.ProvisionID, result2.ProvisionID)
	}

	// Clean up.
	waitCtx2, cancel2 := context.WithTimeout(ctx, 3*time.Second)
	t.Cleanup(cancel2)
	if _, err = waitForStatus(waitCtx2, svc, result2.ProvisionID, StatusInstalling); err != nil {
		t.Fatalf("failed to reach installing: %v", err)
	}
	if completeErr := svc.CompleteInstall(result2.ProvisionID); completeErr != nil {
		t.Logf("CompleteInstall cleanup error: %v", completeErr)
	}
}
