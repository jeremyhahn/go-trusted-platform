package daemon

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/baremetal"
	bmcwebsvc "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/bmc"
)

// The orchestrator satisfies the gRPC service's interface, and the
// adapter satisfies the REST handler's interface.
var _ BaremetalServicer = (*baremetal.Service)(nil)
var _ bmcwebsvc.BaremetalServicer = (*restBaremetalAdapter)(nil)

// adapterTestProfiles is a baremetal.ProfileChecker that knows profile 1.
type adapterTestProfiles struct{}

func (adapterTestProfiles) Get(_ context.Context, id uint64) (*bmc.Config, error) {
	if id == 1 {
		return &bmc.Config{}, nil
	}
	return nil, fmt.Errorf("profile %d not found", id)
}

func TestRESTBaremetalAdapter_StatusByProfile(t *testing.T) {
	svc, err := baremetal.NewService(baremetal.ServiceParams{
		BMC:      &fakeBMCService{},
		Profiles: adapterTestProfiles{},
		Config: &baremetal.Config{
			InstallTimeout: 5 * time.Second,
			PowerOnDelay:   10 * time.Millisecond,
		},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	adapter := newRESTBaremetalAdapter(svc)
	ctx := context.Background()

	_, err = adapter.Status(ctx, 1)
	var notFound baremetal.ErrProvisionNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("Status() before Provision error = %v, want ErrProvisionNotFound", err)
	}

	result, err := adapter.Provision(ctx, baremetal.ProvisionRequest{ProfileID: 1})
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	got, err := adapter.Status(ctx, 1)
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if got.ProvisionID != result.ProvisionID {
		t.Fatalf("Status() ProvisionID = %q, want %q", got.ProvisionID, result.ProvisionID)
	}
}
