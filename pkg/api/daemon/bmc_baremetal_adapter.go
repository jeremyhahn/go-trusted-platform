package daemon

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/baremetal"
)

// restBaremetalAdapter adapts the bare metal orchestrator to the REST
// handler's BaremetalServicer: the handler passes the request by value and
// asks for status by profile ID.
type restBaremetalAdapter struct {
	svc *baremetal.Service
}

// newRESTBaremetalAdapter wraps svc for the BMC REST handler.
func newRESTBaremetalAdapter(svc *baremetal.Service) *restBaremetalAdapter {
	return &restBaremetalAdapter{svc: svc}
}

// Provision starts a provisioning workflow for req.ProfileID.
func (a *restBaremetalAdapter) Provision(ctx context.Context, req baremetal.ProvisionRequest) (*baremetal.ProvisionResult, error) {
	return a.svc.Provision(ctx, &req)
}

// Status returns the newest provisioning result for profileID.
func (a *restBaremetalAdapter) Status(ctx context.Context, profileID uint64) (*baremetal.ProvisionResult, error) {
	return a.svc.StatusForProfile(ctx, profileID)
}
