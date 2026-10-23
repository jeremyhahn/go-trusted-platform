package daemon

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// containerCreation is the outcome of createContainer.
type containerCreation struct {
	// Instance is the created container.
	Instance *compute.Instance
	// AttestErr is set when attest-on-create was asked for and the container,
	// already created, could not be attested.
	AttestErr error
}

// status reports the creation the way CreateContainerResponse.status does:
// a container that was created but failed attestation is not a success.
func (c containerCreation) status() *platformv1.Status {
	if c.AttestErr != nil {
		return &platformv1.Status{
			Success: false,
			Message: "Container created but attestation failed: " + c.AttestErr.Error(),
		}
	}
	return &platformv1.Status{
		Success: true,
		Message: "Container created successfully",
	}
}

// createContainer is the create path the gRPC CreateContainer RPC and the MCP
// container_create tool share. It creates the container from its image and,
// when attestOnCreate is set, attests it. An orchestrator that cannot attest
// refuses an attest-on-create request with ErrContainerAttestNotSupported
// before anything is created. An error from the orchestrator's Create is
// returned as is, for each transport to map; a Create that answers no instance
// is refused with ErrContainerCreateNoInstance.
func createContainer(ctx context.Context, orchestrator compute.Orchestrator, name, image string, attestOnCreate bool) (containerCreation, error) {
	var attester containerAttester
	if attestOnCreate {
		var ok bool
		if attester, ok = orchestrator.(containerAttester); !ok {
			return containerCreation{}, ErrContainerAttestNotSupported{}
		}
	}

	profile := &entities.DeviceProfile{
		Name:  name,
		Model: "container:image=" + image,
	}
	instance, err := orchestrator.Create(ctx, profile)
	if err != nil {
		return containerCreation{}, err
	}
	if instance == nil {
		return containerCreation{}, ErrContainerCreateNoInstance{}
	}

	creation := containerCreation{Instance: instance}
	if attester != nil {
		_, creation.AttestErr = attester.Attest(ctx, instance.ID)
	}
	return creation, nil
}
