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

package compute

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// Orchestrator defines the common interface for compute orchestration
// supporting both VMs and containers with unified lifecycle management
type Orchestrator interface {
	// Create creates a new compute instance from a device profile
	Create(ctx context.Context, profile *entities.DeviceProfile) (*Instance, error)

	// Start starts a stopped instance
	Start(ctx context.Context, instanceID string) error

	// Stop stops a running instance
	Stop(ctx context.Context, instanceID string) error

	// Delete deletes an instance and cleans up resources
	Delete(ctx context.Context, instanceID string) error

	// List returns all instances, optionally filtered
	List(ctx context.Context, filter *InstanceFilter) ([]*Instance, error)

	// Get retrieves a specific instance by ID
	Get(ctx context.Context, instanceID string) (*Instance, error)

	// AttachNetwork attaches an instance to an OVS network port
	AttachNetwork(ctx context.Context, instanceID, portName string) error

	// DetachNetwork detaches an instance from an OVS network port
	DetachNetwork(ctx context.Context, instanceID, portName string) error

	// ActivateInstance transitions an instance's network port from enrolled to authorized
	// This is called after the device has completed enrollment and is ready for production use
	ActivateInstance(ctx context.Context, instanceID string, portPolicy *policy.PortPolicy) error

	// Wait waits for an instance to exit (blocks until instance stops)
	Wait(ctx context.Context, instanceID string) error

	// GetState returns the current state of an instance
	GetState(ctx context.Context, instanceID string) (InstanceState, error)

	// Close closes the orchestrator and releases resources
	Close() error
}
