// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build integration

package vpn

import (
	"context"
	"fmt"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// VPNCommands is the transport-agnostic surface every adapter (CLI plus the
// five SDK transports) implements, so the multi-protocol test body runs
// unchanged against each protocol.
type VPNCommands interface {
	// Name identifies the transport under test.
	Name() string

	// Setup connects the adapter to the running platformd.
	Setup(ctx context.Context) error

	// Teardown releases the adapter's resources.
	Teardown() error

	// EnrolPeer admits a device to the tenant's management VPN.
	EnrolPeer(ctx context.Context, tenantID, deviceID string, zones []string) (*platformv1.VPNPeer, error)

	// ListPeers returns the tenant's enrolled peers.
	ListPeers(ctx context.Context, tenantID string) ([]*platformv1.VPNPeer, error)

	// RevokePeer removes a device from the enrolment set.
	RevokePeer(ctx context.Context, tenantID, deviceID string) error

	// Status returns the gateways' reported session state.
	Status(ctx context.Context, gatewayID string) ([]*platformv1.VPNGatewayStatus, error)

	// GetPosturePolicy returns one posture policy, module included.
	GetPosturePolicy(ctx context.Context, tenantID, name string) (*platformv1.VPNPosturePolicy, error)

	// SetPosturePolicy stores a Rego posture module.
	SetPosturePolicy(ctx context.Context, tenantID, name, module string) (*platformv1.VPNPosturePolicy, error)

	// DeletePosturePolicy removes a posture policy.
	DeletePosturePolicy(ctx context.Context, tenantID, name string) error

	// ListPosturePolicies returns the tenant's posture policies.
	ListPosturePolicies(ctx context.Context, tenantID string) ([]*platformv1.VPNPosturePolicy, error)
}

// ErrConnectionFailed indicates the adapter could not connect to platformd.
type ErrConnectionFailed struct {
	Protocol string
	Endpoint string
	Err      error
}

// Error implements the error interface.
func (e ErrConnectionFailed) Error() string {
	return fmt.Sprintf("%s connection to %s failed: %v", e.Protocol, e.Endpoint, e.Err)
}

// Unwrap returns the underlying dial failure.
func (e ErrConnectionFailed) Unwrap() error { return e.Err }

// ErrCLICommandFailed indicates a platformctl invocation failed.
type ErrCLICommandFailed struct {
	Args   []string
	Output string
	Err    error
}

// Error implements the error interface.
func (e ErrCLICommandFailed) Error() string {
	return fmt.Sprintf("platformctl %v failed: %v (output: %s)", e.Args, e.Err, e.Output)
}

// Unwrap returns the underlying exec failure.
func (e ErrCLICommandFailed) Unwrap() error { return e.Err }

// ErrCLIDecodeFailed indicates platformctl JSON output could not be parsed.
type ErrCLIDecodeFailed struct {
	Args   []string
	Output string
	Err    error
}

// Error implements the error interface.
func (e ErrCLIDecodeFailed) Error() string {
	return fmt.Sprintf("decoding platformctl %v output failed: %v (output: %s)", e.Args, e.Err, e.Output)
}

// Unwrap returns the underlying decode failure.
func (e ErrCLIDecodeFailed) Unwrap() error { return e.Err }

// ErrPostureModuleWrite indicates the CLI adapter could not stage a posture
// module file for "platformctl vpn posture-policy set --file".
type ErrPostureModuleWrite struct {
	Path string
	Err  error
}

// Error implements the error interface.
func (e ErrPostureModuleWrite) Error() string {
	return fmt.Sprintf("writing posture module %s failed: %v", e.Path, e.Err)
}

// Unwrap returns the underlying file-system failure.
func (e ErrPostureModuleWrite) Unwrap() error { return e.Err }
