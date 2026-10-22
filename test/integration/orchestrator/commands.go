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

package orchestrator

import (
	"context"
	"fmt"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// OrchestratorCommands is the transport-agnostic surface every adapter (CLI
// plus the five SDK transports) implements, so the multi-protocol test body
// runs unchanged against each protocol. Each method takes and returns the
// OrchestratorService messages, so every transport is held to one shape.
type OrchestratorCommands interface {
	// Name identifies the transport under test.
	Name() string

	// Setup connects the adapter to the running platformd.
	Setup(ctx context.Context) error

	// Teardown releases the adapter's resources.
	Teardown() error

	Health(ctx context.Context) (*platformv1.OrchestratorHealthResponse, error)
	ListAgents(ctx context.Context, req *platformv1.ListOrchestratorAgentsRequest) (*platformv1.ListOrchestratorAgentsResponse, error)
	GetAgent(ctx context.Context, req *platformv1.GetOrchestratorAgentRequest) (*platformv1.GetOrchestratorAgentResponse, error)
	DisableAgent(ctx context.Context, req *platformv1.DisableOrchestratorAgentRequest) (*platformv1.DisableOrchestratorAgentResponse, error)
	EnableAgent(ctx context.Context, req *platformv1.EnableOrchestratorAgentRequest) (*platformv1.EnableOrchestratorAgentResponse, error)
	ListSessions(ctx context.Context, req *platformv1.ListOrchestratorSessionsRequest) (*platformv1.ListOrchestratorSessionsResponse, error)
	CloseSession(ctx context.Context, req *platformv1.CloseOrchestratorSessionRequest) (*platformv1.CloseOrchestratorSessionResponse, error)
	ListJobs(ctx context.Context, req *platformv1.ListOrchestratorJobsRequest) (*platformv1.ListOrchestratorJobsResponse, error)
	GetJob(ctx context.Context, req *platformv1.GetOrchestratorJobRequest) (*platformv1.GetOrchestratorJobResponse, error)
	CancelJob(ctx context.Context, req *platformv1.CancelOrchestratorJobRequest) (*platformv1.CancelOrchestratorJobResponse, error)
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
