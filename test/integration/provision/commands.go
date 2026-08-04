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

//go:build integration

package provision

import (
	"context"
	"fmt"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// SessionCommands is the provisioning-session surface every adapter
// implements. It matches the operator-facing verbs exposed by
// `platformctl provision session` and the ConfigDeliveryService session
// RPCs, so the same scenario body runs against every transport.
type SessionCommands interface {
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	ListSessions(ctx context.Context) ([]*platformv1.ProvisioningSession, error)
	GetSession(ctx context.Context, sessionID string) (*platformv1.ProvisioningSession, error)
	FulfillSession(ctx context.Context, sessionID string, profileID uint64) (*platformv1.FulfillSessionResponse, error)
	PollSession(ctx context.Context, sessionID string) (*platformv1.PollSessionResponse, error)
}

// ProvisionCommands extends SessionCommands with the pre-enrollment verbs
// (nonce issuance and config fetch). The five SDK transports (REST, gRPC,
// QUIC, MCP, Unix) implement the full surface; the CLI adapter implements
// only SessionCommands because the CLI's pre-enrollment verbs
// (`provision fetch-config` / `provision interactive`) are raw-HTTP
// install-time flows by design, not daemon-transport commands.
type ProvisionCommands interface {
	SessionCommands

	GetNonce(ctx context.Context) (string, error)
	FetchConfig(ctx context.Context, req *platformv1.FetchConfigRequest) (*platformv1.FetchConfigResponse, error)
	SignDigest(ctx context.Context, req *platformv1.SignDigestRequest) (*platformv1.SignDigestResponse, error)
}

// ErrConnectionFailed indicates the adapter could not connect to platformd.
type ErrConnectionFailed struct {
	Protocol string
	Endpoint string
	Err      error
}

// Error returns the error message.
func (e ErrConnectionFailed) Error() string {
	return fmt.Sprintf("%s connection to %s failed: %v", e.Protocol, e.Endpoint, e.Err)
}

// Unwrap returns the underlying error.
func (e ErrConnectionFailed) Unwrap() error { return e.Err }

// ErrCallFailed indicates a protocol call failed.
type ErrCallFailed struct {
	Protocol string
	Method   string
	Err      error
}

// Error returns the error message.
func (e ErrCallFailed) Error() string {
	return fmt.Sprintf("%s call %s failed: %v", e.Protocol, e.Method, e.Err)
}

// Unwrap returns the underlying error.
func (e ErrCallFailed) Unwrap() error { return e.Err }

// ErrMTLSNotConfigured indicates the mTLS environment variables required by
// a TLS transport are not set.
type ErrMTLSNotConfigured struct {
	Protocol string
}

// Error returns the error message.
func (e ErrMTLSNotConfigured) Error() string {
	return fmt.Sprintf("%s: mTLS environment variables not configured (PLATFORM_CLIENT_CERT/PLATFORM_CLIENT_KEY/PLATFORM_CA_CERT)", e.Protocol)
}

// ErrUnexpectedOutput indicates CLI output could not be decoded into the
// expected shape.
type ErrUnexpectedOutput struct {
	Method string
	Err    error
}

// Error returns the error message.
func (e ErrUnexpectedOutput) Error() string {
	return fmt.Sprintf("CLI %s produced unexpected output: %v", e.Method, e.Err)
}

// Unwrap returns the underlying error.
func (e ErrUnexpectedOutput) Unwrap() error { return e.Err }

// ErrConfigMismatch indicates a delivered (or persisted) device config does
// not match the config seeded on the device profile.
type ErrConfigMismatch struct {
	Reason string
}

// Error returns the error message.
func (e ErrConfigMismatch) Error() string {
	return fmt.Sprintf("delivered config mismatch: %s", e.Reason)
}
