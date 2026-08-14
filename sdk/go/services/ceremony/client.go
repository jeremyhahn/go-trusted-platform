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

package ceremony

import "context"

// Service defines the operations exposed by the platform ceremony service.
//
// All methods are transport-agnostic: implementations are expected to dispatch
// over whichever SDK transport (embedded, rest, grpc, quic, mcp, unix) the
// caller selected via the platform.Client. The Phase 3 default client
// (returned by NewClient) is a stub that returns ErrNotYetWired for every
// method until the server-side handlers are wired up in Phase 3.5.
type Service interface {
	// Init performs the initial ceremony bootstrap.
	Init(ctx context.Context, req *InitRequest) (*InitResponse, error)
	// Status reports the current ceremony state.
	Status(ctx context.Context) (*StatusResponse, error)
	// ClaimCertBegin requests a cert-claim challenge for an officer.
	ClaimCertBegin(ctx context.Context, req *ClaimCertBeginRequest) (*ClaimCertBeginResponse, error)
	// ClaimCertComplete completes a cert-claim challenge with a signature.
	ClaimCertComplete(ctx context.Context, req *ClaimCertCompleteRequest) (*ClaimCertCompleteResponse, error)
	// ClaimShareBegin requests a share-claim challenge for an officer.
	ClaimShareBegin(ctx context.Context, req *ClaimShareBeginRequest) (*ClaimShareBeginResponse, error)
	// ClaimShareComplete completes a share-claim challenge and returns the
	// caller's Shamir share.
	ClaimShareComplete(ctx context.Context, req *ClaimShareCompleteRequest) (*ClaimShareCompleteResponse, error)
	// SignCSR signs a CSR using the ceremony CA.
	SignCSR(ctx context.Context, req *SignCSRRequest) (*SignCSRResponse, error)
}

// Client is the default Service implementation.
//
// TODO: wire to platformd server-side ceremony handlers (Phase 3.5).
// Today every method returns ErrNotYetWired.
type Client struct{}

// NewClient constructs a Phase 3 stub ceremony client.
// When server-side handlers land the signature will grow a transport argument
// (for example platform.Client) without breaking existing call sites that go
// through Service.
func NewClient() *Client {
	return &Client{}
}

// Init is the stubbed Init entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) Init(_ context.Context, _ *InitRequest) (*InitResponse, error) {
	return nil, &ErrInitFailed{Cause: ErrNotYetWired}
}

// Status is the stubbed Status entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) Status(_ context.Context) (*StatusResponse, error) {
	return nil, &ErrStatusFailed{Cause: ErrNotYetWired}
}

// ClaimCertBegin is the stubbed ClaimCertBegin entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) ClaimCertBegin(_ context.Context, _ *ClaimCertBeginRequest) (*ClaimCertBeginResponse, error) {
	return nil, &ErrClaimCertBeginFailed{Cause: ErrNotYetWired}
}

// ClaimCertComplete is the stubbed ClaimCertComplete entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) ClaimCertComplete(_ context.Context, _ *ClaimCertCompleteRequest) (*ClaimCertCompleteResponse, error) {
	return nil, &ErrClaimCertCompleteFailed{Cause: ErrNotYetWired}
}

// ClaimShareBegin is the stubbed ClaimShareBegin entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) ClaimShareBegin(_ context.Context, _ *ClaimShareBeginRequest) (*ClaimShareBeginResponse, error) {
	return nil, &ErrClaimShareFailed{Cause: ErrNotYetWired}
}

// ClaimShareComplete is the stubbed ClaimShareComplete entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) ClaimShareComplete(_ context.Context, _ *ClaimShareCompleteRequest) (*ClaimShareCompleteResponse, error) {
	return nil, &ErrClaimShareFailed{Cause: ErrNotYetWired}
}

// SignCSR is the stubbed SignCSR entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) SignCSR(_ context.Context, _ *SignCSRRequest) (*SignCSRResponse, error) {
	return nil, &ErrSignCSRFailed{Cause: ErrNotYetWired}
}

// Compile-time interface check.
var _ Service = (*Client)(nil)
