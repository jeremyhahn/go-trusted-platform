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
// Implementations dispatch over whichever SDK transport the caller selected
// via the platform.Client; GRPCClient is the gRPC-backed implementation.
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
