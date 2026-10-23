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

package quicbaas

import (
	"context"
	"sync/atomic"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
)

// ErrContainerAttestorNotAvailable indicates no platform container attestor
// has been installed yet. The embedded QuicBaaS server is built before the
// device registry, the attestation service and the host TPM are wired, and a
// node without attestation reporting never installs one.
type ErrContainerAttestorNotAvailable struct{}

// Error implements the error interface.
func (ErrContainerAttestorNotAvailable) Error() string {
	return "container attestor not available (the platform fleet attestor is not wired on this node)"
}

// containerAttestorHolder boxes the interface so it can live behind an
// atomic.Pointer.
type containerAttestorHolder struct {
	attestor service.ContainerAttestor
}

// ContainerAttestorAdapter is the container attestor registered with the
// embedded QuicBaaS server via WithContainerAttestor. The server takes its
// options when it starts, before the platform's fleet attestor can be
// built, so the adapter forwards to whatever SetAttestor last installed and
// refuses with ErrContainerAttestorNotAvailable until then.
//
// Thread-safe: the attestor is read via atomic load on every call so
// SetAttestor can run concurrently with in-flight attestations.
type ContainerAttestorAdapter struct {
	current atomic.Pointer[containerAttestorHolder]
}

// Compile-time check that the adapter satisfies the SDK interface.
var _ service.ContainerAttestor = (*ContainerAttestorAdapter)(nil)

// NewContainerAttestorAdapter returns an adapter with no attestor installed.
func NewContainerAttestorAdapter() *ContainerAttestorAdapter {
	return &ContainerAttestorAdapter{}
}

// SetAttestor atomically installs the attestor. Passing nil clears it so
// subsequent calls return ErrContainerAttestorNotAvailable.
func (a *ContainerAttestorAdapter) SetAttestor(attestor service.ContainerAttestor) {
	if a == nil {
		return
	}
	if attestor == nil {
		a.current.Store(nil)
		return
	}
	a.current.Store(&containerAttestorHolder{attestor: attestor})
}

// AttestContainer forwards to the installed attestor.
func (a *ContainerAttestorAdapter) AttestContainer(ctx context.Context, req *service.AttestContainerRequest) (*service.AttestContainerResponse, error) {
	if a == nil {
		return nil, ErrContainerAttestorNotAvailable{}
	}
	holder := a.current.Load()
	if holder == nil {
		return nil, ErrContainerAttestorNotAvailable{}
	}
	return holder.attestor.AttestContainer(ctx, req)
}
