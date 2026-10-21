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

package container

import (
	"log/slog"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
)

// TrustStack is the go-quicbaas SDK container-trust stack the platform runs
// on: a Tier 0 exec runtime that resolves image content digests, wrapped by
// the Tier 1 / Tier 2 attesting runtime over the platform's host TPM.
//
// The platform contributes the host TPM and, above this stack, the
// measurement event log and fleet policy. It contributes no digest, quote or
// PCR primitive of its own.
type TrustStack struct {
	// Runtime is the Tier 0 runtime. It fills the ImageDigestResolver seam.
	Runtime *orchestration.ExecContainerRuntime

	// Attesting is the Tier 1 / Tier 2 runtime layered over Runtime.
	Attesting *orchestration.TPMAttestingRuntime
}

// NewTrustStack builds the SDK trust stack over the supplied host TPM.
//
// It fails when no container runtime binary is present or when the TPM is
// nil: an attesting stack that silently degrades to no attestation while
// advertising more is the failure mode deny-by-default exists to prevent.
func NewTrustStack(tpm orchestration.HostTPM, logger *slog.Logger) (*TrustStack, error) {
	if tpm == nil {
		return nil, ErrHostTPMRequired{}
	}

	runtime, err := orchestration.NewExecContainerRuntime(newSDKLogger(logger))
	if err != nil {
		return nil, err
	}

	attesting, err := NewAttestingRuntime(runtime, tpm, logger)
	if err != nil {
		return nil, err
	}

	return &TrustStack{Runtime: runtime, Attesting: attesting}, nil
}

// NewAttestingRuntime layers the go-quicbaas SDK's TPM attesting runtime
// (Tiers 1 and 2) over base, the Tier 0 runtime that runs the containers.
// NewTrustStack layers it over the exec runtime; a caller that already holds a
// Tier 0 runtime passes its own.
func NewAttestingRuntime(
	base orchestration.ContainerRuntime,
	tpm orchestration.HostTPM,
	logger *slog.Logger,
) (*orchestration.TPMAttestingRuntime, error) {
	if tpm == nil {
		return nil, ErrHostTPMRequired{}
	}
	return orchestration.NewTPMAttestingRuntime(base, tpm, newSDKLogger(logger))
}

// NewSDKContainerAttestor fills the go-quicbaas orchestration seam
// service.ContainerAttestor with the platform's host TPM.
//
// QuicBaaS leaves AttestContainer unimplemented until an application
// registers an attestor through quicbaas.WithContainerAttestor. The platform
// owns a real host TPM, so it can supply one: this returns the SDK's own
// runtime-backed attestor bound to that TPM, rather than a second
// implementation of the same interface.
func NewSDKContainerAttestor(tpm orchestration.HostTPM, logger *slog.Logger) (service.ContainerAttestor, error) {
	stack, err := NewTrustStack(tpm, logger)
	if err != nil {
		return nil, err
	}
	return service.NewRuntimeContainerAttestor(stack.Attesting), nil
}
