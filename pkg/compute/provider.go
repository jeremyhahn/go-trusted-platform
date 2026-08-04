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
	"sort"
	"sync"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// ProviderKind identifies a compute orchestrator backend. Local providers
// (QEMU virtual machines, OCI containers) are always compiled; cloud
// providers are gated behind build tags and only register a factory when
// their tag is present in the build.
type ProviderKind string

const (
	// ProviderLocalQEMU launches KVM/QEMU virtual machines with a per-VM
	// swtpm vTPM. Always compiled.
	ProviderLocalQEMU ProviderKind = "local-qemu"

	// ProviderLocalContainer launches OCI containers via the consolidated
	// container orchestrator. Always compiled; the default when Provider is
	// unset.
	ProviderLocalContainer ProviderKind = "local-container"

	// ProviderAWS launches AWS EC2 NitroTPM 2.0 instances. Registered only
	// when the awscompute build tag is present.
	ProviderAWS ProviderKind = "aws"

	// ProviderGCP launches Google Compute Engine Shielded/Confidential VMs
	// with a vTPM. Registered only when the gcpcompute build tag is present.
	ProviderGCP ProviderKind = "gcp"

	// ProviderAzure launches Azure Trusted Launch VMs with a vTPM.
	// Registered only when the azurecompute build tag is present.
	ProviderAzure ProviderKind = "azure"
)

// normalize maps aliases and the empty value to a canonical ProviderKind.
// An empty Provider defaults to ProviderLocalContainer so existing daemon
// wiring that never set a provider keeps launching containers.
func (k ProviderKind) normalize() ProviderKind {
	switch k {
	case "", "container", "local", ProviderLocalContainer:
		return ProviderLocalContainer
	case "qemu", "vm", ProviderLocalQEMU:
		return ProviderLocalQEMU
	default:
		return k
	}
}

// isCloud reports whether the provider is a cloud backend. Cloud providers
// launch VMs through a vendor SDK and therefore skip the local QEMU/OVMF
// firmware validation.
func (k ProviderKind) isCloud() bool {
	switch k.normalize() {
	case ProviderAWS, ProviderGCP, ProviderAzure:
		return true
	default:
		return false
	}
}

// String returns the canonical string form of the provider.
func (k ProviderKind) String() string {
	return string(k.normalize())
}

// Deps carries provider-neutral dependencies handed to every orchestrator
// factory. Factories take only what they need: local providers use Logger
// (and HostTPM for container attestation); cloud providers use Logger and
// build their own SDK clients from the OrchestratorConfig provider block.
type Deps struct {
	// Logger is the platform logger. A nil Logger is replaced with the
	// default logger by each factory.
	Logger *logging.Logger

	// HostTPM is the host TPM used by the container orchestrator for
	// workload measurement and quote attestation. Optional; when nil,
	// container attestation is disabled. Cloud providers ignore it (guest
	// attestation uses the instance's own NitroTPM/vTPM).
	HostTPM xkmssdk.TrustedPlatformModule

	// VTPMGenerator is the profile-aware vTPM facade used by the local QEMU
	// orchestrator to source a VM's swtpm from a profile-bound, CA-issued-EK
	// bundle instead of an anonymous swtpm. Optional; when nil the QEMU
	// orchestrator fails closed for profiles that require a hardware-rooted
	// identity and otherwise falls back to an identity-less swtpm.
	VTPMGenerator vtpm.Generator
}

// logger returns d.Logger or the default logger when d or d.Logger is nil.
func (d *Deps) logger() *logging.Logger {
	if d != nil && d.Logger != nil {
		return d.Logger
	}
	return logging.DefaultLogger()
}

// OrchestratorFactory constructs an Orchestrator for a resolved provider.
// The factory receives the full OrchestratorConfig (including the
// provider-specific sub-block) and the shared Deps. Implementations must
// return typed errors and must not panic.
type OrchestratorFactory func(ctx context.Context, cfg *OrchestratorConfig, deps *Deps) (Orchestrator, error)

var (
	registryMu          sync.RWMutex
	orchestratorFactory = make(map[ProviderKind]OrchestratorFactory)
)

// RegisterOrchestrator registers an orchestrator factory for a provider
// kind. It is called from package init functions: local providers register
// from within this module, cloud providers register from their tagged
// sub-packages. Registering a nil factory or re-registering a kind panics,
// because both indicate a programming error at init time.
func RegisterOrchestrator(kind ProviderKind, factory OrchestratorFactory) {
	if factory == nil {
		panic("compute: RegisterOrchestrator called with nil factory for " + string(kind))
	}
	canonical := kind.normalize()
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := orchestratorFactory[canonical]; exists {
		panic("compute: orchestrator already registered for provider " + string(canonical))
	}
	orchestratorFactory[canonical] = factory
}

// IsProviderCompiled reports whether a factory is registered for the given
// provider kind in this build.
func IsProviderCompiled(kind ProviderKind) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	_, ok := orchestratorFactory[kind.normalize()]
	return ok
}

// RegisteredProviders returns the sorted list of provider kinds with a
// registered factory in this build. Useful for diagnostics and CLI help.
func RegisteredProviders() []ProviderKind {
	registryMu.RLock()
	kinds := make([]ProviderKind, 0, len(orchestratorFactory))
	for k := range orchestratorFactory {
		kinds = append(kinds, k)
	}
	registryMu.RUnlock()
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	return kinds
}

// NewOrchestratorForConfig resolves the compute provider named in cfg and
// constructs its orchestrator. It fails closed with a typed
// ErrComputeProviderNotCompiled when cfg names a provider whose build tag
// was not compiled into this binary, so an operator can never silently get
// a different backend than they asked for.
//
// A nil or empty Provider resolves to ProviderLocalContainer, preserving the
// historical default.
func NewOrchestratorForConfig(ctx context.Context, cfg *OrchestratorConfig, deps *Deps) (Orchestrator, error) {
	if cfg == nil {
		return nil, &SentinelCauseError{
			Sentinel: ErrInvalidConfiguration,
			Cause:    &MessageError{Msg: "config is required"},
		}
	}

	kind := cfg.Provider.normalize()

	registryMu.RLock()
	factory, ok := orchestratorFactory[kind]
	registryMu.RUnlock()
	if !ok {
		return nil, &ErrComputeProviderNotCompiled{Provider: kind}
	}

	return factory(ctx, cfg, deps)
}

// ErrComputeProviderNotCompiled is returned when the compute config names a
// provider whose build tag was not compiled into this binary. It carries the
// canonical provider kind so callers can surface a precise remediation
// (rebuild with the provider's build tag).
type ErrComputeProviderNotCompiled struct {
	// Provider is the canonical provider kind that has no registered
	// factory.
	Provider ProviderKind
}

// Error implements the error interface.
func (e *ErrComputeProviderNotCompiled) Error() string {
	return "compute: provider " + string(e.Provider) +
		" is not compiled into this build (rebuild with the provider's build tag, e.g. -tags " +
		buildTagFor(e.Provider) + ")"
}

// buildTagFor returns the build tag that compiles the named cloud provider,
// used only to enrich the not-compiled error message.
func buildTagFor(kind ProviderKind) string {
	switch kind.normalize() {
	case ProviderAWS:
		return "awscompute"
	case ProviderGCP:
		return "gcpcompute"
	case ProviderAzure:
		return "azurecompute"
	default:
		return string(kind.normalize())
	}
}
