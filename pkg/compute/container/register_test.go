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

package container

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
)

func TestContainerProviderRegistered(t *testing.T) {
	// Importing this package runs register.go init(), which registers the
	// local-container factory with the compute provider registry.
	if !compute.IsProviderCompiled(compute.ProviderLocalContainer) {
		t.Fatal("ProviderLocalContainer must be registered after importing the container package")
	}
}

func TestContainerFactory_NilConfig(t *testing.T) {
	_, err := newContainerOrchestratorForConfig(context.Background(), nil, nil)
	if !errors.Is(err, compute.ErrInvalidConfiguration) {
		t.Fatalf("err = %v, want ErrInvalidConfiguration", err)
	}
}

func TestContainerFactory_BuildsOrchestrator(t *testing.T) {
	cfg := &compute.OrchestratorConfig{
		Type:            compute.ComputeTypeContainer,
		WorkDir:         t.TempDir(),
		DefaultMemory:   256,
		DefaultCPUs:     1,
		DefaultDiskSize: "5G",
		MaxInstances:    5,
		// No OVS socket so the factory does not attempt a network connection.
	}
	orch, err := newContainerOrchestratorForConfig(context.Background(), cfg, &compute.Deps{})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if orch == nil {
		t.Fatal("expected non-nil orchestrator")
	}
	if err := orch.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestComputeOrchestrator_HostTPMWithoutRuntime pins the devcontainer case:
// a host TPM is present but neither docker nor podman is on PATH. The
// orchestrator must still start, unmeasured, so the daemon keeps serving the
// compute API instead of dropping it altogether.
func TestComputeOrchestrator_HostTPMWithoutRuntime(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	provider, err := NewHostTPMProvider(newMockQuoteTPM(t))
	if err != nil {
		t.Fatalf("NewHostTPMProvider: %v", err)
	}
	cfg := &compute.OrchestratorConfig{
		Type:            compute.ComputeTypeContainer,
		WorkDir:         t.TempDir(),
		DefaultMemory:   256,
		DefaultCPUs:     1,
		DefaultDiskSize: "5G",
		MaxInstances:    5,
	}

	orch, err := NewComputeOrchestrator(cfg, nil, WithComputeTPMProvider(provider))
	if err != nil {
		t.Fatalf("NewComputeOrchestrator: %v", err)
	}
	t.Cleanup(func() {
		if err := orch.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if orch.engine == nil {
		t.Fatal("expected the container engine to be built")
	}
	if orch.engine.measurementRequired() {
		t.Fatal("a host with no container runtime must not claim measured launches")
	}
}

// TestComputeOrchestrator_HostTPMWithRuntimeMeasures is the counterpart: with
// a runtime binary on PATH the trust stack builds and launches are measured.
func TestComputeOrchestrator_HostTPMWithRuntimeMeasures(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "podman"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake podman: %v", err)
	}
	t.Setenv("PATH", bin)

	provider, err := NewHostTPMProvider(newMockQuoteTPM(t))
	if err != nil {
		t.Fatalf("NewHostTPMProvider: %v", err)
	}
	cfg := &compute.OrchestratorConfig{
		Type:            compute.ComputeTypeContainer,
		WorkDir:         t.TempDir(),
		DefaultMemory:   256,
		DefaultCPUs:     1,
		DefaultDiskSize: "5G",
		MaxInstances:    5,
	}

	orch, err := NewComputeOrchestrator(cfg, nil, WithComputeTPMProvider(provider))
	if err != nil {
		t.Fatalf("NewComputeOrchestrator: %v", err)
	}
	t.Cleanup(func() {
		if err := orch.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if !orch.engine.measurementRequired() {
		t.Fatal("with a runtime and a host TPM, launches must be measured")
	}
}

func TestContainerFactory_ResolvesThroughRegistry(t *testing.T) {
	cfg := &compute.OrchestratorConfig{
		Type:            compute.ComputeTypeContainer,
		Provider:        compute.ProviderLocalContainer,
		WorkDir:         t.TempDir(),
		DefaultMemory:   256,
		DefaultCPUs:     1,
		DefaultDiskSize: "5G",
		MaxInstances:    5,
	}
	orch, err := compute.NewOrchestratorForConfig(context.Background(), cfg, &compute.Deps{})
	if err != nil {
		t.Fatalf("resolve local-container: %v", err)
	}
	t.Cleanup(func() { _ = orch.Close() })
	if orch == nil {
		t.Fatal("expected non-nil orchestrator")
	}
}
