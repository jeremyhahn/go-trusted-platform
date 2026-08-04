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
