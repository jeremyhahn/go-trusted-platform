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
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
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
// orchestrator still starts, so the daemon keeps serving the compute API, but
// every launch is refused with a typed error naming the missing runtimes: a
// TPM host never starts a workload unmeasured.
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
		t.Fatal("expected the container engine to be built so the compute API stays served")
	}

	ctx := context.Background()
	_, createErr := orch.engine.Create(ctx, &OrchestratorContainerSpec{Name: "refused", Image: "alpine:latest"})
	startErr := orch.engine.Start(ctx, "refused")
	// The compute API answers a start of an instance it never created with
	// the refusal too: a refusing host keeps no instance to look up.
	_, computeCreateErr := orch.Create(ctx, &entities.DeviceProfile{Name: "refused", Model: "container:image=alpine:latest"})
	computeStartErr := orch.Start(ctx, "never-created")
	for op, err := range map[string]error{
		"Create":         createErr,
		"Start":          startErr,
		"compute Create": computeCreateErr,
		"compute Start":  computeStartErr,
	} {
		var refusal *MeasuredRuntimeUnavailableError
		if !errors.As(err, &refusal) {
			t.Fatalf("%s on a TPM host without a runtime: got %v, want MeasuredRuntimeUnavailableError", op, err)
		}
		if !strings.Contains(err.Error(), "podman") || !strings.Contains(err.Error(), "docker") {
			t.Errorf("%s refusal must name the missing runtimes, got %q", op, err)
		}
	}
}

// TestComputeOrchestrator_NoHostTPMLaunchesUnmeasured pins the other side of
// the default-deny rule: only a host without a TPM launches unmeasured.
func TestComputeOrchestrator_NoHostTPMLaunchesUnmeasured(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	cfg := &compute.OrchestratorConfig{
		Type:            compute.ComputeTypeContainer,
		WorkDir:         t.TempDir(),
		DefaultMemory:   256,
		DefaultCPUs:     1,
		DefaultDiskSize: "5G",
		MaxInstances:    5,
	}
	orch, err := NewComputeOrchestrator(cfg, nil)
	if err != nil {
		t.Fatalf("NewComputeOrchestrator: %v", err)
	}
	t.Cleanup(func() {
		if err := orch.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if orch.engine.launchRefusal != nil {
		t.Fatalf("a host without a TPM must not refuse launches: %v", orch.engine.launchRefusal)
	}
	if orch.engine.measurementRequired() {
		t.Fatal("a host without a TPM cannot measure launches")
	}
}

// TestOrchestrator_LaunchRefusal checks the refusal stops a launch before the
// backend is reached, and that without it the same launch goes ahead.
func TestOrchestrator_LaunchRefusal(t *testing.T) {
	ctx := context.Background()
	spec := &OrchestratorContainerSpec{Name: "workload", Image: "alpine:latest"}
	refusal := &MeasuredRuntimeUnavailableError{Runtimes: MeasuredRuntimes}

	refusing := NewMockPodmanBackend()
	orch, err := NewOrchestrator(OrchestratorConfig{Logger: slog.Default()}, WithPodmanBackend(refusing), WithLaunchRefusal(refusal))
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	t.Cleanup(func() { _ = orch.Close() })
	if _, err := orch.Create(ctx, spec); !errors.Is(err, ErrAttestationFailed) {
		t.Fatalf("Create: got %v, want the launch refusal", err)
	}
	if len(refusing.containers) != 0 {
		t.Fatal("a refused launch must not reach the backend")
	}

	allowing := NewMockPodmanBackend()
	unmeasured, err := NewOrchestrator(OrchestratorConfig{Logger: slog.Default()}, WithPodmanBackend(allowing))
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	t.Cleanup(func() { _ = unmeasured.Close() })
	created, err := unmeasured.Create(ctx, spec)
	if err != nil {
		t.Fatalf("Create without a refusal: %v", err)
	}
	if err := unmeasured.Start(ctx, created.ID); err != nil {
		t.Fatalf("Start without a refusal: %v", err)
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
