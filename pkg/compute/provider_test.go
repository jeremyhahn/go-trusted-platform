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
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// fakeOrchestrator is a no-op Orchestrator used to prove factory resolution
// without constructing a real backend.
type fakeOrchestrator struct{}

func (fakeOrchestrator) Create(context.Context, *entities.DeviceProfile) (*Instance, error) {
	return &Instance{ID: "fake"}, nil
}
func (fakeOrchestrator) Start(context.Context, string) error                        { return nil }
func (fakeOrchestrator) Stop(context.Context, string) error                         { return nil }
func (fakeOrchestrator) Delete(context.Context, string) error                       { return nil }
func (fakeOrchestrator) List(context.Context, *InstanceFilter) ([]*Instance, error) { return nil, nil }
func (fakeOrchestrator) Get(context.Context, string) (*Instance, error)             { return nil, nil }
func (fakeOrchestrator) AttachNetwork(context.Context, string, string) error        { return nil }
func (fakeOrchestrator) DetachNetwork(context.Context, string, string) error        { return nil }
func (fakeOrchestrator) ActivateInstance(context.Context, string, *policy.PortPolicy) error {
	return nil
}
func (fakeOrchestrator) Wait(context.Context, string) error { return nil }
func (fakeOrchestrator) GetState(context.Context, string) (InstanceState, error) {
	return StateUnknown, nil
}
func (fakeOrchestrator) Close() error { return nil }

// unregisterAfterTest removes kind from the global registry when the test
// ends, so a test that registers a fake provider can run with -count > 1.
func unregisterAfterTest(t *testing.T, kind ProviderKind) {
	t.Helper()
	t.Cleanup(func() {
		registryMu.Lock()
		defer registryMu.Unlock()
		delete(orchestratorFactory, kind.normalize())
	})
}

func TestRegisterAndResolve(t *testing.T) {
	const kind ProviderKind = "test-fake-resolve"
	unregisterAfterTest(t, kind)
	RegisterOrchestrator(kind, func(context.Context, *OrchestratorConfig, *Deps) (Orchestrator, error) {
		return fakeOrchestrator{}, nil
	})

	orch, err := NewOrchestratorForConfig(context.Background(), &OrchestratorConfig{Provider: kind}, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, ok := orch.(fakeOrchestrator); !ok {
		t.Fatalf("resolved %T, want fakeOrchestrator", orch)
	}
}

func TestResolve_NilConfig(t *testing.T) {
	_, err := NewOrchestratorForConfig(context.Background(), nil, nil)
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("err = %v, want ErrInvalidConfiguration", err)
	}
}

func TestResolve_ProviderNotCompiled(t *testing.T) {
	// The aws sub-package is not imported in this test binary, so ProviderAWS
	// has no registered factory and the resolver must fail closed.
	_, err := NewOrchestratorForConfig(context.Background(), &OrchestratorConfig{Provider: ProviderAWS}, nil)
	var notCompiled *ErrComputeProviderNotCompiled
	if !errors.As(err, &notCompiled) {
		t.Fatalf("err = %v, want ErrComputeProviderNotCompiled", err)
	}
	if notCompiled.Provider != ProviderAWS {
		t.Errorf("Provider = %q, want aws", notCompiled.Provider)
	}
	if !strings.Contains(err.Error(), "awscompute") {
		t.Errorf("error should name the build tag: %v", err)
	}
}

func TestQEMUProviderRegistered(t *testing.T) {
	if !IsProviderCompiled(ProviderLocalQEMU) {
		t.Fatal("ProviderLocalQEMU must be registered (register_qemu.go init)")
	}
}

func TestRegisteredProviders_Sorted(t *testing.T) {
	kinds := RegisteredProviders()
	if len(kinds) == 0 {
		t.Fatal("expected at least the QEMU provider registered")
	}
	for i := 1; i < len(kinds); i++ {
		if kinds[i-1] > kinds[i] {
			t.Fatalf("providers not sorted: %v", kinds)
		}
	}
}

func TestRegister_NilFactoryPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on nil factory")
		}
	}()
	RegisterOrchestrator("test-nil-factory", nil)
}

func TestRegister_DuplicatePanics(t *testing.T) {
	const kind ProviderKind = "test-dup"
	factory := func(context.Context, *OrchestratorConfig, *Deps) (Orchestrator, error) {
		return fakeOrchestrator{}, nil
	}
	unregisterAfterTest(t, kind)
	RegisterOrchestrator(kind, factory)
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	RegisterOrchestrator(kind, factory)
}

func TestProviderKind_NormalizeAliases(t *testing.T) {
	cases := map[ProviderKind]ProviderKind{
		"":                     ProviderLocalContainer,
		"container":            ProviderLocalContainer,
		"local":                ProviderLocalContainer,
		ProviderLocalContainer: ProviderLocalContainer,
		"qemu":                 ProviderLocalQEMU,
		"vm":                   ProviderLocalQEMU,
		ProviderLocalQEMU:      ProviderLocalQEMU,
		ProviderAWS:            ProviderAWS,
	}
	for in, want := range cases {
		if got := in.normalize(); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProviderKind_IsCloud(t *testing.T) {
	for _, k := range []ProviderKind{ProviderAWS, ProviderGCP, ProviderAzure} {
		if !k.isCloud() {
			t.Errorf("%q should be cloud", k)
		}
	}
	for _, k := range []ProviderKind{"", ProviderLocalQEMU, ProviderLocalContainer, "vm", "container"} {
		if k.isCloud() {
			t.Errorf("%q should not be cloud", k)
		}
	}
}

func TestValidate_CloudProviderSkipsQEMUChecks(t *testing.T) {
	// A cloud VM config with no QEMU binary/OVMF paths must still validate,
	// because cloud providers do not use local firmware.
	cfg := &OrchestratorConfig{
		Type:            ComputeTypeVM,
		Provider:        ProviderAWS,
		WorkDir:         t.TempDir(),
		DefaultMemory:   512,
		DefaultCPUs:     1,
		DefaultDiskSize: "10G",
		MaxInstances:    10,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cloud VM config should validate without QEMU paths: %v", err)
	}
}

func TestValidate_LocalQEMURequiresFirmware(t *testing.T) {
	// A VM config with the empty (legacy) provider still enforces QEMU paths.
	cfg := &OrchestratorConfig{
		Type:            ComputeTypeVM,
		WorkDir:         t.TempDir(),
		DefaultMemory:   512,
		DefaultCPUs:     1,
		DefaultDiskSize: "10G",
		MaxInstances:    10,
	}
	if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("legacy VM config without QEMU binary should fail: %v", err)
	}
}
