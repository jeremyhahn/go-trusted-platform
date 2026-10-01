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
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// mockPolicyEngine is a minimal 802.1X policy engine for port-auth tests.
type mockPolicyEngine struct {
	mu          sync.Mutex
	portStates  map[string]policy.PortState
	setStateErr error
	applyErr    error
	removeErr   error
	applied     map[string]*policy.PortPolicy
}

func newMockPolicyEngine() *mockPolicyEngine {
	return &mockPolicyEngine{
		portStates: make(map[string]policy.PortState),
		applied:    make(map[string]*policy.PortPolicy),
	}
}

func (m *mockPolicyEngine) SetPortState(portID string, state policy.PortState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.setStateErr != nil {
		return m.setStateErr
	}
	m.portStates[portID] = state
	return nil
}

func (m *mockPolicyEngine) GetPortState(portID string) (policy.PortState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.portStates[portID], nil
}

func (m *mockPolicyEngine) GetPortInfo(portID string) (*policy.PortInfo, error) {
	return nil, nil
}

func (m *mockPolicyEngine) ApplyPolicy(portID string, portPolicy *policy.PortPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.applyErr != nil {
		return m.applyErr
	}
	m.applied[portID] = portPolicy
	m.portStates[portID] = policy.PortStateAuthorized
	return nil
}

func (m *mockPolicyEngine) RemovePolicy(portID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.removeErr != nil {
		return m.removeErr
	}
	delete(m.applied, portID)
	delete(m.portStates, portID)
	return nil
}

func (m *mockPolicyEngine) GetPolicy(portID string) (*policy.PortPolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applied[portID], nil
}

func (m *mockPolicyEngine) SetPortVLAN(portID string, vlan uint16) error { return nil }
func (m *mockPolicyEngine) GetPortVLAN(portID string) (uint16, error)    { return 0, nil }
func (m *mockPolicyEngine) BlockPort(portID string) error                { return nil }
func (m *mockPolicyEngine) UnblockPort(portID string) error              { return nil }
func (m *mockPolicyEngine) GetOFPort(portID string) (int32, error)       { return 0, nil }
func (m *mockPolicyEngine) AuthenticatePort(portID string, cert *x509.Certificate) error {
	return nil
}
func (m *mockPolicyEngine) OnCertificateExpired(portID string) error { return nil }
func (m *mockPolicyEngine) OnCertificateRevoked(portID string) error { return nil }
func (m *mockPolicyEngine) GetMonitor() *policy.CertificateMonitor   { return nil }

// newTestComputeConfig returns a valid container orchestrator configuration.
func newTestComputeConfig() *compute.OrchestratorConfig {
	return &compute.OrchestratorConfig{
		Type:            compute.ComputeTypeContainer,
		WorkDir:         "/tmp/compute-test",
		DefaultMemory:   512,
		DefaultCPUs:     1,
		DefaultDiskSize: "10G",
		MaxInstances:    10,
		NetworkBridge:   "br-int",
	}
}

// newTestComputeOrchestrator builds a ComputeOrchestrator over a mock
// Podman backend, optionally with attestation enabled.
func newTestComputeOrchestrator(t *testing.T, config *compute.OrchestratorConfig, withAttestation bool, opts ...ComputeOrchestratorOption) (*ComputeOrchestrator, *MockPodmanBackend) {
	t.Helper()

	backend := NewMockPodmanBackend()

	engineOpts := []OrchestratorOption{WithPodmanBackend(backend)}
	enableAttestation := false
	if withAttestation {
		tpm := NewMockTPMProvider()
		attestor, err := NewContainerAttestor(tpm, WithAttestingRuntime(newTestAttestingRuntime(t, tpm)))
		if err != nil {
			t.Fatalf("failed to create attestor: %v", err)
		}
		engineOpts = append(engineOpts,
			WithAttestor(attestor),
			WithImageDigestResolver(fixedDigestResolver{}),
		)
		enableAttestation = true
	}

	engine, err := NewOrchestrator(OrchestratorConfig{
		Logger:            slog.Default(),
		EnableAttestation: enableAttestation,
	}, engineOpts...)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	opts = append(opts, WithComputeEngine(engine))
	orchestrator, err := NewComputeOrchestrator(config, logging.DefaultLogger(), opts...)
	if err != nil {
		t.Fatalf("failed to create compute orchestrator: %v", err)
	}
	return orchestrator, backend
}

func testProfile() *entities.DeviceProfile {
	return &entities.DeviceProfile{
		ID:    42,
		Name:  "test-profile",
		Model: "container:image=docker.io/library/busybox:latest",
	}
}

func TestNewComputeOrchestrator(t *testing.T) {
	t.Run("rejects nil config", func(t *testing.T) {
		_, err := NewComputeOrchestrator(nil, logging.DefaultLogger())
		if !errors.Is(err, compute.ErrInvalidConfiguration) {
			t.Fatalf("expected ErrInvalidConfiguration, got %v", err)
		}
	})

	t.Run("rejects VM compute type", func(t *testing.T) {
		config := compute.DefaultOrchestratorConfig(compute.ComputeTypeVM)
		_, err := NewComputeOrchestrator(config, logging.DefaultLogger())
		if !errors.Is(err, compute.ErrInvalidConfiguration) {
			t.Fatalf("expected ErrInvalidConfiguration, got %v", err)
		}
	})

	t.Run("rejects invalid config", func(t *testing.T) {
		config := newTestComputeConfig()
		config.MaxInstances = 0
		_, err := NewComputeOrchestrator(config, logging.DefaultLogger())
		if !errors.Is(err, compute.ErrInvalidConfiguration) {
			t.Fatalf("expected ErrInvalidConfiguration, got %v", err)
		}
	})

	t.Run("creates orchestrator with injected engine", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()
		if orchestrator.Engine() == nil {
			t.Fatal("expected engine accessor to return the engine")
		}
	})
}

func TestComputeOrchestrator_Create(t *testing.T) {
	ctx := context.Background()

	t.Run("creates instance from profile", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		instance, err := orchestrator.Create(ctx, testProfile())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if instance.Type != compute.ComputeTypeContainer {
			t.Fatalf("expected container type, got %s", instance.Type)
		}
		if instance.State != compute.StateStopped {
			t.Fatalf("expected stopped state, got %s", instance.State)
		}
		if instance.Metadata["image"] != "docker.io/library/busybox:latest" {
			t.Fatalf("expected image from profile model, got %s", instance.Metadata["image"])
		}
		if instance.Metadata["container_id"] != instance.ID {
			t.Fatal("expected container_id metadata to match instance ID")
		}
	})

	t.Run("supports multiple instances from same profile", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		if _, err := orchestrator.Create(ctx, testProfile()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := orchestrator.Create(ctx, testProfile()); err != nil {
			t.Fatalf("expected second create from same profile to succeed, got %v", err)
		}
	})

	t.Run("rejects nil profile", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		if _, err := orchestrator.Create(ctx, nil); !errors.Is(err, compute.ErrInvalidProfile) {
			t.Fatalf("expected ErrInvalidProfile, got %v", err)
		}
	})

	t.Run("enforces instance limit", func(t *testing.T) {
		config := newTestComputeConfig()
		config.MaxInstances = 1
		orchestrator, _ := newTestComputeOrchestrator(t, config, false)
		defer orchestrator.Close()

		if _, err := orchestrator.Create(ctx, testProfile()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := orchestrator.Create(ctx, testProfile()); !errors.Is(err, compute.ErrResourceExhausted) {
			t.Fatalf("expected ErrResourceExhausted, got %v", err)
		}
	})

	t.Run("maps engine create failure", func(t *testing.T) {
		orchestrator, backend := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()
		backend.createError = errors.New("podman down")

		if _, err := orchestrator.Create(ctx, testProfile()); err == nil {
			t.Fatal("expected create error")
		}
	})

	t.Run("rejects create on closed orchestrator", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		orchestrator.Close()

		if _, err := orchestrator.Create(ctx, testProfile()); !errors.Is(err, compute.ErrOrchestratorNotInitialized) {
			t.Fatalf("expected ErrOrchestratorNotInitialized, got %v", err)
		}
	})
}

func TestComputeOrchestrator_Lifecycle(t *testing.T) {
	ctx := context.Background()

	t.Run("start stop delete lifecycle", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		instance, err := orchestrator.Create(ctx, testProfile())
		if err != nil {
			t.Fatalf("create failed: %v", err)
		}

		if err := orchestrator.Start(ctx, instance.ID); err != nil {
			t.Fatalf("start failed: %v", err)
		}

		state, err := orchestrator.GetState(ctx, instance.ID)
		if err != nil {
			t.Fatalf("get state failed: %v", err)
		}
		if state != compute.StateRunning {
			t.Fatalf("expected running, got %s", state)
		}

		if err := orchestrator.Stop(ctx, instance.ID); err != nil {
			t.Fatalf("stop failed: %v", err)
		}

		if err := orchestrator.Delete(ctx, instance.ID); err != nil {
			t.Fatalf("delete failed: %v", err)
		}

		if _, err := orchestrator.Get(ctx, instance.ID); !errors.Is(err, compute.ErrInstanceNotFound) {
			t.Fatalf("expected ErrInstanceNotFound after delete, got %v", err)
		}
	})

	t.Run("start maps already-running error", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		instance, _ := orchestrator.Create(ctx, testProfile())
		if err := orchestrator.Start(ctx, instance.ID); err != nil {
			t.Fatalf("start failed: %v", err)
		}
		if err := orchestrator.Start(ctx, instance.ID); !errors.Is(err, compute.ErrInstanceAlreadyRunning) {
			t.Fatalf("expected ErrInstanceAlreadyRunning, got %v", err)
		}
	})

	t.Run("stop maps not-running error", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		instance, _ := orchestrator.Create(ctx, testProfile())
		if err := orchestrator.Stop(ctx, instance.ID); !errors.Is(err, compute.ErrInstanceNotRunning) {
			t.Fatalf("expected ErrInstanceNotRunning, got %v", err)
		}
	})

	t.Run("operations reject unknown instance", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		if err := orchestrator.Start(ctx, "unknown"); !errors.Is(err, compute.ErrInstanceNotFound) {
			t.Fatalf("expected ErrInstanceNotFound, got %v", err)
		}
		if err := orchestrator.Stop(ctx, "unknown"); !errors.Is(err, compute.ErrInstanceNotFound) {
			t.Fatalf("expected ErrInstanceNotFound, got %v", err)
		}
		if err := orchestrator.Delete(ctx, "unknown"); !errors.Is(err, compute.ErrInstanceNotFound) {
			t.Fatalf("expected ErrInstanceNotFound, got %v", err)
		}
	})

	t.Run("operations reject empty instance ID", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		if err := orchestrator.Start(ctx, ""); !errors.Is(err, compute.ErrInvalidInstanceID) {
			t.Fatalf("expected ErrInvalidInstanceID, got %v", err)
		}
	})
}

func TestComputeOrchestrator_ListAndGet(t *testing.T) {
	ctx := context.Background()

	t.Run("lists instances with filter", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		instance, _ := orchestrator.Create(ctx, testProfile())

		containerType := compute.ComputeTypeContainer
		instances, err := orchestrator.List(ctx, &compute.InstanceFilter{Type: &containerType})
		if err != nil {
			t.Fatalf("list failed: %v", err)
		}
		if len(instances) != 1 || instances[0].ID != instance.ID {
			t.Fatalf("expected the created instance, got %+v", instances)
		}

		vmType := compute.ComputeTypeVM
		instances, err = orchestrator.List(ctx, &compute.InstanceFilter{Type: &vmType})
		if err != nil {
			t.Fatalf("list failed: %v", err)
		}
		if len(instances) != 0 {
			t.Fatalf("expected no VM instances, got %d", len(instances))
		}
	})

	t.Run("get returns instance copy", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		created, _ := orchestrator.Create(ctx, testProfile())
		fetched, err := orchestrator.Get(ctx, created.ID)
		if err != nil {
			t.Fatalf("get failed: %v", err)
		}
		if fetched.ID != created.ID {
			t.Fatal("instance ID mismatch")
		}

		// Mutating the returned copy must not affect internal state.
		fetched.Name = "mutated"
		again, _ := orchestrator.Get(ctx, created.ID)
		if again.Name == "mutated" {
			t.Fatal("expected Get to return a copy")
		}
	})

	t.Run("get rejects empty and unknown IDs", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		if _, err := orchestrator.Get(ctx, ""); !errors.Is(err, compute.ErrInvalidInstanceID) {
			t.Fatalf("expected ErrInvalidInstanceID, got %v", err)
		}
		if _, err := orchestrator.Get(ctx, "unknown"); !errors.Is(err, compute.ErrInstanceNotFound) {
			t.Fatalf("expected ErrInstanceNotFound, got %v", err)
		}
	})
}

func TestComputeOrchestrator_Network(t *testing.T) {
	ctx := context.Background()

	newNetworkOrchestrator := func(t *testing.T, portAuth bool) (*ComputeOrchestrator, *mockPolicyEngine) {
		config := newTestComputeConfig()
		engine := newMockPolicyEngine()
		if portAuth {
			config.PortAuthEnabled = true
			config.PolicyEngine = engine
		}
		orchestrator, _ := newTestComputeOrchestrator(t, config, false,
			WithComputeOVSClient(&ovs.Client{}))
		return orchestrator, engine
	}

	t.Run("attach and detach without port auth", func(t *testing.T) {
		orchestrator, _ := newNetworkOrchestrator(t, false)
		defer orchestrator.Close()

		instance, _ := orchestrator.Create(ctx, testProfile())

		if err := orchestrator.AttachNetwork(ctx, instance.ID, "veth0"); err != nil {
			t.Fatalf("attach failed: %v", err)
		}

		fetched, _ := orchestrator.Get(ctx, instance.ID)
		if len(fetched.NetworkAttachments) != 1 || fetched.NetworkAttachments[0].PortName != "veth0" {
			t.Fatalf("expected veth0 attachment, got %+v", fetched.NetworkAttachments)
		}

		if err := orchestrator.DetachNetwork(ctx, instance.ID, "veth0"); err != nil {
			t.Fatalf("detach failed: %v", err)
		}

		fetched, _ = orchestrator.Get(ctx, instance.ID)
		if len(fetched.NetworkAttachments) != 0 {
			t.Fatal("expected no attachments after detach")
		}
	})

	t.Run("attach with port auth sets provisioning state", func(t *testing.T) {
		orchestrator, engine := newNetworkOrchestrator(t, true)
		defer orchestrator.Close()

		instance, _ := orchestrator.Create(ctx, testProfile())

		if err := orchestrator.AttachNetwork(ctx, instance.ID, "veth1"); err != nil {
			t.Fatalf("attach failed: %v", err)
		}

		state, _ := engine.GetPortState("veth1")
		if state != policy.PortStateProvisioning {
			t.Fatalf("expected provisioning state, got %v", state)
		}
	})

	t.Run("attach rolls back on provisioning failure", func(t *testing.T) {
		orchestrator, engine := newNetworkOrchestrator(t, true)
		defer orchestrator.Close()
		engine.setStateErr = errors.New("openflow down")

		instance, _ := orchestrator.Create(ctx, testProfile())

		if err := orchestrator.AttachNetwork(ctx, instance.ID, "veth2"); !errors.Is(err, compute.ErrNetworkAttachmentFailed) {
			t.Fatalf("expected ErrNetworkAttachmentFailed, got %v", err)
		}

		fetched, _ := orchestrator.Get(ctx, instance.ID)
		if len(fetched.NetworkAttachments) != 0 {
			t.Fatal("expected attachment rollback")
		}
	})

	t.Run("attach fails without OVS client", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		instance, _ := orchestrator.Create(ctx, testProfile())

		if err := orchestrator.AttachNetwork(ctx, instance.ID, "veth0"); !errors.Is(err, compute.ErrNetworkAttachmentFailed) {
			t.Fatalf("expected ErrNetworkAttachmentFailed, got %v", err)
		}
	})

	t.Run("detach fails when no network attached", func(t *testing.T) {
		orchestrator, _ := newNetworkOrchestrator(t, false)
		defer orchestrator.Close()

		instance, _ := orchestrator.Create(ctx, testProfile())

		if err := orchestrator.DetachNetwork(ctx, instance.ID, "veth0"); !errors.Is(err, compute.ErrNetworkDetachmentFailed) {
			t.Fatalf("expected ErrNetworkDetachmentFailed, got %v", err)
		}
	})

	t.Run("activate applies production policy", func(t *testing.T) {
		orchestrator, engine := newNetworkOrchestrator(t, true)
		defer orchestrator.Close()

		instance, _ := orchestrator.Create(ctx, testProfile())
		if err := orchestrator.AttachNetwork(ctx, instance.ID, "veth3"); err != nil {
			t.Fatalf("attach failed: %v", err)
		}

		portPolicy := &policy.PortPolicy{VLAN: 100}
		if err := orchestrator.ActivateInstance(ctx, instance.ID, portPolicy); err != nil {
			t.Fatalf("activate failed: %v", err)
		}

		state, _ := engine.GetPortState("veth3")
		if state != policy.PortStateAuthorized {
			t.Fatalf("expected authorized state, got %v", state)
		}

		fetched, _ := orchestrator.Get(ctx, instance.ID)
		if fetched.Metadata["port_state"] != "authorized" || fetched.Metadata["vlan"] != "100" {
			t.Fatalf("expected port metadata, got %+v", fetched.Metadata)
		}
	})

	t.Run("activate errors", func(t *testing.T) {
		orchestrator, _ := newNetworkOrchestrator(t, true)
		defer orchestrator.Close()

		instance, _ := orchestrator.Create(ctx, testProfile())

		if err := orchestrator.ActivateInstance(ctx, instance.ID, nil); err == nil {
			t.Fatal("expected error for nil policy")
		}
		if err := orchestrator.ActivateInstance(ctx, instance.ID, &policy.PortPolicy{}); err == nil {
			t.Fatal("expected error when no port mapped")
		}
		if err := orchestrator.ActivateInstance(ctx, "unknown", &policy.PortPolicy{}); !errors.Is(err, compute.ErrInstanceNotFound) {
			t.Fatalf("expected ErrInstanceNotFound, got %v", err)
		}
	})

	t.Run("delete removes port auth", func(t *testing.T) {
		orchestrator, engine := newNetworkOrchestrator(t, true)
		defer orchestrator.Close()

		instance, _ := orchestrator.Create(ctx, testProfile())
		if err := orchestrator.AttachNetwork(ctx, instance.ID, "veth4"); err != nil {
			t.Fatalf("attach failed: %v", err)
		}

		if err := orchestrator.Delete(ctx, instance.ID); err != nil {
			t.Fatalf("delete failed: %v", err)
		}

		engine.mu.Lock()
		_, exists := engine.portStates["veth4"]
		engine.mu.Unlock()
		if exists {
			t.Fatal("expected port auth removal on delete")
		}
	})
}

func TestComputeOrchestrator_Wait(t *testing.T) {
	ctx := context.Background()

	t.Run("waits for container exit", func(t *testing.T) {
		orchestrator, backend := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()
		backend.waitExitCode = 3

		instance, _ := orchestrator.Create(ctx, testProfile())
		if err := orchestrator.Start(ctx, instance.ID); err != nil {
			t.Fatalf("start failed: %v", err)
		}

		if err := orchestrator.Wait(ctx, instance.ID); err != nil {
			t.Fatalf("wait failed: %v", err)
		}

		fetched, _ := orchestrator.Get(ctx, instance.ID)
		if fetched.Metadata["exit_code"] != "3" {
			t.Fatalf("expected exit code 3, got %s", fetched.Metadata["exit_code"])
		}
		if fetched.State != compute.StateStopped {
			t.Fatalf("expected stopped state, got %s", fetched.State)
		}
	})

	t.Run("wait maps backend failure", func(t *testing.T) {
		orchestrator, backend := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()
		backend.waitError = errors.New("wait failed")

		instance, _ := orchestrator.Create(ctx, testProfile())
		if err := orchestrator.Wait(ctx, instance.ID); err == nil {
			t.Fatal("expected wait error")
		}
	})

	t.Run("wait rejects unknown instance", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		if err := orchestrator.Wait(ctx, "unknown"); !errors.Is(err, compute.ErrInstanceNotFound) {
			t.Fatalf("expected ErrInstanceNotFound, got %v", err)
		}
	})
}

func TestComputeOrchestrator_RichCapabilities(t *testing.T) {
	ctx := context.Background()

	t.Run("logs returns container output", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		instance, _ := orchestrator.Create(ctx, testProfile())

		reader, err := orchestrator.Logs(ctx, instance.ID, LogOptions{Stdout: true, Stderr: true})
		if err != nil {
			t.Fatalf("logs failed: %v", err)
		}
		defer reader.Close()

		data, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("read failed: %v", err)
		}
		if len(data) == 0 {
			t.Fatal("expected log output")
		}
	})

	t.Run("logs rejects unknown instance", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		if _, err := orchestrator.Logs(ctx, "unknown", LogOptions{}); !errors.Is(err, compute.ErrInstanceNotFound) {
			t.Fatalf("expected ErrInstanceNotFound, got %v", err)
		}
	})

	t.Run("attest produces quote-based report", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), true)
		defer orchestrator.Close()

		instance, _ := orchestrator.Create(ctx, testProfile())

		report, err := orchestrator.Attest(ctx, instance.ID)
		if err != nil {
			t.Fatalf("attest failed: %v", err)
		}
		if report.ContainerID != instance.ID {
			t.Fatal("report container ID mismatch")
		}
		if len(report.Quote) == 0 || len(report.Signature) == 0 {
			t.Fatal("expected quote and signature in report")
		}
	})

	t.Run("attest fails without attestor", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		instance, _ := orchestrator.Create(ctx, testProfile())

		if _, err := orchestrator.Attest(ctx, instance.ID); !errors.Is(err, ErrAttestationFailed) {
			t.Fatalf("expected ErrAttestationFailed, got %v", err)
		}
	})

	t.Run("verify attestation requires known instance", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), true)
		defer orchestrator.Close()

		if err := orchestrator.VerifyAttestation(ctx, "unknown", []byte("evidence")); !errors.Is(err, compute.ErrInstanceNotFound) {
			t.Fatalf("expected ErrInstanceNotFound, got %v", err)
		}
	})

	t.Run("evaluate policy allows by default", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		decision, err := orchestrator.EvaluatePolicy(ctx, &OrchestratorContainerSpec{
			Name:  "policy-test",
			Image: "busybox:latest",
		})
		if err != nil {
			t.Fatalf("evaluate policy failed: %v", err)
		}
		if !decision.Allowed {
			t.Fatal("expected policy to allow by default")
		}
	})

	t.Run("evaluate policy rejects nil spec", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		if _, err := orchestrator.EvaluatePolicy(ctx, nil); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("expected ErrInvalidSpec, got %v", err)
		}
	})

	t.Run("pull image delegates to engine", func(t *testing.T) {
		orchestrator, backend := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		if err := orchestrator.PullImage(ctx, "busybox:latest", PullOptions{}); err != nil {
			t.Fatalf("pull failed: %v", err)
		}
		if backend.pullCalled != 1 {
			t.Fatalf("expected 1 pull call, got %d", backend.pullCalled)
		}
	})

	t.Run("pull image rejects empty ref", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		if err := orchestrator.PullImage(ctx, "", PullOptions{}); !errors.Is(err, ErrInvalidImage) {
			t.Fatalf("expected ErrInvalidImage, got %v", err)
		}
	})

	t.Run("verify image fails closed without image manager", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		verification, err := orchestrator.VerifyImage(ctx, "busybox:latest")
		if !errors.Is(err, ErrImageManagerUnavailable) {
			t.Fatalf("expected ErrImageManagerUnavailable, got %v", err)
		}
		if verification != nil {
			t.Fatalf("no verification result may be returned, got %+v", verification)
		}
	})

	t.Run("verify image rejects empty ref", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		defer orchestrator.Close()

		if _, err := orchestrator.VerifyImage(ctx, ""); !errors.Is(err, ErrInvalidImage) {
			t.Fatalf("expected ErrInvalidImage, got %v", err)
		}
	})

	t.Run("capabilities rejected after close", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		orchestrator.Close()

		if err := orchestrator.PullImage(ctx, "busybox:latest", PullOptions{}); !errors.Is(err, compute.ErrOrchestratorNotInitialized) {
			t.Fatalf("expected ErrOrchestratorNotInitialized, got %v", err)
		}
		if _, err := orchestrator.EvaluatePolicy(ctx, &OrchestratorContainerSpec{}); !errors.Is(err, compute.ErrOrchestratorNotInitialized) {
			t.Fatalf("expected ErrOrchestratorNotInitialized, got %v", err)
		}
	})
}

func TestBuildContainerSpec_TPMAccess(t *testing.T) {
	orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
	defer orchestrator.Close()

	t.Run("TPM access disabled by default", func(t *testing.T) {
		spec := orchestrator.buildContainerSpec(testProfile(), "abcd1234")
		if spec.TPMAccess {
			t.Fatal("expected TPM access disabled by default")
		}
	})

	t.Run("TPM access follows podman config", func(t *testing.T) {
		orchestrator.podmanConfig.EnableTPMAccess = true
		defer func() { orchestrator.podmanConfig.EnableTPMAccess = false }()

		spec := orchestrator.buildContainerSpec(testProfile(), "abcd1234")
		if !spec.TPMAccess {
			t.Fatal("expected TPM access enabled")
		}

		launch := newLaunchConfig(spec)
		if !launch.GrantsTPMDevice() {
			t.Fatal("expected the launch configuration to grant the TPM device")
		}
		found := false
		for _, mount := range launch.Mounts {
			if mount.Source == HostTPMDevicePath && mount.Target == HostTPMDevicePath {
				found = true
			}
		}
		if !found {
			t.Fatal("expected /dev/tpm0 bind mount")
		}
	})

	// The host default is the one surviving TPM knob, and it survives BECAUSE it
	// is projected into the specification before the container is measured. If
	// it ever stopped moving the digest it would be granting the platform's root
	// of trust behind the measurement, which is what the runtime-level default
	// used to do.
	t.Run("the host default changes the configuration digest", func(t *testing.T) {
		withoutTPM := digestOfSpec(t, orchestrator.buildContainerSpec(testProfile(), "abcd1234"))

		orchestrator.podmanConfig.EnableTPMAccess = true
		defer func() { orchestrator.podmanConfig.EnableTPMAccess = false }()

		withTPM := digestOfSpec(t, orchestrator.buildContainerSpec(testProfile(), "abcd1234"))
		if withoutTPM == withTPM {
			t.Fatal("a container granted the host TPM by the host default measured " +
				"identically to one that was not: the default is applied outside " +
				"the measurement")
		}
	})
}

func TestComputeOrchestrator_StateAndErrorMapping(t *testing.T) {
	t.Run("engine state mapping", func(t *testing.T) {
		cases := map[ContainerState]compute.InstanceState{
			StateCreated:    compute.StateStopped,
			StateRunning:    compute.StateRunning,
			StatePaused:     compute.StateRunning,
			StateRestarting: compute.StateStarting,
			StateStopped:    compute.StateStopped,
			StateExited:     compute.StateStopped,
			StateRemoving:   compute.StateDeleting,
			StateDead:       compute.StateError,
			"bogus":         compute.StateUnknown,
		}
		for engineState, expected := range cases {
			if got := mapEngineState(engineState); got != expected {
				t.Errorf("mapEngineState(%s) = %s, want %s", engineState, got, expected)
			}
		}
	})

	t.Run("engine error mapping", func(t *testing.T) {
		cases := []struct {
			engineErr error
			expected  error
		}{
			{ErrContainerNotFound, compute.ErrInstanceNotFound},
			{ErrContainerExists, compute.ErrInstanceAlreadyExists},
			{ErrContainerRunning, compute.ErrInstanceAlreadyRunning},
			{ErrContainerStopped, compute.ErrInstanceNotRunning},
			{ErrOrchestratorClosed, compute.ErrOrchestratorNotInitialized},
		}
		for _, tc := range cases {
			wrapped := NewContainerError("id", "name", "op", tc.engineErr)
			if got := mapEngineError("test", wrapped); !errors.Is(got, tc.expected) {
				t.Errorf("mapEngineError(%v) = %v, want %v", tc.engineErr, got, tc.expected)
			}
		}

		// Unrecognized errors are wrapped.
		unknown := errors.New("boom")
		if got := mapEngineError("test", unknown); !errors.Is(got, unknown) {
			t.Errorf("expected wrapped error to preserve cause, got %v", got)
		}
	})
}

func TestComputeOrchestrator_Close(t *testing.T) {
	ctx := context.Background()

	t.Run("close is idempotent", func(t *testing.T) {
		orchestrator, _ := newTestComputeOrchestrator(t, newTestComputeConfig(), false)
		if err := orchestrator.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}
		if err := orchestrator.Close(); err != nil {
			t.Fatalf("second close failed: %v", err)
		}
	})

	t.Run("close stops running instances", func(t *testing.T) {
		orchestrator, backend := newTestComputeOrchestrator(t, newTestComputeConfig(), false)

		instance, _ := orchestrator.Create(ctx, testProfile())
		if err := orchestrator.Start(ctx, instance.ID); err != nil {
			t.Fatalf("start failed: %v", err)
		}

		if err := orchestrator.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		backend.mu.Lock()
		stopCalls := backend.stopCalled
		backend.mu.Unlock()
		if stopCalls == 0 {
			t.Fatal("expected running instance to be stopped during close")
		}
	})
}
