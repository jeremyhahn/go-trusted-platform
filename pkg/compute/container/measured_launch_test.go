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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
)

// newMeasuringOrchestrator builds an orchestrator with measurement required.
func newMeasuringOrchestrator(
	t *testing.T,
	resolver ImageDigestResolver,
) (*Orchestrator, *MockPodmanBackend, *MockTPMProvider) {
	t.Helper()

	tpm := NewMockTPMProvider()
	attestor, err := NewContainerAttestor(tpm, WithAttestingRuntime(newTestAttestingRuntime(t, tpm)))
	if err != nil {
		t.Fatalf("NewContainerAttestor: %v", err)
	}

	podman := NewMockPodmanBackend()
	opts := []OrchestratorOption{
		WithPodmanBackend(podman),
		WithAttestor(attestor),
	}
	if resolver != nil {
		opts = append(opts, WithImageDigestResolver(resolver))
	}

	orch, err := NewOrchestrator(OrchestratorConfig{
		Logger:            slog.Default(),
		EnableAttestation: true,
	}, opts...)
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	t.Cleanup(func() { _ = orch.Close() })

	return orch, podman, tpm
}

// TestCreate_UnmeasuredLaunchFailsClosed is the security regression test for
// the digest-resolution hole.
//
// Create used to LOG a digest-resolution failure and then skip the
// measurement entirely: the container was created and reported as a success
// while the measurement log had no entry for it and the workload PCR was
// never extended. A verifier could not tell that container apart from one
// that was never approved.
func TestCreate_UnmeasuredLaunchFailsClosed(t *testing.T) {
	ctx := context.Background()
	spec := func() *OrchestratorContainerSpec {
		return &OrchestratorContainerSpec{Name: "unmeasured", Image: "alpine:latest"}
	}

	t.Run("digest resolution failure fails the launch", func(t *testing.T) {
		resolveErr := &orchestration.ImageDigestUnresolvedError{
			Image: "alpine:latest",
			Cause: errors.New("image has no repository digest"),
		}
		orch, podman, tpm := newMeasuringOrchestrator(t, fixedDigestResolver{err: resolveErr})

		container, err := orch.Create(ctx, spec())
		if err == nil {
			t.Fatal("a container that cannot be measured must not be created successfully")
		}
		if container != nil {
			t.Fatal("no container may be returned when the measurement failed")
		}

		var unmeasured *UnmeasuredLaunchError
		if !errors.As(err, &unmeasured) {
			t.Fatalf("error = %T (%v), want *UnmeasuredLaunchError", err, err)
		}
		if unmeasured.Stage != "resolve_image_digest" {
			t.Errorf("Stage = %q, want resolve_image_digest", unmeasured.Stage)
		}
		if !errors.Is(err, orchestration.ErrImageDigestUnresolved) {
			t.Error("the underlying SDK cause must remain inspectable")
		}

		if len(tpm.getExtendCalls()) != 0 {
			t.Error("no PCR may be extended for a launch that was refused")
		}
		if orch.attestor.GetMeasurementLog().Len() != 0 {
			t.Error("no measurement entry may be recorded for a refused launch")
		}
		if count := len(podman.containers); count != 0 {
			t.Errorf("the unmeasured container must be rolled back, %d left behind", count)
		}
	})

	t.Run("no resolver configured fails the launch", func(t *testing.T) {
		orch, _, _ := newMeasuringOrchestrator(t, nil)

		_, err := orch.Create(ctx, spec())
		if !errors.Is(err, ErrImageDigestResolverUnavailable) {
			t.Fatalf("error = %v, want ErrImageDigestResolverUnavailable", err)
		}
	})

	t.Run("non-canonical digest fails the launch", func(t *testing.T) {
		orch, _, _ := newMeasuringOrchestrator(t, staticDigestResolver{digest: "sha256:short"})

		_, err := orch.Create(ctx, spec())
		var unmeasured *UnmeasuredLaunchError
		if !errors.As(err, &unmeasured) {
			t.Fatalf("error = %T (%v), want *UnmeasuredLaunchError", err, err)
		}
	})

	t.Run("PCR extension failure fails the launch", func(t *testing.T) {
		orch, podman, tpm := newMeasuringOrchestrator(t, fixedDigestResolver{})
		tpm.extendErr = errors.New("tpm busy")

		if _, err := orch.Create(ctx, spec()); err == nil {
			t.Fatal("a launch whose PCR extension failed must be refused")
		}
		if count := len(podman.containers); count != 0 {
			t.Errorf("the unmeasured container must be rolled back, %d left behind", count)
		}
	})

	t.Run("a measured launch succeeds and is recorded", func(t *testing.T) {
		orch, _, tpm := newMeasuringOrchestrator(t, fixedDigestResolver{})

		container, err := orch.Create(ctx, spec())
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		entry, err := orch.attestor.GetMeasurementLog().FindImageIdentity(container.ID)
		if err != nil {
			t.Fatalf("FindImageIdentity: %v", err)
		}
		if entry.ImageDigest != digestOf("alpine:latest") {
			t.Errorf("ImageDigest = %q, want the resolved content digest", entry.ImageDigest)
		}
		if err := orchestration.ValidateImageDigest(entry.ConfigDigest); err != nil {
			t.Errorf("ConfigDigest is not canonical: %v", err)
		}
		if len(tpm.getExtendCalls()) != 1 {
			t.Errorf("extend calls = %d, want 1", len(tpm.getExtendCalls()))
		}
	})
}

// TestStart_MeasuresBeforeLaunch asserts the start event is measured before
// the container is handed to the runtime, and that a failed measurement stops
// the launch rather than being logged.
func TestStart_MeasuresBeforeLaunch(t *testing.T) {
	ctx := context.Background()

	orch, podman, tpm := newMeasuringOrchestrator(t, fixedDigestResolver{})

	container, err := orch.Create(ctx, &OrchestratorContainerSpec{Name: "measured", Image: "alpine:latest"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	tpm.resetExtendCalls()
	tpm.extendErr = errors.New("tpm busy")

	if err := orch.Start(ctx, container.ID); err == nil {
		t.Fatal("a start whose measurement failed must not report success")
	}

	stored, ok := podman.containers[container.ID]
	if !ok {
		t.Fatal("container missing from the backend")
	}
	if stored.State == "running" {
		t.Error("the container must not have been started")
	}
}

// mockQuotePCRValue is the PCR value newMockQuoteTPM reports for the workload
// PCR, which is what a matching golden set must contain.
func mockQuotePCRValue() []byte {
	return bytes.Repeat([]byte{0xAB}, SHA256Size)
}

// staticDigestResolver returns a fixed digest for every image.
type staticDigestResolver struct {
	digest string
}

func (r staticDigestResolver) ResolveImageDigest(context.Context, string) (string, error) {
	return r.digest, nil
}

// TestTrustStackAndSDKAttestor covers the seam the platform fills in the SDK.
func TestTrustStackAndSDKAttestor(t *testing.T) {
	t.Run("rejects a nil host TPM", func(t *testing.T) {
		if _, err := NewTrustStack(nil, slog.Default()); err == nil {
			t.Fatal("a trust stack with no TPM must be refused")
		}
		if _, err := NewSDKContainerAttestor(nil, slog.Default()); err == nil {
			t.Fatal("an attestor with no TPM must be refused")
		}
	})

	// The platform's production host TPM adapter must drive the SDK service
	// seam end to end: quicbaas leaves AttestContainer unimplemented until an
	// application registers an attestor, and this is the platform's.
	t.Run("the host TPM adapter fills service.ContainerAttestor", func(t *testing.T) {
		provider, err := NewHostTPMProvider(newMockQuoteTPM(t))
		if err != nil {
			t.Fatalf("NewHostTPMProvider: %v", err)
		}

		attesting, err := orchestration.NewTPMAttestingRuntime(
			&stubContainerRuntime{}, provider, newSDKLogger(slog.Default()))
		if err != nil {
			t.Fatalf("NewTPMAttestingRuntime: %v", err)
		}

		var seam = service.NewRuntimeContainerAttestor(attesting)
		if seam == nil {
			t.Fatal("the platform must fill service.ContainerAttestor")
		}

		resp, err := seam.AttestContainer(context.Background(), &service.AttestContainerRequest{
			ContainerID: "c1",
			Image:       testImageRef,
			ImageDigest: testImageDigest,
			TrustLevel:  orchestration.TrustLevelAttested.String(),
			ExpectedPCRs: map[uint32][]byte{
				DefaultPCRIndex: mockQuotePCRValue(),
			},
			MeasurementBank: orchestration.DefaultMeasurementBank,
		})
		if err != nil {
			t.Fatalf("AttestContainer: %v", err)
		}
		if !resp.Attested {
			t.Error("expected attested evidence")
		}
		if resp.ImageDigest != testImageDigest {
			t.Errorf("ImageDigest = %q, want %q", resp.ImageDigest, testImageDigest)
		}
		if len(resp.Quoted) == 0 || len(resp.Signature) == 0 {
			t.Error("expected a signed quote in the response")
		}
	})

	t.Run("golden PCR mismatch is refused through the seam", func(t *testing.T) {
		provider, err := NewHostTPMProvider(newMockQuoteTPM(t))
		if err != nil {
			t.Fatalf("NewHostTPMProvider: %v", err)
		}
		attesting, err := orchestration.NewTPMAttestingRuntime(
			&stubContainerRuntime{}, provider, newSDKLogger(slog.Default()))
		if err != nil {
			t.Fatalf("NewTPMAttestingRuntime: %v", err)
		}
		seam := service.NewRuntimeContainerAttestor(attesting)

		_, err = seam.AttestContainer(context.Background(), &service.AttestContainerRequest{
			ContainerID:     "c1",
			Image:           testImageRef,
			ImageDigest:     testImageDigest,
			TrustLevel:      orchestration.TrustLevelAttested.String(),
			ExpectedPCRs:    map[uint32][]byte{DefaultPCRIndex: []byte("wrong")},
			MeasurementBank: orchestration.DefaultMeasurementBank,
		})
		if err == nil {
			t.Fatal("a host whose PCRs do not match the golden set must be refused")
		}
		if !errors.Is(err, orchestration.ErrPCRMismatch) {
			t.Errorf("error = %v, want the SDK PCR mismatch sentinel", err)
		}
	})
}

// TestNewAttestingRuntime covers layering the SDK attesting runtime over a
// caller's own Tier 0 runtime.
func TestNewAttestingRuntime(t *testing.T) {
	t.Run("attests over the supplied Tier 0 runtime", func(t *testing.T) {
		attesting, err := NewAttestingRuntime(&stubContainerRuntime{}, newMockHostTPM(), slog.Default())
		if err != nil {
			t.Fatalf("NewAttestingRuntime: %v", err)
		}
		if attesting == nil {
			t.Fatal("expected an attesting runtime")
		}
	})

	t.Run("rejects a nil host TPM", func(t *testing.T) {
		_, err := NewAttestingRuntime(&stubContainerRuntime{}, nil, slog.Default())
		var want ErrHostTPMRequired
		if !errors.As(err, &want) {
			t.Fatalf("error = %v, want ErrHostTPMRequired", err)
		}
	})

	t.Run("rejects a nil Tier 0 runtime", func(t *testing.T) {
		if _, err := NewAttestingRuntime(nil, newMockHostTPM(), slog.Default()); err == nil {
			t.Fatal("an attesting runtime with no Tier 0 runtime must be refused")
		}
	})
}

// TestAttestationSpec covers the reconstruction of the SDK spec from a
// measurement-log entry, which is what the golden-PCR comparison runs against.
func TestAttestationSpec(t *testing.T) {
	attestor, _ := newTestAttestor(t)
	expectedPCR := make([]byte, SHA256Size)

	t.Run("uses the recorded image reference", func(t *testing.T) {
		spec, err := attestor.attestationSpec(&MeasurementEntry{
			ContainerName: "web",
			Image:         testImageRef,
			ImageDigest:   testImageDigest,
		}, expectedPCR)
		if err != nil {
			t.Fatalf("attestationSpec: %v", err)
		}
		if spec.Image != testImageRef {
			t.Errorf("Image = %q, want %q", spec.Image, testImageRef)
		}
		if !spec.IsPinned() {
			t.Error("the reconstructed spec must be pinned")
		}
		if spec.TrustLevel != orchestration.TrustLevelAttested {
			t.Errorf("TrustLevel = %v, want attested", spec.TrustLevel)
		}
	})

	// Logs written before the image reference was recorded still carry the
	// digest, which is the identity that actually matters.
	t.Run("falls back to the digest when no reference was recorded", func(t *testing.T) {
		spec, err := attestor.attestationSpec(&MeasurementEntry{
			ImageDigest: testImageDigest,
		}, expectedPCR)
		if err != nil {
			t.Fatalf("attestationSpec: %v", err)
		}
		if spec.Image != testImageDigest {
			t.Errorf("Image = %q, want the digest as a fallback", spec.Image)
		}
	})

	t.Run("rejects an entry with no image identity", func(t *testing.T) {
		if _, err := attestor.attestationSpec(&MeasurementEntry{}, expectedPCR); err == nil {
			t.Fatal("a spec with no image must be rejected by SDK validation")
		}
	})
}

// TestRollbackUnmeasured asserts a failing rollback is reported rather than
// masking the original measurement failure.
func TestRollbackUnmeasured(t *testing.T) {
	orch, podman, _ := newMeasuringOrchestrator(t, fixedDigestResolver{err: errors.New("no digest")})
	podman.removeError = errors.New("podman refused")

	_, err := orch.Create(context.Background(), &OrchestratorContainerSpec{
		Name:  "stuck",
		Image: "alpine:latest",
	})

	// The measurement failure, not the rollback failure, is what the caller
	// must see: the launch was refused either way.
	var unmeasured *UnmeasuredLaunchError
	if !errors.As(err, &unmeasured) {
		t.Fatalf("error = %T (%v), want *UnmeasuredLaunchError", err, err)
	}
}
