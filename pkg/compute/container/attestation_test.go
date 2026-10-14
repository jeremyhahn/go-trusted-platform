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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
)

func TestNewContainerAttestor(t *testing.T) {
	t.Run("Success with defaults", func(t *testing.T) {
		attestor, tpm := newTestAttestor(t)
		if attestor.GetPCRIndex() != DefaultPCRIndex {
			t.Errorf("Default PCR index = %d, want %d", attestor.GetPCRIndex(), DefaultPCRIndex)
		}
		if attestor.MeasurementBank() != orchestration.DefaultMeasurementBank {
			t.Errorf("Default bank = %q, want %q",
				attestor.MeasurementBank(), orchestration.DefaultMeasurementBank)
		}
		if attestor.GetMeasurementLog() == nil {
			t.Error("GetMeasurementLog() returned nil")
		}
		if attestor.verifier == nil {
			t.Error("a host TPM implementing QuoteVerifier must be adopted automatically")
		}
		_ = tpm
	})

	t.Run("Success with custom PCR index", func(t *testing.T) {
		attestor, _ := newTestAttestor(t, WithPCRIndex(10))
		if attestor.GetPCRIndex() != 10 {
			t.Errorf("Custom PCR index = %d, want 10", attestor.GetPCRIndex())
		}
	})

	t.Run("Success with existing measurement log", func(t *testing.T) {
		existingLog := NewThreadSafeMeasurementLog()
		entry := NewMeasurementEntry("existing", "name", EventContainerCreate, "", "", "")
		if err := existingLog.AppendEntry(entry); err != nil {
			t.Fatalf("AppendEntry() error = %v", err)
		}

		attestor, _ := newTestAttestor(t, WithThreadSafeMeasurementLog(existingLog))
		if attestor.GetMeasurementLog().Len() != 1 {
			t.Error("Existing log not preserved")
		}
	})

	t.Run("Nil host TPM", func(t *testing.T) {
		if _, err := NewContainerAttestor(nil); err == nil {
			t.Error("NewContainerAttestor(nil) should return error")
		}
	})

	t.Run("Invalid PCR index negative", func(t *testing.T) {
		if _, err := NewContainerAttestor(newMockHostTPM(), WithPCRIndex(-1)); err == nil {
			t.Error("NewContainerAttestor with PCR -1 should return error")
		}
	})

	t.Run("Invalid PCR index too high", func(t *testing.T) {
		if _, err := NewContainerAttestor(newMockHostTPM(), WithPCRIndex(24)); err == nil {
			t.Error("NewContainerAttestor with PCR 24 should return error")
		}
	})
}

// TestContainerAttestor_DeletedPrimitivesAreGone is the de-duplication
// regression test. The platform used to carry its own image digest, config
// digest, PCR extension and quote primitives; every one of them now comes
// from the go-quicbaas SDK. This test fails to compile if any of them is
// reintroduced as a method on the attestor, and asserts the SDK replacements
// are the ones actually in use.
func TestContainerAttestor_DeletedPrimitivesAreGone(t *testing.T) {
	attestorType := any((*ContainerAttestor)(nil))

	t.Run("no digest or TPM primitives on the attestor", func(t *testing.T) {
		// ComputeImageDigest was a hash of the image REFERENCE; the SDK
		// resolves the real content digest instead.
		if _, ok := attestorType.(interface {
			ComputeImageDigest(string) ([]byte, error)
		}); ok {
			t.Error("ComputeImageDigest must be deleted in favour of ExecContainerRuntime.ResolveImageDigest")
		}
		if _, ok := attestorType.(interface {
			ComputeConfigDigest(any) ([]byte, error)
		}); ok {
			t.Error("ComputeConfigDigest must be deleted in favour of orchestration.ContainerConfigDigest")
		}
		if _, ok := attestorType.(interface {
			ExtendPCR(context.Context, int, []byte) error
		}); ok {
			t.Error("ExtendPCR must be deleted in favour of orchestration.HostTPM")
		}
		if _, ok := attestorType.(interface {
			GenerateQuote(context.Context, []int) (any, error)
		}); ok {
			t.Error("GenerateQuote must be deleted in favour of the SDK attesting runtime")
		}
	})

	t.Run("SDK config digest excludes the container name", func(t *testing.T) {
		// The platform's old digest hashed the whole spec including Name.
		// The SDK deliberately excludes it as a per-instance identifier.
		a := &orchestration.ContainerSpec{Name: "alpha", Image: testImageRef, ImageDigest: testImageDigest}
		b := &orchestration.ContainerSpec{Name: "beta", Image: testImageRef, ImageDigest: testImageDigest}

		digestA, err := orchestration.ContainerConfigDigest(a)
		if err != nil {
			t.Fatalf("ContainerConfigDigest(a): %v", err)
		}
		digestB, err := orchestration.ContainerConfigDigest(b)
		if err != nil {
			t.Fatalf("ContainerConfigDigest(b): %v", err)
		}
		if digestA != digestB {
			t.Errorf("differently named identical configs must measure identically: %s != %s",
				digestA, digestB)
		}
		if err := orchestration.ValidateImageDigest(digestA); err != nil {
			t.Errorf("config digest %q is not a canonical digest: %v", digestA, err)
		}
	})

	t.Run("attestor drives the SDK host TPM seam", func(t *testing.T) {
		attestor, tpm := newTestAttestor(t)
		if err := attestor.RecordContainerCreate(context.Background(),
			"c1", "name", testImageRef, testImageDigest, digestOf("config")); err != nil {
			t.Fatalf("RecordContainerCreate: %v", err)
		}

		calls := tpm.getExtendCalls()
		if len(calls) != 1 {
			t.Fatalf("extend calls = %d, want 1", len(calls))
		}
		if calls[0].bank != orchestration.DefaultMeasurementBank {
			t.Errorf("extend bank = %q, want %q", calls[0].bank, orchestration.DefaultMeasurementBank)
		}
		if calls[0].pcrIndex != DefaultPCRIndex {
			t.Errorf("extend PCR = %d, want %d", calls[0].pcrIndex, DefaultPCRIndex)
		}
	})
}

func TestContainerAttestor_ComputeContainerEntryHash(t *testing.T) {
	attestor, _ := newTestAttestor(t)

	imageDigest := digestOf("image")
	configDigest := digestOf("config")

	t.Run("Valid inputs", func(t *testing.T) {
		hash, err := attestor.ComputeContainerEntryHash("container-1", imageDigest, configDigest)
		if err != nil {
			t.Fatalf("ComputeContainerEntryHash() error = %v", err)
		}
		if len(hash) != SHA256Size {
			t.Errorf("hash length = %d, want %d", len(hash), SHA256Size)
		}

		expected := ComputeEntryHash("container-1", imageDigest, configDigest, EventContainerCreate)
		if !bytes.Equal(hash, expected) {
			t.Error("hash does not match ComputeEntryHash")
		}
	})

	t.Run("Empty container ID", func(t *testing.T) {
		if _, err := attestor.ComputeContainerEntryHash("", imageDigest, configDigest); err == nil {
			t.Error("empty container ID should return error")
		}
	})

	t.Run("Closed attestor", func(t *testing.T) {
		closed, _ := newTestAttestor(t)
		if err := closed.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		if _, err := closed.ComputeContainerEntryHash("c", imageDigest, configDigest); !errors.Is(err, ErrOrchestratorClosed) {
			t.Errorf("error = %v, want ErrOrchestratorClosed", err)
		}
	})
}

func TestContainerAttestor_RecordContainerCreate(t *testing.T) {
	ctx := context.Background()
	imageDigest := digestOf("image")
	configDigest := digestOf("config")

	t.Run("Records entry and extends PCR", func(t *testing.T) {
		attestor, tpm := newTestAttestor(t)

		if err := attestor.RecordContainerCreate(ctx, "c1", "name", testImageRef, imageDigest, configDigest); err != nil {
			t.Fatalf("RecordContainerCreate() error = %v", err)
		}

		entry, err := attestor.GetMeasurementLog().FindEntry("c1")
		if err != nil {
			t.Fatalf("FindEntry() error = %v", err)
		}
		if entry.ImageDigest != imageDigest {
			t.Errorf("ImageDigest = %q, want %q", entry.ImageDigest, imageDigest)
		}
		if entry.ConfigDigest != configDigest {
			t.Errorf("ConfigDigest = %q, want %q", entry.ConfigDigest, configDigest)
		}
		if entry.Image != testImageRef {
			t.Errorf("Image = %q, want %q", entry.Image, testImageRef)
		}
		if len(tpm.getExtendCalls()) != 1 {
			t.Errorf("extend calls = %d, want 1", len(tpm.getExtendCalls()))
		}
	})

	t.Run("Rejects a create with no image digest", func(t *testing.T) {
		attestor, tpm := newTestAttestor(t)

		err := attestor.RecordContainerCreate(ctx, "c1", "name", testImageRef, "", configDigest)
		if err == nil {
			t.Fatal("a create event with no image digest must be rejected")
		}
		var unmeasured *UnmeasuredLaunchError
		if !errors.As(err, &unmeasured) {
			t.Errorf("error = %T, want *UnmeasuredLaunchError", err)
		}
		if len(tpm.getExtendCalls()) != 0 {
			t.Error("no PCR must be extended for a rejected measurement")
		}
	})

	t.Run("Rejects a non-canonical digest", func(t *testing.T) {
		attestor, _ := newTestAttestor(t)
		err := attestor.RecordContainerCreate(ctx, "c1", "name", testImageRef, "deadbeef", configDigest)
		if err == nil {
			t.Fatal("a non-canonical image digest must be rejected")
		}
		if !errors.Is(err, ErrMeasurementLogInvalid) {
			t.Errorf("error = %v, want ErrMeasurementLogInvalid", err)
		}
	})

	t.Run("TPM extend failure is fatal", func(t *testing.T) {
		attestor, tpm := newTestAttestor(t)
		tpm.extendErr = errors.New("tpm offline")

		err := attestor.RecordContainerCreate(ctx, "c1", "name", testImageRef, imageDigest, configDigest)
		if err == nil {
			t.Fatal("a failed PCR extension must fail the measurement")
		}
		if attestor.GetMeasurementLog().Len() != 0 {
			t.Error("no entry may be appended when the PCR was not extended")
		}
	})

	t.Run("Closed attestor", func(t *testing.T) {
		attestor, _ := newTestAttestor(t)
		if err := attestor.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		if err := attestor.RecordContainerCreate(ctx, "c1", "n", testImageRef, imageDigest, configDigest); !errors.Is(err, ErrOrchestratorClosed) {
			t.Errorf("error = %v, want ErrOrchestratorClosed", err)
		}
	})
}

func TestContainerAttestor_RecordLifecycleEvents(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name   string
		record func(*ContainerAttestor) error
		event  MeasurementEventType
	}{
		{
			name:   "start",
			record: func(a *ContainerAttestor) error { return a.RecordContainerStart(ctx, "c1", "name") },
			event:  EventContainerStart,
		},
		{
			name:   "stop",
			record: func(a *ContainerAttestor) error { return a.RecordContainerStop(ctx, "c1", "name") },
			event:  EventContainerStop,
		},
		{
			name:   "remove",
			record: func(a *ContainerAttestor) error { return a.RecordContainerRemove(ctx, "c1", "name") },
			event:  EventContainerRemove,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attestor, tpm := newTestAttestor(t)
			if err := tc.record(attestor); err != nil {
				t.Fatalf("record %s: %v", tc.name, err)
			}
			entry, err := attestor.GetMeasurementLog().FindEntry("c1")
			if err != nil {
				t.Fatalf("FindEntry() error = %v", err)
			}
			if entry.EventType != tc.event {
				t.Errorf("EventType = %v, want %v", entry.EventType, tc.event)
			}
			if entry.ImageDigest != "" {
				t.Error("lifecycle events must not re-assert an image digest")
			}
			if len(tpm.getExtendCalls()) != 1 {
				t.Errorf("extend calls = %d, want 1", len(tpm.getExtendCalls()))
			}
		})

		t.Run(tc.name+" empty container ID", func(t *testing.T) {
			attestor, _ := newTestAttestor(t)
			var err error
			switch tc.event {
			case EventContainerStart:
				err = attestor.RecordContainerStart(ctx, "", "n")
			case EventContainerStop:
				err = attestor.RecordContainerStop(ctx, "", "n")
			default:
				err = attestor.RecordContainerRemove(ctx, "", "n")
			}
			if !errors.Is(err, ErrInvalidContainerID) {
				t.Errorf("error = %v, want ErrInvalidContainerID", err)
			}
		})
	}
}

func TestContainerAttestor_Attest(t *testing.T) {
	ctx := context.Background()
	imageDigest := digestOf("image")
	configDigest := digestOf("config")

	t.Run("Produces SDK evidence bound to the replayed log", func(t *testing.T) {
		attestor, tpm := newTestAttestor(t)
		if err := attestor.RecordContainerCreate(ctx, "c1", "name", testImageRef, imageDigest, configDigest); err != nil {
			t.Fatalf("RecordContainerCreate: %v", err)
		}

		evidence, err := attestor.Attest(ctx, "c1", attestor.GetMeasurementLog())
		if err != nil {
			t.Fatalf("Attest() error = %v", err)
		}
		if evidence.ImageDigest != imageDigest {
			t.Errorf("evidence ImageDigest = %q, want %q", evidence.ImageDigest, imageDigest)
		}
		if len(evidence.Nonce) == 0 {
			t.Error("evidence must carry the qualifying-data nonce")
		}
		if tpm.quoteCalls != 1 {
			t.Errorf("quote calls = %d, want 1", tpm.quoteCalls)
		}

		quoted := evidence.PCRs[uint32(DefaultPCRIndex)]
		if !bytes.Equal(quoted, attestor.GetMeasurementLog().ComputeExpectedPCR()) {
			t.Error("quoted PCR must equal the replayed golden value")
		}
	})

	t.Run("PCR drift is rejected by the SDK comparison", func(t *testing.T) {
		attestor, tpm := newTestAttestor(t)
		if err := attestor.RecordContainerCreate(ctx, "c1", "name", testImageRef, imageDigest, configDigest); err != nil {
			t.Fatalf("RecordContainerCreate: %v", err)
		}

		// Extend the workload PCR behind the log's back: the host is no
		// longer in the state the log describes.
		if err := tpm.ExtendPCR(DefaultPCRIndex, orchestration.DefaultMeasurementBank, []byte("rogue")); err != nil {
			t.Fatalf("ExtendPCR: %v", err)
		}

		_, err := attestor.Attest(ctx, "c1", attestor.GetMeasurementLog())
		if err == nil {
			t.Fatal("a PCR that disagrees with the log replay must fail attestation")
		}
		var mismatch *orchestration.PCRMismatchError
		if !errors.As(err, &mismatch) {
			t.Errorf("error = %T (%v), want *orchestration.PCRMismatchError", err, err)
		}
		if !errors.Is(err, orchestration.ErrPCRMismatch) {
			t.Errorf("error %v must match the SDK sentinel", err)
		}
	})

	t.Run("Unknown container", func(t *testing.T) {
		attestor, _ := newTestAttestor(t)
		if _, err := attestor.Attest(ctx, "missing", attestor.GetMeasurementLog()); !errors.Is(err, ErrContainerNotFound) {
			t.Errorf("error = %v, want ErrContainerNotFound", err)
		}
	})

	t.Run("Container with no image identity", func(t *testing.T) {
		attestor, _ := newTestAttestor(t)
		// Only a start event: no digest was ever recorded, so the
		// container cannot be pinned and must not be attested.
		if err := attestor.RecordContainerStart(ctx, "c1", "name"); err != nil {
			t.Fatalf("RecordContainerStart: %v", err)
		}
		if _, err := attestor.Attest(ctx, "c1", attestor.GetMeasurementLog()); !errors.Is(err, ErrContainerNotFound) {
			t.Errorf("error = %v, want ErrContainerNotFound", err)
		}
	})

	t.Run("No attesting runtime fails closed", func(t *testing.T) {
		tpm := newMockHostTPM()
		attestor, err := NewContainerAttestor(tpm)
		if err != nil {
			t.Fatalf("NewContainerAttestor: %v", err)
		}
		if err := attestor.RecordContainerCreate(ctx, "c1", "n", testImageRef, imageDigest, configDigest); err != nil {
			t.Fatalf("RecordContainerCreate: %v", err)
		}

		_, err = attestor.Attest(ctx, "c1", attestor.GetMeasurementLog())
		var unavailable *AttestationRuntimeUnavailableError
		if !errors.As(err, &unavailable) {
			t.Fatalf("error = %T (%v), want *AttestationRuntimeUnavailableError", err, err)
		}
	})

	t.Run("Nil log", func(t *testing.T) {
		attestor, _ := newTestAttestor(t)
		if _, err := attestor.Attest(ctx, "c1", nil); !errors.Is(err, ErrMeasurementLogInvalid) {
			t.Errorf("error = %v, want ErrMeasurementLogInvalid", err)
		}
	})
}

func TestContainerAttestor_VerifyAttestation(t *testing.T) {
	ctx := context.Background()
	imageDigest := digestOf("image")
	configDigest := digestOf("config")

	record := func(t *testing.T, a *ContainerAttestor) {
		t.Helper()
		if err := a.RecordContainerCreate(ctx, "c1", "name", testImageRef, imageDigest, configDigest); err != nil {
			t.Fatalf("RecordContainerCreate: %v", err)
		}
	}

	t.Run("Successful verification", func(t *testing.T) {
		attestor, tpm := newTestAttestor(t)
		record(t, attestor)

		result, err := attestor.VerifyAttestation(ctx, "c1", attestor.GetMeasurementLog())
		if err != nil {
			t.Fatalf("VerifyAttestation() error = %v", err)
		}
		if !result.Verified {
			t.Errorf("verification failed: %s", result.Error)
		}
		if result.ContainerName != "name" {
			t.Errorf("ContainerName = %q, want name", result.ContainerName)
		}
		if result.ImageDigest != imageDigest {
			t.Errorf("ImageDigest = %q, want %q", result.ImageDigest, imageDigest)
		}
		if result.ConfigDigest != configDigest {
			t.Errorf("ConfigDigest = %q, want %q", result.ConfigDigest, configDigest)
		}
		if !bytes.Equal(result.PCRValue, result.ExpectedPCRValue) {
			t.Error("PCRValue must equal the replayed ExpectedPCRValue on success")
		}
		if result.Evidence == nil {
			t.Fatal("result must carry the SDK evidence")
		}
		if tpm.verifyCalls != 1 {
			t.Errorf("quote signature verifications = %d, want 1", tpm.verifyCalls)
		}
	})

	t.Run("Quote signature failure", func(t *testing.T) {
		attestor, tpm := newTestAttestor(t)
		record(t, attestor)
		tpm.verifyErr = errors.New("bad signature")

		result, err := attestor.VerifyAttestation(ctx, "c1", attestor.GetMeasurementLog())
		if !errors.Is(err, ErrQuoteVerificationFailed) {
			t.Fatalf("error = %v, want ErrQuoteVerificationFailed", err)
		}
		if result.Verified {
			t.Error("Verified must be false when the quote signature does not verify")
		}
	})

	t.Run("No quote verifier fails closed", func(t *testing.T) {
		// A host TPM that cannot verify signatures cannot support fleet
		// attestation, and must not silently report success.
		attesting, err := orchestration.NewTPMAttestingRuntime(
			&stubContainerRuntime{}, newMockHostTPM(), newSDKLogger(slog.Default()))
		if err != nil {
			t.Fatalf("NewTPMAttestingRuntime: %v", err)
		}
		attestor, err := NewContainerAttestor(
			&verifierlessHostTPM{inner: newMockHostTPM()},
			WithAttestingRuntime(attesting))
		if err != nil {
			t.Fatalf("NewContainerAttestor: %v", err)
		}

		result, err := attestor.VerifyAttestation(ctx, "c1", attestor.GetMeasurementLog())
		var unavailable *QuoteVerifierUnavailableError
		if !errors.As(err, &unavailable) {
			t.Fatalf("error = %T (%v), want *QuoteVerifierUnavailableError", err, err)
		}
		if result.Verified {
			t.Error("Verified must be false without a quote verifier")
		}
	})

	t.Run("Empty container ID", func(t *testing.T) {
		attestor, _ := newTestAttestor(t)
		if _, err := attestor.VerifyAttestation(ctx, "", attestor.GetMeasurementLog()); !errors.Is(err, ErrInvalidContainerID) {
			t.Errorf("error = %v, want ErrInvalidContainerID", err)
		}
	})

	t.Run("Nil log", func(t *testing.T) {
		attestor, _ := newTestAttestor(t)
		if _, err := attestor.VerifyAttestation(ctx, "c1", nil); !errors.Is(err, ErrMeasurementLogInvalid) {
			t.Errorf("error = %v, want ErrMeasurementLogInvalid", err)
		}
	})

	t.Run("Closed attestor", func(t *testing.T) {
		attestor, _ := newTestAttestor(t)
		if err := attestor.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		if _, err := attestor.VerifyAttestation(ctx, "c1", attestor.GetMeasurementLog()); !errors.Is(err, ErrOrchestratorClosed) {
			t.Errorf("error = %v, want ErrOrchestratorClosed", err)
		}
	})
}

// verifierlessHostTPM fills only the SDK HostTPM seam. It deliberately does
// NOT embed the mock, so it cannot promote VerifyQuote and therefore cannot
// satisfy QuoteVerifier.
type verifierlessHostTPM struct {
	inner *mockHostTPM
}

var _ orchestration.HostTPM = (*verifierlessHostTPM)(nil)

func (v *verifierlessHostTPM) ExtendPCR(pcrIndex int, hashAlg string, data []byte) error {
	return v.inner.ExtendPCR(pcrIndex, hashAlg, data)
}

func (v *verifierlessHostTPM) ReadPCRs(pcrList []uint) ([]orchestration.PCRBank, error) {
	return v.inner.ReadPCRs(pcrList)
}

func (v *verifierlessHostTPM) Quote(pcrs []uint, nonce []byte) (orchestration.TPMQuote, error) {
	return v.inner.Quote(pcrs, nonce)
}

func TestContainerAttestor_FullLifecycle(t *testing.T) {
	attestor, tpm := newTestAttestor(t)
	ctx := context.Background()

	containerID := "lifecycle-test"
	containerName := "lifecycle-test-name"
	imageDigest := digestOf("myimage:latest")
	configDigest := digestOf(`{"env": ["FOO=bar"]}`)

	if err := attestor.RecordContainerCreate(ctx, containerID, containerName, testImageRef, imageDigest, configDigest); err != nil {
		t.Fatalf("RecordContainerCreate() error = %v", err)
	}
	if err := attestor.RecordContainerStart(ctx, containerID, containerName); err != nil {
		t.Fatalf("RecordContainerStart() error = %v", err)
	}

	log := attestor.GetMeasurementLog()

	// The log replay must track the TPM exactly.
	if !bytes.Equal(log.ComputeExpectedPCR(), tpm.pcrValue(DefaultPCRIndex)) {
		t.Fatal("computed PCR does not match the TPM PCR")
	}

	result, err := attestor.VerifyAttestation(ctx, containerID, log)
	if err != nil {
		t.Fatalf("VerifyAttestation() error = %v", err)
	}
	if !result.Verified {
		t.Errorf("verification failed: %s", result.Error)
	}

	if err := attestor.RecordContainerStop(ctx, containerID, containerName); err != nil {
		t.Fatalf("RecordContainerStop() error = %v", err)
	}
	if err := attestor.RecordContainerRemove(ctx, containerID, containerName); err != nil {
		t.Fatalf("RecordContainerRemove() error = %v", err)
	}

	if log.Len() != 4 {
		t.Errorf("log length = %d, want 4", log.Len())
	}

	entries, err := log.FindEntriesByContainer(containerID)
	if err != nil {
		t.Fatalf("FindEntriesByContainer() error = %v", err)
	}
	expectedEvents := []MeasurementEventType{
		EventContainerCreate,
		EventContainerStart,
		EventContainerStop,
		EventContainerRemove,
	}
	if len(entries) != len(expectedEvents) {
		t.Fatalf("container entries = %d, want %d", len(entries), len(expectedEvents))
	}
	for i, expected := range expectedEvents {
		if entries[i].EventType != expected {
			t.Errorf("entry %d EventType = %v, want %v", i, entries[i].EventType, expected)
		}
	}

	// FindImageIdentity must still resolve to the create event even after
	// three later digest-free events.
	identity, err := log.FindImageIdentity(containerID)
	if err != nil {
		t.Fatalf("FindImageIdentity() error = %v", err)
	}
	if identity.EventType != EventContainerCreate {
		t.Errorf("identity event = %v, want %v", identity.EventType, EventContainerCreate)
	}
}

func TestContainerAttestor_Close(t *testing.T) {
	attestor, _ := newTestAttestor(t)
	ctx := context.Background()

	if err := attestor.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if _, err := attestor.ComputeContainerEntryHash("c", digestOf("i"), digestOf("c")); !errors.Is(err, ErrOrchestratorClosed) {
		t.Errorf("ComputeContainerEntryHash after Close: %v, want ErrOrchestratorClosed", err)
	}
	if err := attestor.RecordContainerCreate(ctx, "c", "n", testImageRef, digestOf("i"), digestOf("c")); !errors.Is(err, ErrOrchestratorClosed) {
		t.Errorf("RecordContainerCreate after Close: %v, want ErrOrchestratorClosed", err)
	}
	if _, err := attestor.Attest(ctx, "c", attestor.GetMeasurementLog()); !errors.Is(err, ErrOrchestratorClosed) {
		t.Errorf("Attest after Close: %v, want ErrOrchestratorClosed", err)
	}
}

func TestAttestationVerificationResult_Fields(t *testing.T) {
	result := &AttestationVerificationResult{
		ContainerID:      "test-container",
		ContainerName:    "test-name",
		Verified:         true,
		ImageDigest:      testImageDigest,
		ConfigDigest:     digestOf("config"),
		PCRValue:         make([]byte, SHA256Size),
		ExpectedPCRValue: make([]byte, SHA256Size),
		Timestamp:        time.Now(),
	}

	if result.ContainerID != "test-container" {
		t.Errorf("ContainerID = %s, want test-container", result.ContainerID)
	}
	if !result.Verified {
		t.Error("Verified should be true")
	}
	if result.Error != "" {
		t.Errorf("Error should be empty, got: %s", result.Error)
	}
	if err := orchestration.ValidateImageDigest(result.ImageDigest); err != nil {
		t.Errorf("ImageDigest must be canonical: %v", err)
	}
}

// TestAttestationTypedErrors covers the message and unwrap behaviour of the
// fail-closed error types, which are the contract downstream callers match on.
func TestAttestationTypedErrors(t *testing.T) {
	t.Run("AttestationRuntimeUnavailableError", func(t *testing.T) {
		err := &AttestationRuntimeUnavailableError{ContainerID: "c1"}
		if !strings.Contains(err.Error(), "c1") {
			t.Errorf("message %q must name the container", err.Error())
		}
		if !errors.Is(err, ErrAttestationFailed) {
			t.Error("must unwrap to ErrAttestationFailed")
		}
		bare := &AttestationRuntimeUnavailableError{}
		if strings.Contains(bare.Error(), "()") {
			t.Errorf("message %q must omit an empty container", bare.Error())
		}
	})

	t.Run("QuoteVerifierUnavailableError", func(t *testing.T) {
		err := &QuoteVerifierUnavailableError{ContainerID: "c1"}
		if !strings.Contains(err.Error(), "c1") {
			t.Errorf("message %q must name the container", err.Error())
		}
		if !errors.Is(err, ErrQuoteVerificationFailed) {
			t.Error("must unwrap to ErrQuoteVerificationFailed")
		}
		if strings.Contains((&QuoteVerifierUnavailableError{}).Error(), "()") {
			t.Error("message must omit an empty container")
		}
	})

	t.Run("UnmeasuredLaunchError", func(t *testing.T) {
		cause := errors.New("no repository digest")
		err := &UnmeasuredLaunchError{ContainerName: "web", Stage: "resolve_image_digest", Cause: cause}
		if !strings.Contains(err.Error(), "resolve_image_digest") {
			t.Errorf("message %q must name the failing stage", err.Error())
		}
		if !errors.Is(err, cause) {
			t.Error("must unwrap to the cause")
		}
		if !errors.Is(err, ErrAttestationFailed) {
			t.Error("must unwrap to ErrAttestationFailed")
		}
		if !errors.Is(&UnmeasuredLaunchError{Stage: "record_create"}, ErrAttestationFailed) {
			t.Error("a causeless error must still unwrap to the sentinel")
		}
	})

	t.Run("MeasurementDigestError", func(t *testing.T) {
		entry := &MeasurementEntry{
			ContainerID:    "c1",
			EventType:      EventContainerCreate,
			ImageDigest:    "not-a-digest",
			CumulativeHash: make([]byte, SHA256Size),
		}
		err := entry.Validate()
		var digestErr *MeasurementDigestError
		if !errors.As(err, &digestErr) {
			t.Fatalf("error = %T (%v), want *MeasurementDigestError", err, err)
		}
		if digestErr.Field != "image_digest" {
			t.Errorf("Field = %q, want image_digest", digestErr.Field)
		}
		if !strings.Contains(err.Error(), "not-a-digest") {
			t.Errorf("message %q must quote the rejected value", err.Error())
		}
	})
}

// TestContainerAttestorOptions covers the option setters that production
// wiring uses but the default construction path does not.
func TestContainerAttestorOptions(t *testing.T) {
	t.Run("WithMeasurementBank", func(t *testing.T) {
		attestor, _ := newTestAttestor(t, WithMeasurementBank("sha384"))
		if attestor.MeasurementBank() != "sha384" {
			t.Errorf("bank = %q, want sha384", attestor.MeasurementBank())
		}

		if err := attestor.RecordContainerStart(context.Background(), "c1", "n"); err != nil {
			t.Fatalf("RecordContainerStart: %v", err)
		}
	})

	t.Run("empty bank falls back to the SDK default", func(t *testing.T) {
		attestor, _ := newTestAttestor(t, WithMeasurementBank(""))
		if attestor.MeasurementBank() != orchestration.DefaultMeasurementBank {
			t.Errorf("bank = %q, want %q",
				attestor.MeasurementBank(), orchestration.DefaultMeasurementBank)
		}
	})

	t.Run("WithQuoteVerifier overrides the TPM's own", func(t *testing.T) {
		explicit := newMockHostTPM()
		attestor, tpm := newTestAttestor(t, WithQuoteVerifier(explicit))
		if attestor.verifier != QuoteVerifier(explicit) {
			t.Error("the explicit verifier must win over the TPM's")
		}
		if tpm.verifyCalls != 0 {
			t.Error("the TPM's own verifier must not be used")
		}
	})
}

// TestContainerAttestor_Attest_QuoteBinding proves the platform is protected
// by the SDK's binding of the unsigned TPM2_PCR_Read to the signed quote body,
// not merely that a well-formed quote is accepted.
//
// Each case drives the mock TPM into a state a real attacker could create — a
// tampered read path, a PCR extended in the TOCTOU window between the quote
// and the read, and a replayed quote — and requires attestation to fail. A
// mock that can only produce passing quotes cannot make that claim, which is
// how the original weakness (a golden comparison against an unsigned read)
// went unnoticed.
func TestContainerAttestor_Attest_QuoteBinding(t *testing.T) {
	ctx := context.Background()
	imageDigest := digestOf("image")
	configDigest := digestOf("config")

	// recordContainer registers a container so Attest has a measurement-log
	// entry, and therefore a golden PCR value, to attest against.
	recordContainer := func(t *testing.T, attestor *ContainerAttestor) {
		t.Helper()
		if err := attestor.RecordContainerCreate(
			ctx, "c1", "name", testImageRef, imageDigest, configDigest); err != nil {
			t.Fatalf("RecordContainerCreate: %v", err)
		}
	}

	t.Run("a signed digest that disagrees with the reported PCRs is refused", func(t *testing.T) {
		attestor, tpm := newTestAttestor(t)
		recordContainer(t, attestor)

		// The PCR read still reports the golden values, so the golden
		// comparison alone would pass. Only the binding catches this.
		tpm.tamperQuoteDigest = true

		_, err := attestor.Attest(ctx, "c1", attestor.GetMeasurementLog())
		if err == nil {
			t.Fatal("a quote whose pcrDigest does not cover the reported PCRs must fail attestation")
		}
		var mismatch *orchestration.QuotedPCRDigestMismatchError
		if !errors.As(err, &mismatch) {
			t.Fatalf("error = %T (%v), want *orchestration.QuotedPCRDigestMismatchError", err, err)
		}
		if len(mismatch.Signed) == 0 {
			t.Error("the mismatch must report the digest the signed quote commits to")
		}
		if mismatch.Cause == nil {
			t.Error("the mismatch must carry the evidence check that failed")
		}
		if !errors.Is(err, orchestration.ErrQuotedPCRDigestMismatch) {
			t.Errorf("error %v must match the SDK digest-mismatch sentinel", err)
		}
		if !errors.Is(err, orchestration.ErrQuoteNotBound) {
			t.Errorf("error %v must also match the unbound-quote sentinel", err)
		}
	})

	t.Run("a PCR extended between the quote and the read is refused", func(t *testing.T) {
		attestor, tpm := newTestAttestor(t)
		recordContainer(t, attestor)

		// The quote is signed over the approved state; the workload PCR is
		// then extended before the read observes it. The read reports a
		// value the signature never covered.
		tpm.extendAfterQuote = &extendCall{
			pcrIndex: DefaultPCRIndex,
			bank:     orchestration.DefaultMeasurementBank,
			data:     []byte("payload loaded after the quote"),
		}

		_, err := attestor.Attest(ctx, "c1", attestor.GetMeasurementLog())
		if err == nil {
			t.Fatal("a PCR extended in the quote-to-read window must fail attestation")
		}
		if !errors.Is(err, orchestration.ErrQuoteNotBound) {
			t.Errorf("error = %v, want the SDK unbound-quote sentinel", err)
		}
		// The read no longer reproduces the signed digest, so the failure
		// must be the binding and not the downstream golden comparison.
		if errors.Is(err, orchestration.ErrPCRMismatch) {
			t.Error("the binding must reject the read before any golden value is compared")
		}
	})

	t.Run("a quote carrying a stale nonce is refused", func(t *testing.T) {
		attestor, tpm := newTestAttestor(t)
		recordContainer(t, attestor)

		// Every PCR still matches the log replay; only the freshness proof
		// inside the signed body is wrong.
		tpm.tamperQuoteNonce = true

		_, err := attestor.Attest(ctx, "c1", attestor.GetMeasurementLog())
		if err == nil {
			t.Fatal("a quote that does not carry this attestation's nonce must fail attestation")
		}
		var binding *orchestration.QuoteBindingError
		if !errors.As(err, &binding) {
			t.Fatalf("error = %T (%v), want *orchestration.QuoteBindingError", err, err)
		}
		if !errors.Is(err, orchestration.ErrQuoteNotBound) {
			t.Errorf("error %v must match the SDK unbound-quote sentinel", err)
		}
	})

	t.Run("an untampered quote binds and attests", func(t *testing.T) {
		attestor, _ := newTestAttestor(t)
		recordContainer(t, attestor)

		// The control case: the same mock, untouched, must succeed. Without
		// it the three failures above could be passing for the wrong reason.
		if _, err := attestor.Attest(ctx, "c1", attestor.GetMeasurementLog()); err != nil {
			t.Fatalf("Attest() error = %v", err)
		}
	})
}

// TestSyntheticQuote covers the test-support encoder itself. The negative
// tests above are only meaningful if the quote bodies they build are the ones
// a TPM would emit, so the encoder's own contract is asserted here.
func TestSyntheticQuote(t *testing.T) {
	nonce := []byte("nonce")
	reported := map[int][]byte{
		1:  bytes.Repeat([]byte{0x01}, SHA256Size),
		7:  bytes.Repeat([]byte{0x07}, SHA256Size),
		23: bytes.Repeat([]byte{0x17}, SHA256Size),
	}

	t.Run("selects the reported PCRs in ascending order", func(t *testing.T) {
		quote := newSyntheticQuote(sha256BankName, reported, []uint{23, 7, 7, 1}, nonce)
		want := []uint32{1, 7, 23}
		if len(quote.indices) != len(want) {
			t.Fatalf("indices = %v, want %v", quote.indices, want)
		}
		for i, index := range want {
			if quote.indices[i] != index {
				t.Fatalf("indices = %v, want %v", quote.indices, want)
			}
			if !bytes.Equal(quote.values[i], reported[int(index)]) {
				t.Errorf("value for PCR %d does not match the reported one", index)
			}
		}
	})

	t.Run("drops PCRs the double cannot report", func(t *testing.T) {
		quote := newSyntheticQuote(sha256BankName, reported, []uint{7, 9}, nonce)
		if len(quote.indices) != 1 || quote.indices[0] != 7 {
			t.Fatalf("indices = %v, want [7]", quote.indices)
		}
	})

	t.Run("emits a TPMS_ATTEST the SDK binding accepts", func(t *testing.T) {
		body, err := newSyntheticQuote(sha256BankName, reported, []uint{1, 7}, nonce).quoted()
		if err != nil {
			t.Fatalf("quoted() error = %v", err)
		}
		if len(body) < 6 {
			t.Fatalf("quote body is %d bytes, too short for a TPMS_ATTEST header", len(body))
		}
		if magic := binary.BigEndian.Uint32(body[:4]); magic != uint32(tpm2.TPMGeneratedValue) {
			t.Errorf("magic = %#08x, want %#08x", magic, uint32(tpm2.TPMGeneratedValue))
		}
		if kind := binary.BigEndian.Uint16(body[4:6]); kind != uint16(tpm2.TPMSTAttestQuote) {
			t.Errorf("type = %#04x, want %#04x", kind, uint16(tpm2.TPMSTAttestQuote))
		}
		if !bytes.Contains(body, nonce) {
			t.Error("the signed body must carry the nonce as extraData")
		}
		// The digest must be the bank hash over the selected values in
		// selection order, which is what the SDK recomputes.
		want := sha256.Sum256(append(append([]byte(nil), reported[1]...), reported[7]...))
		if !bytes.Contains(body, want[:]) {
			t.Error("the signed body must commit to the digest over the selected PCR values")
		}
	})

	t.Run("rejects a bank no TPM exposes", func(t *testing.T) {
		_, err := newSyntheticQuote("SHA3-512", reported, []uint{7}, nonce).quoted()
		var unsupported UnsupportedPCRBankError
		if !errors.As(err, &unsupported) {
			t.Fatalf("error = %v, want UnsupportedPCRBankError", err)
		}
		if unsupported.Bank != "SHA3-512" {
			t.Errorf("Bank = %q, want %q", unsupported.Bank, "SHA3-512")
		}
	})

	t.Run("rejects a PCR index outside the selection bitmap", func(t *testing.T) {
		quote := newSyntheticQuote(sha256BankName, reported, []uint{7}, nonce)
		quote.indices = append(quote.indices, orchestration.MaxPCRIndex+1)
		_, err := quote.quoted()
		var outOfRange PCRIndexOutOfRangeError
		if !errors.As(err, &outOfRange) {
			t.Fatalf("error = %v, want PCRIndexOutOfRangeError", err)
		}
		if outOfRange.Index != orchestration.MaxPCRIndex+1 {
			t.Errorf("Index = %d, want %d", outOfRange.Index, orchestration.MaxPCRIndex+1)
		}
	})
}
