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
	"errors"
	"sync"
	"testing"
	"time"
)

// mockTPMProvider implements TPMProvider for testing.
type mockTPMProvider struct {
	mu             sync.RWMutex
	pcrs           map[int][]byte
	extendCalls    []extendCall
	quoteCalls     int
	verifyCalls    int
	extendErr      error
	readErr        error
	quoteErr       error
	verifyErr      error
	verifyCallback func(*Quote) error
}

type extendCall struct {
	pcrIndex int
	hash     []byte
}

func newMockTPMProvider() *mockTPMProvider {
	m := &mockTPMProvider{
		pcrs:        make(map[int][]byte),
		extendCalls: make([]extendCall, 0),
	}
	// Initialize all PCRs to zeros
	for i := 0; i <= 23; i++ {
		m.pcrs[i] = make([]byte, SHA256Size)
	}
	return m
}

func (m *mockTPMProvider) ExtendPCR(ctx context.Context, pcrIndex int, hash []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.extendErr != nil {
		return m.extendErr
	}

	m.extendCalls = append(m.extendCalls, extendCall{pcrIndex: pcrIndex, hash: hash})

	// Simulate PCR extend: new = SHA256(old || hash)
	current := m.pcrs[pcrIndex]
	h := sha256.New()
	h.Write(current)
	h.Write(hash)
	m.pcrs[pcrIndex] = h.Sum(nil)

	return nil
}

func (m *mockTPMProvider) ReadPCR(ctx context.Context, pcrIndex int) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.readErr != nil {
		return nil, m.readErr
	}

	pcr, ok := m.pcrs[pcrIndex]
	if !ok {
		return nil, errors.New("PCR not found")
	}

	result := make([]byte, len(pcr))
	copy(result, pcr)
	return result, nil
}

func (m *mockTPMProvider) GenerateQuote(ctx context.Context, pcrIndices []int, nonce []byte) (*Quote, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.quoteCalls++

	if m.quoteErr != nil {
		return nil, m.quoteErr
	}

	quote := &Quote{
		QuoteData: []byte("mock-quote-data"),
		Signature: []byte("mock-signature"),
		PCRs:      make(map[int][]byte),
		Nonce:     nonce,
		Timestamp: time.Now(),
	}

	for _, idx := range pcrIndices {
		if pcr, ok := m.pcrs[idx]; ok {
			quote.PCRs[idx] = make([]byte, len(pcr))
			copy(quote.PCRs[idx], pcr)
		}
	}

	return quote, nil
}

func (m *mockTPMProvider) VerifyQuote(ctx context.Context, quote *Quote) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.verifyCalls++

	if m.verifyCallback != nil {
		return m.verifyCallback(quote)
	}

	return m.verifyErr
}

func (m *mockTPMProvider) getExtendCalls() []extendCall {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]extendCall, len(m.extendCalls))
	copy(result, m.extendCalls)
	return result
}

func (m *mockTPMProvider) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.extendCalls = make([]extendCall, 0)
	m.quoteCalls = 0
	m.verifyCalls = 0
	for i := 0; i <= 23; i++ {
		m.pcrs[i] = make([]byte, SHA256Size)
	}
}

func TestNewContainerAttestor(t *testing.T) {
	tpm := newMockTPMProvider()

	t.Run("Success with defaults", func(t *testing.T) {
		attestor, err := NewContainerAttestor(tpm)
		if err != nil {
			t.Fatalf("NewContainerAttestor() error = %v", err)
		}
		if attestor == nil {
			t.Fatal("NewContainerAttestor() returned nil")
		}
		if attestor.GetPCRIndex() != DefaultPCRIndex {
			t.Errorf("Default PCR index = %d, want %d", attestor.GetPCRIndex(), DefaultPCRIndex)
		}
		if attestor.GetMeasurementLog() == nil {
			t.Error("GetMeasurementLog() returned nil")
		}
	})

	t.Run("Success with custom PCR index", func(t *testing.T) {
		attestor, err := NewContainerAttestor(tpm, WithPCRIndex(10))
		if err != nil {
			t.Fatalf("NewContainerAttestor() error = %v", err)
		}
		if attestor.GetPCRIndex() != 10 {
			t.Errorf("Custom PCR index = %d, want 10", attestor.GetPCRIndex())
		}
	})

	t.Run("Success with existing measurement log", func(t *testing.T) {
		existingLog := NewThreadSafeMeasurementLog()
		entry := NewMeasurementEntry("existing", "name", EventContainerCreate, nil, nil, "")
		if err := existingLog.AppendEntry(entry); err != nil {
			t.Fatalf("AppendEntry() error = %v", err)
		}

		attestor, err := NewContainerAttestor(tpm, WithThreadSafeMeasurementLog(existingLog))
		if err != nil {
			t.Fatalf("NewContainerAttestor() error = %v", err)
		}
		if attestor.GetMeasurementLog().Len() != 1 {
			t.Error("Existing log not preserved")
		}
	})

	t.Run("Nil TPM provider", func(t *testing.T) {
		_, err := NewContainerAttestor(nil)
		if err == nil {
			t.Error("NewContainerAttestor(nil) should return error")
		}
	})

	t.Run("Invalid PCR index negative", func(t *testing.T) {
		_, err := NewContainerAttestor(tpm, WithPCRIndex(-1))
		if err == nil {
			t.Error("NewContainerAttestor with PCR -1 should return error")
		}
	})

	t.Run("Invalid PCR index too high", func(t *testing.T) {
		_, err := NewContainerAttestor(tpm, WithPCRIndex(24))
		if err == nil {
			t.Error("NewContainerAttestor with PCR 24 should return error")
		}
	})
}

func TestContainerAttestor_ComputeImageDigest(t *testing.T) {
	tpm := newMockTPMProvider()
	attestor, err := NewContainerAttestor(tpm)
	if err != nil {
		t.Fatalf("NewContainerAttestor() error = %v", err)
	}

	t.Run("Valid image reference", func(t *testing.T) {
		digest, err := attestor.ComputeImageDigest("docker.io/library/alpine:latest")
		if err != nil {
			t.Fatalf("ComputeImageDigest() error = %v", err)
		}
		if len(digest) != SHA256Size {
			t.Errorf("ComputeImageDigest() returned %d bytes, want %d", len(digest), SHA256Size)
		}
	})

	t.Run("Deterministic", func(t *testing.T) {
		digest1, _ := attestor.ComputeImageDigest("alpine:latest")
		digest2, _ := attestor.ComputeImageDigest("alpine:latest")
		if !bytes.Equal(digest1, digest2) {
			t.Error("ComputeImageDigest() not deterministic")
		}
	})

	t.Run("Different images produce different digests", func(t *testing.T) {
		digest1, _ := attestor.ComputeImageDigest("alpine:latest")
		digest2, _ := attestor.ComputeImageDigest("nginx:latest")
		if bytes.Equal(digest1, digest2) {
			t.Error("Different images should produce different digests")
		}
	})

	t.Run("Empty image reference", func(t *testing.T) {
		_, err := attestor.ComputeImageDigest("")
		if err == nil {
			t.Error("ComputeImageDigest('') should return error")
		}
	})

	t.Run("After close", func(t *testing.T) {
		closedAttestor, _ := NewContainerAttestor(tpm)
		closedAttestor.Close()
		_, err := closedAttestor.ComputeImageDigest("alpine:latest")
		if err == nil {
			t.Error("ComputeImageDigest after Close() should return error")
		}
	})
}

func TestContainerAttestor_ComputeConfigDigest(t *testing.T) {
	tpm := newMockTPMProvider()
	attestor, err := NewContainerAttestor(tpm)
	if err != nil {
		t.Fatalf("NewContainerAttestor() error = %v", err)
	}

	t.Run("Valid spec", func(t *testing.T) {
		spec := &ContainerSpec{
			Name:  "test-container",
			Image: "alpine:latest",
			Environment: map[string]string{
				"KEY": "value",
			},
		}
		digest, err := attestor.ComputeConfigDigest(spec)
		if err != nil {
			t.Fatalf("ComputeConfigDigest() error = %v", err)
		}
		if len(digest) != SHA256Size {
			t.Errorf("ComputeConfigDigest() returned %d bytes, want %d", len(digest), SHA256Size)
		}
	})

	t.Run("Deterministic", func(t *testing.T) {
		spec := &ContainerSpec{Name: "test", Image: "alpine"}
		digest1, _ := attestor.ComputeConfigDigest(spec)
		digest2, _ := attestor.ComputeConfigDigest(spec)
		if !bytes.Equal(digest1, digest2) {
			t.Error("ComputeConfigDigest() not deterministic")
		}
	})

	t.Run("Different configs produce different digests", func(t *testing.T) {
		spec1 := &ContainerSpec{Name: "test1", Image: "alpine"}
		spec2 := &ContainerSpec{Name: "test2", Image: "alpine"}
		digest1, _ := attestor.ComputeConfigDigest(spec1)
		digest2, _ := attestor.ComputeConfigDigest(spec2)
		if bytes.Equal(digest1, digest2) {
			t.Error("Different configs should produce different digests")
		}
	})

	t.Run("Nil spec", func(t *testing.T) {
		_, err := attestor.ComputeConfigDigest(nil)
		if err == nil {
			t.Error("ComputeConfigDigest(nil) should return error")
		}
	})

	t.Run("After close", func(t *testing.T) {
		closedAttestor, _ := NewContainerAttestor(tpm)
		closedAttestor.Close()
		_, err := closedAttestor.ComputeConfigDigest(&ContainerSpec{})
		if err == nil {
			t.Error("ComputeConfigDigest after Close() should return error")
		}
	})
}

func TestContainerAttestor_ComputeContainerEntryHash(t *testing.T) {
	tpm := newMockTPMProvider()
	attestor, err := NewContainerAttestor(tpm)
	if err != nil {
		t.Fatalf("NewContainerAttestor() error = %v", err)
	}

	imageDigest := sha256.Sum256([]byte("image"))
	configDigest := sha256.Sum256([]byte("config"))

	t.Run("Valid inputs", func(t *testing.T) {
		hash, err := attestor.ComputeContainerEntryHash("container-1", imageDigest[:], configDigest[:])
		if err != nil {
			t.Fatalf("ComputeContainerEntryHash() error = %v", err)
		}
		if len(hash) != SHA256Size {
			t.Errorf("ComputeContainerEntryHash() returned %d bytes, want %d", len(hash), SHA256Size)
		}
	})

	t.Run("Empty container ID", func(t *testing.T) {
		_, err := attestor.ComputeContainerEntryHash("", imageDigest[:], configDigest[:])
		if err == nil {
			t.Error("ComputeContainerEntryHash('') should return error")
		}
	})
}

func TestContainerAttestor_ExtendPCR(t *testing.T) {
	tpm := newMockTPMProvider()
	attestor, err := NewContainerAttestor(tpm)
	if err != nil {
		t.Fatalf("NewContainerAttestor() error = %v", err)
	}
	ctx := context.Background()

	hash := sha256.Sum256([]byte("test"))

	t.Run("Valid extend", func(t *testing.T) {
		tpm.reset()
		err := attestor.ExtendPCR(ctx, 14, hash[:])
		if err != nil {
			t.Fatalf("ExtendPCR() error = %v", err)
		}

		calls := tpm.getExtendCalls()
		if len(calls) != 1 {
			t.Errorf("Expected 1 extend call, got %d", len(calls))
		}
		if calls[0].pcrIndex != 14 {
			t.Errorf("ExtendPCR called with PCR %d, want 14", calls[0].pcrIndex)
		}
	})

	t.Run("Invalid PCR index negative", func(t *testing.T) {
		err := attestor.ExtendPCR(ctx, -1, hash[:])
		if err == nil {
			t.Error("ExtendPCR(-1) should return error")
		}
	})

	t.Run("Invalid PCR index too high", func(t *testing.T) {
		err := attestor.ExtendPCR(ctx, 24, hash[:])
		if err == nil {
			t.Error("ExtendPCR(24) should return error")
		}
	})

	t.Run("Invalid hash length", func(t *testing.T) {
		err := attestor.ExtendPCR(ctx, 14, []byte("short"))
		if err == nil {
			t.Error("ExtendPCR with short hash should return error")
		}
	})

	t.Run("TPM error", func(t *testing.T) {
		tpm.extendErr = errors.New("TPM error")
		defer func() { tpm.extendErr = nil }()

		err := attestor.ExtendPCR(ctx, 14, hash[:])
		if err == nil {
			t.Error("ExtendPCR should return TPM error")
		}
	})
}

func TestContainerAttestor_GenerateQuote(t *testing.T) {
	tpm := newMockTPMProvider()
	attestor, err := NewContainerAttestor(tpm)
	if err != nil {
		t.Fatalf("NewContainerAttestor() error = %v", err)
	}
	ctx := context.Background()

	t.Run("Default PCR index", func(t *testing.T) {
		tpm.reset()
		quote, err := attestor.GenerateQuote(ctx, nil)
		if err != nil {
			t.Fatalf("GenerateQuote() error = %v", err)
		}
		if quote == nil {
			t.Fatal("GenerateQuote() returned nil")
		}
		if _, ok := quote.PCRs[DefaultPCRIndex]; !ok {
			t.Errorf("Quote does not include PCR %d", DefaultPCRIndex)
		}
	})

	t.Run("Custom PCR indices", func(t *testing.T) {
		tpm.reset()
		quote, err := attestor.GenerateQuote(ctx, []int{0, 1, 14})
		if err != nil {
			t.Fatalf("GenerateQuote() error = %v", err)
		}
		for _, idx := range []int{0, 1, 14} {
			if _, ok := quote.PCRs[idx]; !ok {
				t.Errorf("Quote does not include PCR %d", idx)
			}
		}
	})

	t.Run("TPM error", func(t *testing.T) {
		tpm.quoteErr = errors.New("quote error")
		defer func() { tpm.quoteErr = nil }()

		_, err := attestor.GenerateQuote(ctx, nil)
		if err == nil {
			t.Error("GenerateQuote should return TPM error")
		}
	})

	t.Run("After close", func(t *testing.T) {
		closedAttestor, _ := NewContainerAttestor(tpm)
		closedAttestor.Close()
		_, err := closedAttestor.GenerateQuote(ctx, nil)
		if err == nil {
			t.Error("GenerateQuote after Close() should return error")
		}
	})
}

func TestContainerAttestor_VerifyAttestation(t *testing.T) {
	tpm := newMockTPMProvider()
	attestor, err := NewContainerAttestor(tpm)
	if err != nil {
		t.Fatalf("NewContainerAttestor() error = %v", err)
	}
	ctx := context.Background()

	t.Run("Successful verification", func(t *testing.T) {
		tpm.reset()

		// Create a log with some entries
		log := NewThreadSafeMeasurementLog()
		entry := NewMeasurementEntry("container-1", "name", EventContainerCreate, nil, nil, "")
		if err := log.AppendEntry(entry); err != nil {
			t.Fatalf("AppendEntry() error = %v", err)
		}

		// Extend TPM PCR to match log
		if err := tpm.ExtendPCR(ctx, DefaultPCRIndex, entry.CumulativeHash); err != nil {
			t.Fatalf("ExtendPCR() error = %v", err)
		}

		// Generate quote with matching PCR
		quote, err := tpm.GenerateQuote(ctx, []int{DefaultPCRIndex}, nil)
		if err != nil {
			t.Fatalf("GenerateQuote() error = %v", err)
		}

		// Verify
		result, err := attestor.VerifyAttestation(ctx, quote, log)
		if err != nil {
			t.Fatalf("VerifyAttestation() error = %v", err)
		}
		if !result.Verified {
			t.Errorf("VerifyAttestation() Verified = false, want true, error: %s", result.Error)
		}
	})

	t.Run("PCR mismatch", func(t *testing.T) {
		tpm.reset()

		// Create a log with an entry
		log := NewThreadSafeMeasurementLog()
		entry := NewMeasurementEntry("container-1", "name", EventContainerCreate, nil, nil, "")
		if err := log.AppendEntry(entry); err != nil {
			t.Fatalf("AppendEntry() error = %v", err)
		}

		// Generate quote WITHOUT extending PCR (mismatch)
		quote, err := tpm.GenerateQuote(ctx, []int{DefaultPCRIndex}, nil)
		if err != nil {
			t.Fatalf("GenerateQuote() error = %v", err)
		}

		// Verify should fail
		result, err := attestor.VerifyAttestation(ctx, quote, log)
		if err == nil {
			t.Error("VerifyAttestation() should return error on PCR mismatch")
		}
		if result != nil && result.Verified {
			t.Error("VerifyAttestation() Verified should be false on mismatch")
		}
	})

	t.Run("Quote verification fails", func(t *testing.T) {
		tpm.reset()
		tpm.verifyErr = errors.New("signature invalid")
		defer func() { tpm.verifyErr = nil }()

		log := NewThreadSafeMeasurementLog()
		quote := &Quote{
			PCRs: map[int][]byte{DefaultPCRIndex: make([]byte, SHA256Size)},
		}

		result, err := attestor.VerifyAttestation(ctx, quote, log)
		if err == nil {
			t.Error("VerifyAttestation() should return error on quote verification failure")
		}
		if result != nil && result.Verified {
			t.Error("VerifyAttestation() Verified should be false")
		}
	})

	t.Run("Nil quote", func(t *testing.T) {
		log := NewThreadSafeMeasurementLog()
		_, err := attestor.VerifyAttestation(ctx, nil, log)
		if err == nil {
			t.Error("VerifyAttestation(nil quote) should return error")
		}
	})

	t.Run("Nil log", func(t *testing.T) {
		quote := &Quote{PCRs: make(map[int][]byte)}
		_, err := attestor.VerifyAttestation(ctx, quote, nil)
		if err == nil {
			t.Error("VerifyAttestation(nil log) should return error")
		}
	})

	t.Run("PCR not in quote", func(t *testing.T) {
		log := NewThreadSafeMeasurementLog()
		quote := &Quote{
			PCRs: map[int][]byte{0: make([]byte, SHA256Size)}, // Wrong PCR
		}

		result, err := attestor.VerifyAttestation(ctx, quote, log)
		if err == nil {
			t.Error("VerifyAttestation() should return error when PCR missing from quote")
		}
		if result != nil && result.Verified {
			t.Error("VerifyAttestation() Verified should be false")
		}
	})
}

func TestContainerAttestor_VerifyContainerAttestation(t *testing.T) {
	tpm := newMockTPMProvider()
	attestor, err := NewContainerAttestor(tpm)
	if err != nil {
		t.Fatalf("NewContainerAttestor() error = %v", err)
	}
	ctx := context.Background()

	t.Run("Successful verification with container info", func(t *testing.T) {
		tpm.reset()

		imageDigest := sha256.Sum256([]byte("image"))
		configDigest := sha256.Sum256([]byte("config"))

		// Create log
		log := NewThreadSafeMeasurementLog()
		entry := NewMeasurementEntry("container-1", "container-name", EventContainerCreate, imageDigest[:], configDigest[:], "")
		if err := log.AppendEntry(entry); err != nil {
			t.Fatalf("AppendEntry() error = %v", err)
		}

		// Extend PCR
		if err := tpm.ExtendPCR(ctx, DefaultPCRIndex, entry.CumulativeHash); err != nil {
			t.Fatalf("ExtendPCR() error = %v", err)
		}

		// Generate quote
		quote, err := tpm.GenerateQuote(ctx, []int{DefaultPCRIndex}, nil)
		if err != nil {
			t.Fatalf("GenerateQuote() error = %v", err)
		}

		// Verify
		result, err := attestor.VerifyContainerAttestation(ctx, "container-1", quote, log)
		if err != nil {
			t.Fatalf("VerifyContainerAttestation() error = %v", err)
		}
		if !result.Verified {
			t.Error("VerifyContainerAttestation() Verified = false, want true")
		}
		if result.ContainerID != "container-1" {
			t.Errorf("Result.ContainerID = %s, want container-1", result.ContainerID)
		}
		if result.ContainerName != "container-name" {
			t.Errorf("Result.ContainerName = %s, want container-name", result.ContainerName)
		}
		if !bytes.Equal(result.ImageDigest, imageDigest[:]) {
			t.Error("Result.ImageDigest mismatch")
		}
		if !bytes.Equal(result.ConfigDigest, configDigest[:]) {
			t.Error("Result.ConfigDigest mismatch")
		}
	})

	t.Run("Container not in log", func(t *testing.T) {
		tpm.reset()

		log := NewThreadSafeMeasurementLog()
		entry := NewMeasurementEntry("other-container", "other", EventContainerCreate, nil, nil, "")
		if err := log.AppendEntry(entry); err != nil {
			t.Fatalf("AppendEntry() error = %v", err)
		}

		if err := tpm.ExtendPCR(ctx, DefaultPCRIndex, entry.CumulativeHash); err != nil {
			t.Fatalf("ExtendPCR() error = %v", err)
		}

		quote, _ := tpm.GenerateQuote(ctx, []int{DefaultPCRIndex}, nil)

		result, err := attestor.VerifyContainerAttestation(ctx, "nonexistent", quote, log)
		if err == nil {
			t.Error("VerifyContainerAttestation() should return error for unknown container")
		}
		if result != nil && result.Verified {
			t.Error("Result.Verified should be false")
		}
	})

	t.Run("Empty container ID", func(t *testing.T) {
		log := NewThreadSafeMeasurementLog()
		quote := &Quote{PCRs: make(map[int][]byte)}
		_, err := attestor.VerifyContainerAttestation(ctx, "", quote, log)
		if err == nil {
			t.Error("VerifyContainerAttestation('') should return error")
		}
	})
}

func TestContainerAttestor_RecordContainerCreate(t *testing.T) {
	tpm := newMockTPMProvider()
	attestor, err := NewContainerAttestor(tpm)
	if err != nil {
		t.Fatalf("NewContainerAttestor() error = %v", err)
	}
	ctx := context.Background()

	imageDigest := sha256.Sum256([]byte("image"))
	configDigest := sha256.Sum256([]byte("config"))

	t.Run("Success", func(t *testing.T) {
		tpm.reset()
		err := attestor.RecordContainerCreate(ctx, "container-1", "container-name", imageDigest[:], configDigest[:])
		if err != nil {
			t.Fatalf("RecordContainerCreate() error = %v", err)
		}

		// Verify PCR was extended
		calls := tpm.getExtendCalls()
		if len(calls) != 1 {
			t.Errorf("Expected 1 extend call, got %d", len(calls))
		}

		// Verify entry was added to log
		log := attestor.GetMeasurementLog()
		if log.Len() != 1 {
			t.Errorf("Log length = %d, want 1", log.Len())
		}

		entry, err := log.FindEntry("container-1")
		if err != nil {
			t.Fatalf("FindEntry() error = %v", err)
		}
		if entry.EventType != EventContainerCreate {
			t.Errorf("Entry EventType = %v, want container_create", entry.EventType)
		}
	})

	t.Run("Empty container ID", func(t *testing.T) {
		err := attestor.RecordContainerCreate(ctx, "", "name", nil, nil)
		if err == nil {
			t.Error("RecordContainerCreate('') should return error")
		}
	})

	t.Run("TPM error", func(t *testing.T) {
		tpm.reset()
		tpm.extendErr = errors.New("TPM error")
		defer func() { tpm.extendErr = nil }()

		err := attestor.RecordContainerCreate(ctx, "container-1", "name", nil, nil)
		if err == nil {
			t.Error("RecordContainerCreate should return TPM error")
		}
	})
}

func TestContainerAttestor_RecordContainerStart(t *testing.T) {
	tpm := newMockTPMProvider()
	attestor, err := NewContainerAttestor(tpm)
	if err != nil {
		t.Fatalf("NewContainerAttestor() error = %v", err)
	}
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		err := attestor.RecordContainerStart(ctx, "container-1", "container-name")
		if err != nil {
			t.Fatalf("RecordContainerStart() error = %v", err)
		}

		log := attestor.GetMeasurementLog()
		entry, err := log.FindEntry("container-1")
		if err != nil {
			t.Fatalf("FindEntry() error = %v", err)
		}
		if entry.EventType != EventContainerStart {
			t.Errorf("Entry EventType = %v, want container_start", entry.EventType)
		}
	})

	t.Run("Empty container ID", func(t *testing.T) {
		err := attestor.RecordContainerStart(ctx, "", "name")
		if err == nil {
			t.Error("RecordContainerStart('') should return error")
		}
	})
}

func TestContainerAttestor_RecordContainerStop(t *testing.T) {
	tpm := newMockTPMProvider()
	attestor, err := NewContainerAttestor(tpm)
	if err != nil {
		t.Fatalf("NewContainerAttestor() error = %v", err)
	}
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		err := attestor.RecordContainerStop(ctx, "container-1", "container-name")
		if err != nil {
			t.Fatalf("RecordContainerStop() error = %v", err)
		}

		log := attestor.GetMeasurementLog()
		entry, err := log.FindEntry("container-1")
		if err != nil {
			t.Fatalf("FindEntry() error = %v", err)
		}
		if entry.EventType != EventContainerStop {
			t.Errorf("Entry EventType = %v, want container_stop", entry.EventType)
		}
	})

	t.Run("Empty container ID", func(t *testing.T) {
		err := attestor.RecordContainerStop(ctx, "", "name")
		if err == nil {
			t.Error("RecordContainerStop('') should return error")
		}
	})
}

func TestContainerAttestor_RecordContainerRemove(t *testing.T) {
	tpm := newMockTPMProvider()
	attestor, err := NewContainerAttestor(tpm)
	if err != nil {
		t.Fatalf("NewContainerAttestor() error = %v", err)
	}
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		err := attestor.RecordContainerRemove(ctx, "container-1", "container-name")
		if err != nil {
			t.Fatalf("RecordContainerRemove() error = %v", err)
		}

		log := attestor.GetMeasurementLog()
		entry, err := log.FindEntry("container-1")
		if err != nil {
			t.Fatalf("FindEntry() error = %v", err)
		}
		if entry.EventType != EventContainerRemove {
			t.Errorf("Entry EventType = %v, want container_remove", entry.EventType)
		}
	})

	t.Run("Empty container ID", func(t *testing.T) {
		err := attestor.RecordContainerRemove(ctx, "", "name")
		if err == nil {
			t.Error("RecordContainerRemove('') should return error")
		}
	})
}

func TestContainerAttestor_FullLifecycle(t *testing.T) {
	tpm := newMockTPMProvider()
	attestor, err := NewContainerAttestor(tpm)
	if err != nil {
		t.Fatalf("NewContainerAttestor() error = %v", err)
	}
	ctx := context.Background()

	containerID := "lifecycle-test"
	containerName := "lifecycle-test-name"
	imageDigest := sha256.Sum256([]byte("myimage:latest"))
	configDigest := sha256.Sum256([]byte(`{"env": ["FOO=bar"]}`))

	// Create
	if err := attestor.RecordContainerCreate(ctx, containerID, containerName, imageDigest[:], configDigest[:]); err != nil {
		t.Fatalf("RecordContainerCreate() error = %v", err)
	}

	// Start
	if err := attestor.RecordContainerStart(ctx, containerID, containerName); err != nil {
		t.Fatalf("RecordContainerStart() error = %v", err)
	}

	// Stop
	if err := attestor.RecordContainerStop(ctx, containerID, containerName); err != nil {
		t.Fatalf("RecordContainerStop() error = %v", err)
	}

	// Remove
	if err := attestor.RecordContainerRemove(ctx, containerID, containerName); err != nil {
		t.Fatalf("RecordContainerRemove() error = %v", err)
	}

	// Verify all events recorded
	log := attestor.GetMeasurementLog()
	if log.Len() != 4 {
		t.Errorf("Log length = %d, want 4", log.Len())
	}

	entries, err := log.FindEntriesByContainer(containerID)
	if err != nil {
		t.Fatalf("FindEntriesByContainer() error = %v", err)
	}
	if len(entries) != 4 {
		t.Errorf("Container entries = %d, want 4", len(entries))
	}

	expectedEvents := []MeasurementEventType{
		EventContainerCreate,
		EventContainerStart,
		EventContainerStop,
		EventContainerRemove,
	}
	for i, expected := range expectedEvents {
		if entries[i].EventType != expected {
			t.Errorf("Entry %d EventType = %v, want %v", i, entries[i].EventType, expected)
		}
	}

	// Verify PCR computation matches TPM
	expectedPCR := log.ComputeExpectedPCR()
	actualPCR, err := tpm.ReadPCR(ctx, DefaultPCRIndex)
	if err != nil {
		t.Fatalf("ReadPCR() error = %v", err)
	}
	if !bytes.Equal(expectedPCR, actualPCR) {
		t.Error("Computed PCR does not match TPM PCR")
	}

	// Generate and verify quote
	quote, err := attestor.GenerateQuote(ctx, nil)
	if err != nil {
		t.Fatalf("GenerateQuote() error = %v", err)
	}

	result, err := attestor.VerifyContainerAttestation(ctx, containerID, quote, log)
	if err != nil {
		t.Fatalf("VerifyContainerAttestation() error = %v", err)
	}
	if !result.Verified {
		t.Errorf("Verification failed: %s", result.Error)
	}
}

func TestContainerAttestor_Close(t *testing.T) {
	tpm := newMockTPMProvider()
	attestor, err := NewContainerAttestor(tpm)
	if err != nil {
		t.Fatalf("NewContainerAttestor() error = %v", err)
	}

	// Close should succeed
	if err := attestor.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Operations should fail after close
	ctx := context.Background()
	if _, err := attestor.ComputeImageDigest("test"); err == nil {
		t.Error("ComputeImageDigest after Close() should fail")
	}
	if _, err := attestor.ComputeConfigDigest(&ContainerSpec{}); err == nil {
		t.Error("ComputeConfigDigest after Close() should fail")
	}
	if err := attestor.RecordContainerCreate(ctx, "test", "name", nil, nil); err == nil {
		t.Error("RecordContainerCreate after Close() should fail")
	}
}

func TestQuote_Fields(t *testing.T) {
	quote := &Quote{
		QuoteData: []byte("quote-data"),
		Signature: []byte("signature"),
		PCRs: map[int][]byte{
			0:  make([]byte, SHA256Size),
			14: make([]byte, SHA256Size),
		},
		Nonce:     []byte("nonce"),
		Timestamp: time.Now(),
	}

	if len(quote.QuoteData) == 0 {
		t.Error("QuoteData should not be empty")
	}
	if len(quote.Signature) == 0 {
		t.Error("Signature should not be empty")
	}
	if len(quote.PCRs) != 2 {
		t.Errorf("PCRs count = %d, want 2", len(quote.PCRs))
	}
	if quote.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestAttestationVerificationResult_Fields(t *testing.T) {
	result := &AttestationVerificationResult{
		ContainerID:      "test-container",
		ContainerName:    "test-name",
		Verified:         true,
		ImageDigest:      make([]byte, SHA256Size),
		ConfigDigest:     make([]byte, SHA256Size),
		PCRValue:         make([]byte, SHA256Size),
		ExpectedPCRValue: make([]byte, SHA256Size),
		Timestamp:        time.Now(),
	}

	if result.ContainerID != "test-container" {
		t.Errorf("ContainerID = %s, want test-container", result.ContainerID)
	}
	if result.ContainerName != "test-name" {
		t.Errorf("ContainerName = %s, want test-name", result.ContainerName)
	}
	if !result.Verified {
		t.Error("Verified should be true")
	}
	if result.Error != "" {
		t.Errorf("Error should be empty, got: %s", result.Error)
	}
}
