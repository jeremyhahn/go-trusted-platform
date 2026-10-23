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

package workload

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

func testConfig() *config.WorkloadConfig {
	return &config.WorkloadConfig{
		Enabled:             true,
		PCR:                 14,
		PCRBank:             "sha256",
		IncludeImageDigest:  true,
		IncludeContainerID:  true,
		IncludeWorkloadType: true,
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNewChainManager(t *testing.T) {
	cm := NewChainManager()
	if cm == nil {
		t.Fatal("NewChainManager returned nil")
	}
}

func TestNewChainManager_WithOptions(t *testing.T) {
	tpm := NewSoftwareTPM()
	logger := testLogger()

	cm := NewChainManager(
		WithTPMDevice(tpm),
		WithLogger(logger),
	)

	if cm == nil {
		t.Fatal("NewChainManager returned nil")
	}
}

func TestChainManager_Initialize(t *testing.T) {
	t.Run("valid initialization", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		err := cm.Initialize(ctx, testConfig())
		if err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}
	})

	t.Run("nil config", func(t *testing.T) {
		cm := NewChainManager(WithLogger(testLogger()))

		ctx := context.Background()
		err := cm.Initialize(ctx, nil)
		if err == nil {
			t.Error("expected error for nil config")
		}

		_, ok := err.(ErrInvalidConfig)
		if !ok {
			t.Errorf("expected ErrInvalidConfig, got %T", err)
		}
	})

	t.Run("invalid PCR bank", func(t *testing.T) {
		cm := NewChainManager(WithLogger(testLogger()))

		cfg := testConfig()
		cfg.PCRBank = "invalid"

		ctx := context.Background()
		err := cm.Initialize(ctx, cfg)
		if err == nil {
			t.Error("expected error for invalid PCR bank")
		}
	})

	t.Run("double initialization", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("first Initialize failed: %v", err)
		}

		err := cm.Initialize(ctx, testConfig())
		if err == nil {
			t.Error("expected error for double initialization")
		}

		_, ok := err.(ErrChainAlreadyInitialized)
		if !ok {
			t.Errorf("expected ErrChainAlreadyInitialized, got %T", err)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		cm := NewChainManager(WithLogger(testLogger()))

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := cm.Initialize(ctx, testConfig())
		if err == nil {
			t.Error("expected error for canceled context")
		}

		_, ok := err.(ErrContextCanceled)
		if !ok {
			t.Errorf("expected ErrContextCanceled, got %T", err)
		}
	})

	t.Run("software only mode", func(t *testing.T) {
		// No TPM device configured
		cm := NewChainManager(WithLogger(testLogger()))

		ctx := context.Background()
		err := cm.Initialize(ctx, testConfig())
		if err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}
	})
}

func TestChainManager_ExtendPCR(t *testing.T) {
	t.Run("valid extension", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		measurement := &WorkloadMeasurement{
			WorkloadType: WorkloadTypeContainer,
			WorkloadID:   "container-123",
			ImageDigest:  "sha256:abc123",
		}

		entry, err := cm.ExtendPCR(ctx, measurement)
		if err != nil {
			t.Fatalf("ExtendPCR failed: %v", err)
		}

		if entry == nil {
			t.Fatal("entry should not be nil")
		}
		if entry.WorkloadType != WorkloadTypeContainer {
			t.Errorf("WorkloadType = %s, want container", entry.WorkloadType)
		}
		if entry.WorkloadID != "container-123" {
			t.Errorf("WorkloadID = %s, want container-123", entry.WorkloadID)
		}
		if entry.ImageDigest != "sha256:abc123" {
			t.Errorf("ImageDigest = %s, want sha256:abc123", entry.ImageDigest)
		}
		if len(entry.Digest) != 32 {
			t.Errorf("Digest length = %d, want 32", len(entry.Digest))
		}
		if len(entry.PCRValue) != 32 {
			t.Errorf("PCRValue length = %d, want 32", len(entry.PCRValue))
		}
		if entry.Timestamp.IsZero() {
			t.Error("Timestamp should not be zero")
		}
	})

	t.Run("not initialized", func(t *testing.T) {
		cm := NewChainManager(WithLogger(testLogger()))

		ctx := context.Background()
		measurement := &WorkloadMeasurement{
			WorkloadType: WorkloadTypeContainer,
			WorkloadID:   "container-123",
			ImageDigest:  "sha256:abc123",
		}

		_, err := cm.ExtendPCR(ctx, measurement)
		if err == nil {
			t.Error("expected error when not initialized")
		}

		_, ok := err.(ErrChainNotInitialized)
		if !ok {
			t.Errorf("expected ErrChainNotInitialized, got %T", err)
		}
	})

	t.Run("nil measurement", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		_, err := cm.ExtendPCR(ctx, nil)
		if err == nil {
			t.Error("expected error for nil measurement")
		}
	})

	t.Run("invalid workload type", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		measurement := &WorkloadMeasurement{
			WorkloadType: WorkloadType("invalid"),
			WorkloadID:   "container-123",
			ImageDigest:  "sha256:abc123",
		}

		_, err := cm.ExtendPCR(ctx, measurement)
		if err == nil {
			t.Error("expected error for invalid workload type")
		}

		_, ok := err.(ErrInvalidWorkloadType)
		if !ok {
			t.Errorf("expected ErrInvalidWorkloadType, got %T", err)
		}
	})

	t.Run("empty workload ID", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		measurement := &WorkloadMeasurement{
			WorkloadType: WorkloadTypeContainer,
			WorkloadID:   "",
			ImageDigest:  "sha256:abc123",
		}

		_, err := cm.ExtendPCR(ctx, measurement)
		if err == nil {
			t.Error("expected error for empty workload ID")
		}

		_, ok := err.(ErrInvalidWorkloadID)
		if !ok {
			t.Errorf("expected ErrInvalidWorkloadID, got %T", err)
		}
	})

	t.Run("multiple extensions", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		measurements := []*WorkloadMeasurement{
			{WorkloadType: WorkloadTypeContainer, WorkloadID: "c1", ImageDigest: "d1"},
			{WorkloadType: WorkloadTypeVM, WorkloadID: "v1", ImageDigest: "d2"},
			{WorkloadType: WorkloadTypeContainer, WorkloadID: "c2", ImageDigest: "d3"},
		}

		var prevPCR []byte
		for i, m := range measurements {
			entry, err := cm.ExtendPCR(ctx, m)
			if err != nil {
				t.Fatalf("ExtendPCR[%d] failed: %v", i, err)
			}

			// PCR should change with each extension
			if i > 0 && bytes.Equal(entry.PCRValue, prevPCR) {
				t.Errorf("PCR should change after extension %d", i)
			}
			prevPCR = entry.PCRValue
		}

		// Verify chain history
		history := cm.GetChainHistory()
		if len(history) != 3 {
			t.Errorf("chain length = %d, want 3", len(history))
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		canceledCtx, cancel := context.WithCancel(ctx)
		cancel()

		measurement := &WorkloadMeasurement{
			WorkloadType: WorkloadTypeContainer,
			WorkloadID:   "container-123",
			ImageDigest:  "sha256:abc123",
		}

		_, err := cm.ExtendPCR(canceledCtx, measurement)
		if err == nil {
			t.Error("expected error for canceled context")
		}

		_, ok := err.(ErrContextCanceled)
		if !ok {
			t.Errorf("expected ErrContextCanceled, got %T", err)
		}
	})
}

func TestChainManager_GetChainHistory(t *testing.T) {
	t.Run("empty chain", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		history := cm.GetChainHistory()
		if history != nil {
			t.Errorf("empty chain should return nil, got %v", history)
		}
	})

	t.Run("returns copy", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		measurement := &WorkloadMeasurement{
			WorkloadType: WorkloadTypeContainer,
			WorkloadID:   "container-123",
			ImageDigest:  "sha256:abc123",
		}
		_, err := cm.ExtendPCR(ctx, measurement)
		if err != nil {
			t.Fatalf("ExtendPCR failed: %v", err)
		}

		history1 := cm.GetChainHistory()
		history2 := cm.GetChainHistory()

		// Modify history1
		history1[0].WorkloadID = "modified"

		// history2 should not be affected
		if history2[0].WorkloadID == "modified" {
			t.Error("GetChainHistory should return a copy")
		}
	})

	t.Run("correct order", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		ids := []string{"first", "second", "third"}
		for _, id := range ids {
			measurement := &WorkloadMeasurement{
				WorkloadType: WorkloadTypeContainer,
				WorkloadID:   id,
				ImageDigest:  "digest",
			}
			_, err := cm.ExtendPCR(ctx, measurement)
			if err != nil {
				t.Fatalf("ExtendPCR failed: %v", err)
			}
		}

		history := cm.GetChainHistory()
		for i, id := range ids {
			if history[i].WorkloadID != id {
				t.Errorf("entry[%d].WorkloadID = %s, want %s", i, history[i].WorkloadID, id)
			}
		}
	})
}

func TestChainManager_VerifyChain(t *testing.T) {
	t.Run("valid chain", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		// Extend with some measurements
		measurements := []*WorkloadMeasurement{
			{WorkloadType: WorkloadTypeContainer, WorkloadID: "c1", ImageDigest: "d1"},
			{WorkloadType: WorkloadTypeVM, WorkloadID: "v1", ImageDigest: "d2"},
		}

		var lastEntry *ChainEntry
		for _, m := range measurements {
			entry, _ := cm.ExtendPCR(ctx, m)
			lastEntry = entry
		}

		// Verify against the expected PCR value
		valid, err := cm.VerifyChain(ctx, lastEntry.PCRValue)
		if err != nil {
			t.Fatalf("VerifyChain failed: %v", err)
		}
		if !valid {
			t.Error("chain should be valid")
		}
	})

	t.Run("invalid expected value", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		measurement := &WorkloadMeasurement{
			WorkloadType: WorkloadTypeContainer,
			WorkloadID:   "c1",
			ImageDigest:  "d1",
		}
		if _, err := cm.ExtendPCR(ctx, measurement); err != nil {
			t.Fatalf("ExtendPCR failed: %v", err)
		}

		// Wrong expected value
		wrongValue := make([]byte, 32)
		wrongValue[0] = 0xFF

		valid, err := cm.VerifyChain(ctx, wrongValue)
		if err == nil {
			t.Error("expected error for wrong value")
		}
		if valid {
			t.Error("chain should be invalid")
		}

		_, ok := err.(ErrChainVerificationFailed)
		if !ok {
			t.Errorf("expected ErrChainVerificationFailed, got %T", err)
		}
	})

	t.Run("not initialized", func(t *testing.T) {
		cm := NewChainManager(WithLogger(testLogger()))

		ctx := context.Background()
		_, err := cm.VerifyChain(ctx, make([]byte, 32))
		if err == nil {
			t.Error("expected error when not initialized")
		}

		_, ok := err.(ErrChainNotInitialized)
		if !ok {
			t.Errorf("expected ErrChainNotInitialized, got %T", err)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		canceledCtx, cancel := context.WithCancel(ctx)
		cancel()

		_, err := cm.VerifyChain(canceledCtx, make([]byte, 32))
		if err == nil {
			t.Error("expected error for canceled context")
		}
	})
}

func TestChainManager_GetCurrentPCRValue(t *testing.T) {
	t.Run("zero value initially", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		value, err := cm.GetCurrentPCRValue(ctx)
		if err != nil {
			t.Fatalf("GetCurrentPCRValue failed: %v", err)
		}

		zeroPCR := make([]byte, 32)
		if !bytes.Equal(value, zeroPCR) {
			t.Error("PCR should be zero initially")
		}
	})

	t.Run("after extension", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		measurement := &WorkloadMeasurement{
			WorkloadType: WorkloadTypeContainer,
			WorkloadID:   "container-123",
			ImageDigest:  "sha256:abc123",
		}
		entry, _ := cm.ExtendPCR(ctx, measurement)

		value, err := cm.GetCurrentPCRValue(ctx)
		if err != nil {
			t.Fatalf("GetCurrentPCRValue failed: %v", err)
		}

		if !bytes.Equal(value, entry.PCRValue) {
			t.Error("PCR value should match entry")
		}
	})

	t.Run("not initialized", func(t *testing.T) {
		cm := NewChainManager(WithLogger(testLogger()))

		ctx := context.Background()
		_, err := cm.GetCurrentPCRValue(ctx)
		if err == nil {
			t.Error("expected error when not initialized")
		}
	})

	t.Run("software only mode", func(t *testing.T) {
		// No TPM device
		cm := NewChainManager(WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		measurement := &WorkloadMeasurement{
			WorkloadType: WorkloadTypeContainer,
			WorkloadID:   "container-123",
			ImageDigest:  "sha256:abc123",
		}
		entry, _ := cm.ExtendPCR(ctx, measurement)

		value, err := cm.GetCurrentPCRValue(ctx)
		if err != nil {
			t.Fatalf("GetCurrentPCRValue failed: %v", err)
		}

		if !bytes.Equal(value, entry.PCRValue) {
			t.Error("PCR value should match entry in software mode")
		}
	})
}

func TestChainManager_Reset(t *testing.T) {
	t.Run("clears chain", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		// Add some entries
		for i := 0; i < 3; i++ {
			measurement := &WorkloadMeasurement{
				WorkloadType: WorkloadTypeContainer,
				WorkloadID:   "container",
				ImageDigest:  "digest",
			}
			if _, err := cm.ExtendPCR(ctx, measurement); err != nil {
				t.Fatalf("ExtendPCR failed: %v", err)
			}
		}

		if len(cm.GetChainHistory()) != 3 {
			t.Error("chain should have 3 entries before reset")
		}

		if err := cm.Reset(ctx); err != nil {
			t.Fatalf("Reset failed: %v", err)
		}

		history := cm.GetChainHistory()
		if history != nil {
			t.Errorf("chain should be empty after reset, got %d entries", len(history))
		}
	})

	t.Run("not initialized", func(t *testing.T) {
		cm := NewChainManager(WithLogger(testLogger()))

		ctx := context.Background()
		err := cm.Reset(ctx)
		if err == nil {
			t.Error("expected error when not initialized")
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		canceledCtx, cancel := context.WithCancel(ctx)
		cancel()

		err := cm.Reset(canceledCtx)
		if err == nil {
			t.Error("expected error for canceled context")
		}
	})
}

func TestChainManager_GetStatistics(t *testing.T) {
	t.Run("empty chain", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		stats := cm.GetStatistics()
		if stats.TotalEntries != 0 {
			t.Errorf("TotalEntries = %d, want 0", stats.TotalEntries)
		}
		if stats.VMCount != 0 {
			t.Errorf("VMCount = %d, want 0", stats.VMCount)
		}
		if stats.ContainerCount != 0 {
			t.Errorf("ContainerCount = %d, want 0", stats.ContainerCount)
		}
		if len(stats.CurrentPCRValue) != 32 {
			t.Errorf("CurrentPCRValue length = %d, want 32", len(stats.CurrentPCRValue))
		}
	})

	t.Run("with entries", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		// Add mixed workloads
		measurements := []*WorkloadMeasurement{
			{WorkloadType: WorkloadTypeContainer, WorkloadID: "c1", ImageDigest: "d1"},
			{WorkloadType: WorkloadTypeContainer, WorkloadID: "c2", ImageDigest: "d2"},
			{WorkloadType: WorkloadTypeVM, WorkloadID: "v1", ImageDigest: "d3"},
			{WorkloadType: WorkloadTypeContainer, WorkloadID: "c3", ImageDigest: "d4"},
			{WorkloadType: WorkloadTypeVM, WorkloadID: "v2", ImageDigest: "d5"},
		}

		// Each entry is stamped one second after the previous one.
		first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		current := first
		cm.(*chainManager).now = func() time.Time { return current }
		for _, m := range measurements {
			if _, err := cm.ExtendPCR(ctx, m); err != nil {
				t.Fatalf("ExtendPCR failed: %v", err)
			}
			current = current.Add(time.Second)
		}
		last := first.Add(time.Duration(len(measurements)-1) * time.Second)

		stats := cm.GetStatistics()
		if stats.TotalEntries != 5 {
			t.Errorf("TotalEntries = %d, want 5", stats.TotalEntries)
		}
		if stats.VMCount != 2 {
			t.Errorf("VMCount = %d, want 2", stats.VMCount)
		}
		if stats.ContainerCount != 3 {
			t.Errorf("ContainerCount = %d, want 3", stats.ContainerCount)
		}
		if !stats.FirstEntryTime.Equal(first) {
			t.Errorf("FirstEntryTime = %v, want %v", stats.FirstEntryTime, first)
		}
		if !stats.LastEntryTime.Equal(last) {
			t.Errorf("LastEntryTime = %v, want %v", stats.LastEntryTime, last)
		}
		if len(stats.CurrentPCRValue) != 32 {
			t.Errorf("CurrentPCRValue length = %d, want 32", len(stats.CurrentPCRValue))
		}
	})
}

func TestChainManager_Close(t *testing.T) {
	t.Run("close releases resources", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		if err := cm.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		// Operations after close should fail
		measurement := &WorkloadMeasurement{
			WorkloadType: WorkloadTypeContainer,
			WorkloadID:   "container-123",
			ImageDigest:  "sha256:abc123",
		}

		_, err := cm.ExtendPCR(ctx, measurement)
		if err == nil {
			t.Error("expected error after close")
		}
	})

	t.Run("double close is safe", func(t *testing.T) {
		cm := NewChainManager(WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		if err := cm.Close(); err != nil {
			t.Fatalf("first Close failed: %v", err)
		}

		if err := cm.Close(); err != nil {
			t.Fatalf("second Close failed: %v", err)
		}
	})
}

func TestChainManager_SoftwareOnlyMode(t *testing.T) {
	// Test chain manager without TPM device (software-only mode)
	cm := NewChainManager(WithLogger(testLogger()))

	ctx := context.Background()
	if err := cm.Initialize(ctx, testConfig()); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Add measurements
	measurements := []*WorkloadMeasurement{
		{WorkloadType: WorkloadTypeContainer, WorkloadID: "c1", ImageDigest: "d1"},
		{WorkloadType: WorkloadTypeVM, WorkloadID: "v1", ImageDigest: "d2"},
	}

	var lastEntry *ChainEntry
	for _, m := range measurements {
		entry, err := cm.ExtendPCR(ctx, m)
		if err != nil {
			t.Fatalf("ExtendPCR failed: %v", err)
		}
		lastEntry = entry
	}

	// Verify chain
	valid, err := cm.VerifyChain(ctx, lastEntry.PCRValue)
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}
	if !valid {
		t.Error("chain should be valid in software mode")
	}

	// Get PCR value
	pcrValue, err := cm.GetCurrentPCRValue(ctx)
	if err != nil {
		t.Fatalf("GetCurrentPCRValue failed: %v", err)
	}

	if !bytes.Equal(pcrValue, lastEntry.PCRValue) {
		t.Error("PCR value should match last entry")
	}
}
