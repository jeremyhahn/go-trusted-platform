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
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

// ChainManager manages the workload measurement chain and PCR extensions.
type ChainManager interface {
	// Initialize sets up the chain manager with the given configuration.
	// Returns ErrChainAlreadyInitialized if already initialized.
	Initialize(ctx context.Context, cfg *config.WorkloadConfig) error

	// ExtendPCR extends the PCR with a new workload measurement.
	// Returns the chain entry created for this extension.
	ExtendPCR(ctx context.Context, measurement *WorkloadMeasurement) (*ChainEntry, error)

	// GetChainHistory returns all entries in the measurement chain.
	// Returns a copy of the entries to prevent external modification.
	GetChainHistory() []*ChainEntry

	// VerifyChain verifies the measurement chain against an expected PCR value.
	// Returns true if the computed PCR matches the expected value.
	VerifyChain(ctx context.Context, expectedPCRValue []byte) (bool, error)

	// GetCurrentPCRValue reads the current PCR value from the TPM.
	GetCurrentPCRValue(ctx context.Context) ([]byte, error)

	// Reset clears the measurement chain and resets the PCR to zeros.
	// Note: Real TPM PCRs cannot be reset except on system restart.
	// This method is primarily for software TPM testing scenarios.
	Reset(ctx context.Context) error

	// GetStatistics returns statistics about the measurement chain.
	GetStatistics() *ChainStatistics

	// Close releases resources held by the chain manager.
	Close() error
}

// chainManager is the concrete implementation of ChainManager.
type chainManager struct {
	mu          sync.RWMutex
	initialized atomic.Bool
	closed      atomic.Bool
	tpm         TPMDevice
	config      *config.WorkloadConfig
	algorithm   HashAlgorithm
	entries     []*ChainEntry
	logger      *slog.Logger
	now         func() time.Time // time.Now in production; tests replace it to control entry timestamps (#284)
}

// ChainManagerOption configures a chain manager.
type ChainManagerOption func(*chainManager)

// WithTPMDevice sets the TPM device for the chain manager.
func WithTPMDevice(tpm TPMDevice) ChainManagerOption {
	return func(cm *chainManager) {
		cm.tpm = tpm
	}
}

// WithLogger sets the logger for the chain manager.
func WithLogger(logger *slog.Logger) ChainManagerOption {
	return func(cm *chainManager) {
		cm.logger = logger
	}
}

// NewChainManager creates a new chain manager with the given options.
func NewChainManager(opts ...ChainManagerOption) ChainManager {
	cm := &chainManager{
		entries: make([]*ChainEntry, 0),
		now:     time.Now,
	}

	for _, opt := range opts {
		opt(cm)
	}

	if cm.logger == nil {
		cm.logger = slog.Default()
	}

	return cm
}

// Initialize sets up the chain manager with the given configuration.
func (cm *chainManager) Initialize(ctx context.Context, cfg *config.WorkloadConfig) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "Initialize"}
	default:
	}

	if cm.initialized.Load() {
		return ErrChainAlreadyInitialized{}
	}

	if cfg == nil {
		return ErrInvalidConfig{Reason: "configuration cannot be nil"}
	}

	if err := cfg.Validate(); err != nil {
		return ErrInvalidConfig{Reason: err.Error()}
	}

	algorithm := HashAlgorithm(cfg.PCRBank)
	if !algorithm.IsValid() {
		return ErrInvalidHashAlgorithm{Algorithm: cfg.PCRBank}
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.config = cfg
	cm.algorithm = algorithm

	// Validate TPM access if device is configured
	if cm.tpm != nil {
		_, err := cm.tpm.ReadPCR(ctx, cfg.PCR, algorithm)
		if err != nil {
			return ErrTPMNotAvailable{Cause: err}
		}
	}

	cm.initialized.Store(true)

	cm.logger.Info("chain manager initialized",
		"pcr", cfg.PCR,
		"algorithm", cfg.PCRBank,
		"enabled", cfg.Enabled,
	)

	return nil
}

// ExtendPCR extends the PCR with a new workload measurement.
func (cm *chainManager) ExtendPCR(ctx context.Context, measurement *WorkloadMeasurement) (*ChainEntry, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "ExtendPCR"}
	default:
	}

	if !cm.initialized.Load() {
		return nil, ErrChainNotInitialized{}
	}

	if cm.closed.Load() {
		return nil, ErrChainNotInitialized{}
	}

	if measurement == nil {
		return nil, ErrInvalidWorkloadID{Reason: "measurement cannot be nil"}
	}

	if err := measurement.Validate(); err != nil {
		return nil, err
	}

	// Compute the measurement digest
	digest, err := computeDigest(cm.algorithm, measurement)
	if err != nil {
		return nil, err
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Get current PCR value (either from TPM or compute from chain)
	var currentPCR []byte
	if cm.tpm != nil {
		currentPCR, err = cm.tpm.ReadPCR(ctx, cm.config.PCR, cm.algorithm)
		if err != nil {
			return nil, ErrPCRReadFailed{PCR: cm.config.PCR, Cause: err}
		}
	} else {
		// Compute from chain for software-only mode
		currentPCR = cm.computePCRFromChain()
	}

	// Extend the PCR
	if cm.tpm != nil {
		if err := cm.tpm.ExtendPCR(ctx, cm.config.PCR, cm.algorithm, digest); err != nil {
			return nil, ErrPCRExtensionFailed{PCR: cm.config.PCR, Cause: err}
		}
	}

	// Compute the new PCR value
	newPCR, err := computeExpectedPCR(cm.algorithm, currentPCR, digest)
	if err != nil {
		return nil, err
	}

	// Create the chain entry
	entry := &ChainEntry{
		Timestamp:    cm.now().UTC(),
		WorkloadType: measurement.WorkloadType,
		WorkloadID:   measurement.WorkloadID,
		ImageDigest:  measurement.ImageDigest,
		Digest:       digest,
		PCRValue:     newPCR,
	}

	cm.entries = append(cm.entries, entry)

	cm.logger.Info("PCR extended",
		"pcr", cm.config.PCR,
		"workload_type", measurement.WorkloadType,
		"workload_id", measurement.WorkloadID,
		"image_digest", measurement.ImageDigest,
		"entry_count", len(cm.entries),
	)

	return entry, nil
}

// GetChainHistory returns a copy of all entries in the measurement chain.
func (cm *chainManager) GetChainHistory() []*ChainEntry {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if len(cm.entries) == 0 {
		return nil
	}

	// Return a copy to prevent external modification
	result := make([]*ChainEntry, len(cm.entries))
	for i, entry := range cm.entries {
		entryCopy := *entry
		entryCopy.Digest = make([]byte, len(entry.Digest))
		copy(entryCopy.Digest, entry.Digest)
		entryCopy.PCRValue = make([]byte, len(entry.PCRValue))
		copy(entryCopy.PCRValue, entry.PCRValue)
		result[i] = &entryCopy
	}
	return result
}

// VerifyChain verifies the measurement chain against an expected PCR value.
func (cm *chainManager) VerifyChain(ctx context.Context, expectedPCRValue []byte) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ErrContextCanceled{Operation: "VerifyChain"}
	default:
	}

	if !cm.initialized.Load() {
		return false, ErrChainNotInitialized{}
	}

	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Compute the expected PCR value from the chain
	computedPCR := cm.computePCRFromChain()

	// Compare with expected value
	if !bytes.Equal(computedPCR, expectedPCRValue) {
		return false, ErrChainVerificationFailed{
			Reason: "computed PCR does not match expected value",
		}
	}

	return true, nil
}

// GetCurrentPCRValue reads the current PCR value.
func (cm *chainManager) GetCurrentPCRValue(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "GetCurrentPCRValue"}
	default:
	}

	if !cm.initialized.Load() {
		return nil, ErrChainNotInitialized{}
	}

	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.tpm != nil {
		return cm.tpm.ReadPCR(ctx, cm.config.PCR, cm.algorithm)
	}

	// For software-only mode, compute from chain
	return cm.computePCRFromChain(), nil
}

// Reset clears the measurement chain.
func (cm *chainManager) Reset(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "Reset"}
	default:
	}

	if !cm.initialized.Load() {
		return ErrChainNotInitialized{}
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.entries = make([]*ChainEntry, 0)

	cm.logger.Info("chain reset", "pcr", cm.config.PCR)

	return nil
}

// GetStatistics returns statistics about the measurement chain.
func (cm *chainManager) GetStatistics() *ChainStatistics {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	stats := &ChainStatistics{
		TotalEntries: len(cm.entries),
	}

	for _, entry := range cm.entries {
		switch entry.WorkloadType {
		case WorkloadTypeVM:
			stats.VMCount++
		case WorkloadTypeContainer:
			stats.ContainerCount++
		}
	}

	if len(cm.entries) > 0 {
		stats.FirstEntryTime = cm.entries[0].Timestamp
		stats.LastEntryTime = cm.entries[len(cm.entries)-1].Timestamp
		stats.CurrentPCRValue = make([]byte, len(cm.entries[len(cm.entries)-1].PCRValue))
		copy(stats.CurrentPCRValue, cm.entries[len(cm.entries)-1].PCRValue)
	} else if cm.initialized.Load() {
		// Return zero PCR for initialized but empty chain
		stats.CurrentPCRValue = make([]byte, cm.algorithm.DigestSize())
	}

	return stats
}

// Close releases resources held by the chain manager.
func (cm *chainManager) Close() error {
	if cm.closed.Swap(true) {
		return nil
	}

	cm.logger.Info("chain manager closed")
	return nil
}

// computePCRFromChain computes the expected PCR value by replaying all chain entries.
func (cm *chainManager) computePCRFromChain() []byte {
	// Start with zero PCR value
	pcr := make([]byte, cm.algorithm.DigestSize())

	// Replay all extensions
	for _, entry := range cm.entries {
		newPCR, _ := computeExpectedPCR(cm.algorithm, pcr, entry.Digest)
		pcr = newPCR
	}

	return pcr
}
