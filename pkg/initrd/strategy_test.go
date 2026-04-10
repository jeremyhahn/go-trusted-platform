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

package initrd

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

func TestNewStrategyChain(t *testing.T) {
	logger := logging.DefaultLogger()
	chain := NewStrategyChain(logger)

	if chain == nil {
		t.Fatal("NewStrategyChain returned nil")
	}

	if chain.logger != logger {
		t.Error("logger not set correctly")
	}

	if len(chain.strategies) != 0 {
		t.Errorf("expected 0 strategies, got %d", len(chain.strategies))
	}
}

func TestStrategyChainAdd(t *testing.T) {
	logger := logging.DefaultLogger()
	chain := NewStrategyChain(logger)

	strategy1 := &mockStrategy{name: "test1", priority: 5}
	strategy2 := &mockStrategy{name: "test2", priority: 1}
	strategy3 := &mockStrategy{name: "test3", priority: 10}

	chain.Add(strategy1)
	chain.Add(strategy2)
	chain.Add(strategy3)

	if chain.Count() != 3 {
		t.Errorf("expected 3 strategies, got %d", chain.Count())
	}

	// Strategies should be sorted by priority
	strategies := chain.List()
	if strategies[0].Priority() != 1 {
		t.Errorf("expected first strategy priority 1, got %d", strategies[0].Priority())
	}
	if strategies[1].Priority() != 5 {
		t.Errorf("expected second strategy priority 5, got %d", strategies[1].Priority())
	}
	if strategies[2].Priority() != 10 {
		t.Errorf("expected third strategy priority 10, got %d", strategies[2].Priority())
	}
}

func TestStrategyChainRemove(t *testing.T) {
	logger := logging.DefaultLogger()
	chain := NewStrategyChain(logger)

	strategy1 := &mockStrategy{name: "test1", priority: 1}
	strategy2 := &mockStrategy{name: "test2", priority: 2}
	strategy3 := &mockStrategy{name: "test3", priority: 3}

	chain.Add(strategy1)
	chain.Add(strategy2)
	chain.Add(strategy3)

	if chain.Count() != 3 {
		t.Fatalf("expected 3 strategies before removal, got %d", chain.Count())
	}

	chain.Remove("test2")

	if chain.Count() != 2 {
		t.Errorf("expected 2 strategies after removal, got %d", chain.Count())
	}

	strategies := chain.List()
	for _, s := range strategies {
		if s.Name() == "test2" {
			t.Error("strategy test2 should have been removed")
		}
	}
}

func TestStrategyChainRemoveNonExistent(t *testing.T) {
	logger := logging.DefaultLogger()
	chain := NewStrategyChain(logger)

	strategy1 := &mockStrategy{name: "test1", priority: 1}
	chain.Add(strategy1)

	// Remove a strategy that doesn't exist - should not panic
	chain.Remove("nonexistent")

	if chain.Count() != 1 {
		t.Errorf("expected 1 strategy, got %d", chain.Count())
	}
}

func TestStrategyChainExecuteNoStrategies(t *testing.T) {
	logger := logging.DefaultLogger()
	chain := NewStrategyChain(logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "crypt-root",
	}

	err := chain.Execute(ctx, volume)
	if err == nil {
		t.Error("expected error for empty strategy chain")
	}

	if !errors.Is(err, ErrNoStrategiesAvail) {
		t.Errorf("expected ErrNoStrategiesAvail, got %v", err)
	}
}

func TestStrategyChainExecuteSuccess(t *testing.T) {
	logger := logging.DefaultLogger()
	chain := NewStrategyChain(logger)

	successStrategy := &mockSuccessStrategy{
		mockStrategy: mockStrategy{name: "success", priority: 1},
	}

	chain.Add(successStrategy)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "crypt-root",
	}

	err := chain.Execute(ctx, volume)
	if err != nil {
		t.Errorf("expected success, got error: %v", err)
	}

	if !successStrategy.unlockCalled {
		t.Error("unlock should have been called")
	}
}

func TestStrategyChainExecuteFailure(t *testing.T) {
	logger := logging.DefaultLogger()
	chain := NewStrategyChain(logger)

	failStrategy := &mockFailStrategy{
		mockStrategy: mockStrategy{name: "fail", priority: 1},
	}

	chain.Add(failStrategy)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "crypt-root",
	}

	err := chain.Execute(ctx, volume)
	if err == nil {
		t.Error("expected error, got success")
	}

	if !errors.Is(err, ErrUnlockFailed) {
		t.Errorf("expected ErrUnlockFailed, got %v", err)
	}
}

func TestStrategyChainExecuteFallback(t *testing.T) {
	logger := logging.DefaultLogger()
	chain := NewStrategyChain(logger)

	failStrategy := &mockFailStrategy{
		mockStrategy: mockStrategy{name: "fail", priority: 1},
	}
	successStrategy := &mockSuccessStrategy{
		mockStrategy: mockStrategy{name: "success", priority: 2},
	}

	chain.Add(failStrategy)
	chain.Add(successStrategy)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "crypt-root",
	}

	err := chain.Execute(ctx, volume)
	if err != nil {
		t.Errorf("expected success from fallback, got error: %v", err)
	}

	if !successStrategy.unlockCalled {
		t.Error("fallback strategy should have been called")
	}
}

func TestStrategyChainExecuteCannotUnlock(t *testing.T) {
	logger := logging.DefaultLogger()
	chain := NewStrategyChain(logger)

	cannotUnlockStrategy := &mockCannotUnlockStrategy{
		mockStrategy: mockStrategy{name: "cannot-unlock", priority: 1},
	}

	chain.Add(cannotUnlockStrategy)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "crypt-root",
	}

	err := chain.Execute(ctx, volume)
	if err == nil {
		t.Error("expected error when no strategy can unlock")
	}

	if !errors.Is(err, ErrUnlockFailed) {
		t.Errorf("expected ErrUnlockFailed, got %v", err)
	}
}

func TestStrategyChainExecuteContextCanceled(t *testing.T) {
	logger := logging.DefaultLogger()
	chain := NewStrategyChain(logger)

	successStrategy := &mockSuccessStrategy{
		mockStrategy: mockStrategy{name: "success", priority: 1},
	}
	chain.Add(successStrategy)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "crypt-root",
	}

	err := chain.Execute(ctx, volume)
	if err == nil {
		t.Error("expected error for canceled context")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestStrategyChainExecuteInstall(t *testing.T) {
	logger := logging.DefaultLogger()
	chain := NewStrategyChain(logger)

	strategy1 := &mockSuccessStrategy{
		mockStrategy: mockStrategy{name: "strategy1", priority: 1},
	}
	strategy2 := &mockSuccessStrategy{
		mockStrategy: mockStrategy{name: "strategy2", priority: 2},
	}

	chain.Add(strategy1)
	chain.Add(strategy2)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "crypt-root",
	}
	password := []byte("test-password")

	err := chain.ExecuteInstall(ctx, volume, password)
	if err != nil {
		t.Errorf("expected success, got error: %v", err)
	}

	if !strategy1.installCalled {
		t.Error("strategy1 install should have been called")
	}

	if !strategy2.installCalled {
		t.Error("strategy2 install should have been called")
	}
}

func TestStrategyChainExecuteInstallFailure(t *testing.T) {
	logger := logging.DefaultLogger()
	chain := NewStrategyChain(logger)

	failStrategy := &mockFailInstallStrategy{
		mockStrategy: mockStrategy{name: "fail", priority: 1},
	}

	chain.Add(failStrategy)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "crypt-root",
	}
	password := []byte("test-password")

	err := chain.ExecuteInstall(ctx, volume, password)
	if err == nil {
		t.Error("expected error from install failure")
	}
}

func TestStrategyChainExecuteInstallContextCanceled(t *testing.T) {
	logger := logging.DefaultLogger()
	chain := NewStrategyChain(logger)

	strategy := &mockSuccessStrategy{
		mockStrategy: mockStrategy{name: "success", priority: 1},
	}
	chain.Add(strategy)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "crypt-root",
	}
	password := []byte("test-password")

	err := chain.ExecuteInstall(ctx, volume, password)
	if err == nil {
		t.Error("expected error for canceled context")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestStrategyChainList(t *testing.T) {
	logger := logging.DefaultLogger()
	chain := NewStrategyChain(logger)

	strategy1 := &mockStrategy{name: "test1", priority: 1}
	strategy2 := &mockStrategy{name: "test2", priority: 2}

	chain.Add(strategy1)
	chain.Add(strategy2)

	strategies := chain.List()
	if len(strategies) != 2 {
		t.Errorf("expected 2 strategies, got %d", len(strategies))
	}
}

func TestStrategyChainCount(t *testing.T) {
	logger := logging.DefaultLogger()
	chain := NewStrategyChain(logger)

	if chain.Count() != 0 {
		t.Errorf("expected 0 strategies initially, got %d", chain.Count())
	}

	chain.Add(&mockStrategy{name: "test1", priority: 1})
	if chain.Count() != 1 {
		t.Errorf("expected 1 strategy after add, got %d", chain.Count())
	}

	chain.Add(&mockStrategy{name: "test2", priority: 2})
	if chain.Count() != 2 {
		t.Errorf("expected 2 strategies after second add, got %d", chain.Count())
	}

	chain.Remove("test1")
	if chain.Count() != 1 {
		t.Errorf("expected 1 strategy after remove, got %d", chain.Count())
	}
}

// Mock strategies for testing

type mockSuccessStrategy struct {
	mockStrategy
	unlockCalled  bool
	installCalled bool
}

func (m *mockSuccessStrategy) CanUnlock(_ context.Context, _ *luks.VolumeConfig) bool {
	return true
}

func (m *mockSuccessStrategy) Unlock(_ context.Context, _ *luks.VolumeConfig) error {
	m.unlockCalled = true
	return nil
}

func (m *mockSuccessStrategy) Install(_ context.Context, _ *luks.VolumeConfig, _ []byte) error {
	m.installCalled = true
	return nil
}

type mockFailStrategy struct {
	mockStrategy
}

func (m *mockFailStrategy) CanUnlock(_ context.Context, _ *luks.VolumeConfig) bool {
	return true
}

func (m *mockFailStrategy) Unlock(_ context.Context, _ *luks.VolumeConfig) error {
	return errors.New("unlock failed")
}

type mockCannotUnlockStrategy struct {
	mockStrategy
}

func (m *mockCannotUnlockStrategy) CanUnlock(_ context.Context, _ *luks.VolumeConfig) bool {
	return false
}

func (m *mockCannotUnlockStrategy) Unlock(_ context.Context, _ *luks.VolumeConfig) error {
	return errors.New("should not be called")
}

type mockFailInstallStrategy struct {
	mockStrategy
}

func (m *mockFailInstallStrategy) Install(_ context.Context, _ *luks.VolumeConfig, _ []byte) error {
	return errors.New("install failed")
}
