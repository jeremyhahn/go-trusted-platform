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
	"fmt"
	"sort"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// StrategyChain executes unlock strategies in priority order with fallback
type StrategyChain struct {
	strategies []UnlockStrategy
	logger     *logging.Logger
}

// NewStrategyChain creates a new strategy chain
func NewStrategyChain(logger *logging.Logger) *StrategyChain {
	return &StrategyChain{
		strategies: make([]UnlockStrategy, 0),
		logger:     logger,
	}
}

// Add adds a strategy to the chain.
// Nil strategies are ignored to support conditional compilation.
func (c *StrategyChain) Add(strategy UnlockStrategy) {
	if strategy == nil {
		return
	}
	c.strategies = append(c.strategies, strategy)
	c.sort()
}

// Remove removes a strategy from the chain
func (c *StrategyChain) Remove(name string) {
	for i, s := range c.strategies {
		if s.Name() == name {
			c.strategies = append(c.strategies[:i], c.strategies[i+1:]...)
			return
		}
	}
}

// Execute executes the strategy chain until one succeeds
func (c *StrategyChain) Execute(ctx context.Context, volume *luks.VolumeConfig) error {
	if len(c.strategies) == 0 {
		return ErrNoStrategiesAvail
	}

	c.sort()

	var lastErr error
	for _, strategy := range c.strategies {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		c.logger.Infof("Trying unlock strategy: %s (priority: %d)",
			strategy.Name(), strategy.Priority())

		if !strategy.CanUnlock(ctx, volume) {
			c.logger.Debugf("Strategy %s cannot unlock volume", strategy.Name())
			continue
		}

		err := strategy.Unlock(ctx, volume)
		if err == nil {
			c.logger.Infof("Successfully unlocked with strategy: %s", strategy.Name())
			return nil
		}

		lastErr = err
		c.logger.Warnf("Strategy %s failed: %v", strategy.Name(), err)
	}

	if lastErr != nil {
		return fmt.Errorf("%w: last error: %v", ErrUnlockFailed, lastErr)
	}

	return ErrUnlockFailed
}

// ExecuteInstall executes installation for all strategies
func (c *StrategyChain) ExecuteInstall(ctx context.Context, volume *luks.VolumeConfig, password []byte) error {
	c.sort()

	for _, strategy := range c.strategies {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		c.logger.Infof("Installing strategy: %s", strategy.Name())

		err := strategy.Install(ctx, volume, password)
		if err != nil {
			c.logger.Errorf("Failed to install strategy %s: %v", strategy.Name(), err)
			return fmt.Errorf("strategy %s install failed: %w", strategy.Name(), err)
		}

		c.logger.Infof("Successfully installed strategy: %s", strategy.Name())
	}

	return nil
}

// List returns all registered strategies
func (c *StrategyChain) List() []UnlockStrategy {
	return c.strategies
}

// Count returns the number of registered strategies
func (c *StrategyChain) Count() int {
	return len(c.strategies)
}

// sort sorts strategies by priority (lower number = higher priority)
func (c *StrategyChain) sort() {
	sort.Slice(c.strategies, func(i, j int) bool {
		return c.strategies[i].Priority() < c.strategies[j].Priority()
	})
}
