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
	"os"
	"path/filepath"
	"sort"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// UnlockStrategyMarkerPath is where Execute records the strategy that actually
// unlocked the volume, for the booted system to read.
//
// The initrd knows which strategy won and the booted system does not; without
// this the only record is an initrd log line that does not survive
// switch_root. #63 needs it to decide whether the TPM-PCR path has been PROVEN
// before destroying the keyfile fallback -- so the value written here will
// later authorise an unrecoverable operation, which is why Execute records the
// strategy that RETURNED SUCCESS rather than the one it was about to try.
const UnlockStrategyMarkerPath = "/run/platform/unlock-strategy"

// StrategyChain executes unlock strategies in priority order with fallback
type StrategyChain struct {
	strategies []UnlockStrategy
	logger     *logging.Logger

	// markerPath is where the winning strategy is recorded. Overridable so
	// tests do not write to /run.
	markerPath string
}

// NewStrategyChain creates a new strategy chain
func NewStrategyChain(logger *logging.Logger) *StrategyChain {
	return &StrategyChain{
		strategies: make([]UnlockStrategy, 0),
		logger:     logger,
		markerPath: UnlockStrategyMarkerPath,
	}
}

// SetMarkerPath overrides where the winning strategy is recorded.
func (c *StrategyChain) SetMarkerPath(path string) { c.markerPath = path }

// recordWinner writes the name of the strategy that unlocked the volume.
//
// Deliberately best-effort: the volume is already unlocked by the time this
// runs, and failing the boot because a marker could not be written would trade
// an observability record for an outage. A MISSING marker is the safe
// direction -- #63's wipe is gated on the marker SAYING TPM-PCR, so absence
// means no wipe.
func (c *StrategyChain) recordWinner(name string) {
	if c.markerPath == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(c.markerPath), 0o755); err != nil {
		c.logger.Warnf("could not create unlock-strategy marker directory: %v", err)
		return
	}
	if err := os.WriteFile(c.markerPath, []byte(name+"\n"), 0o644); err != nil {
		c.logger.Warnf("could not write unlock-strategy marker: %v", err)
		return
	}
	c.logger.Debugf("Recorded winning unlock strategy %q at %s", name, c.markerPath)
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
			// Record HERE and only here. The "Trying unlock strategy" log
			// above names the same strategy before it has proven anything;
			// recording there would mark an ATTEMPT as a success and could
			// later authorise a wipe on a boot that fell back to the keyfile.
			c.recordWinner(strategy.Name())
			return nil
		}

		lastErr = err
		c.logger.Warnf("Strategy %s failed: %v", strategy.Name(), err)
	}

	if lastErr != nil {
		return &SentinelCauseError{Sentinel: ErrUnlockFailed, Cause: &WrappedError{Msg: "last error", Err: lastErr}}
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
			return &WrappedError{Msg: fmt.Sprintf("strategy %s install failed", strategy.Name()), Err: err}
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
