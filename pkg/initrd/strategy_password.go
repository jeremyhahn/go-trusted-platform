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
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
	"golang.org/x/term"
)

// PasswordStrategy provides password-based unlock (fallback)
type PasswordStrategy struct {
	platform *Platform
	logger   *logging.Logger
	priority int
	reader   *bufio.Reader
}

// NewPasswordStrategy creates a new password unlock strategy
func NewPasswordStrategy(platform *Platform, logger *logging.Logger) *PasswordStrategy {
	return &PasswordStrategy{
		platform: platform,
		logger:   logger,
		priority: 100, // Lowest priority - manual fallback
		reader:   nil, // Create lazily when needed to avoid blocking on stdin during init
	}
}

// Name returns the strategy name
func (s *PasswordStrategy) Name() string {
	return "Password"
}

// Priority returns the execution priority
func (s *PasswordStrategy) Priority() int {
	return s.priority
}

// CanUnlock checks if this strategy can unlock the volume
func (s *PasswordStrategy) CanUnlock(ctx context.Context, volume *luks.VolumeConfig) bool {
	// Password unlock is always available as a fallback
	for _, slot := range volume.KeySlots {
		if slot.Type == luks.UnlockPassword {
			return true
		}
	}
	return false
}

// Unlock attempts to unlock the volume using password input
func (s *PasswordStrategy) Unlock(ctx context.Context, volume *luks.VolumeConfig) error {
	s.logger.Infof("Attempting password unlock for %s", volume.DevicePath)

	// Check if password prompts are disabled (automated mode)
	if s.platform.Config.DisablePasswordPrompt {
		fmt.Fprintf(os.Stderr, "[PASSWORD-STRATEGY] Prompts disabled in automated mode\n")
		s.logger.Info("Password prompts disabled in automated mode, skipping")
		return fmt.Errorf("password prompts disabled in automated mode")
	}

	// Find password key slots
	var passwordSlots []luks.KeySlot
	for _, slot := range volume.KeySlots {
		if slot.Type == luks.UnlockPassword {
			passwordSlots = append(passwordSlots, slot)
		}
	}

	if len(passwordSlots) == 0 {
		return fmt.Errorf("no password key slots configured")
	}

	// Prompt for password
	fmt.Printf("\nAll automatic unlock methods failed.\n")
	fmt.Printf("Enter LUKS passphrase for %s: ", volume.DevicePath)

	password, err := s.readPassword(ctx)
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Try each password slot
	for _, slot := range passwordSlots {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		s.logger.Debugf("Trying password slot %d", slot.Index)

		openOpts := &luks.OpenOptions{
			AllowDiscards: volume.AllowDiscards,
			Timeout:       volume.Timeout,
			KeySlot:       &slot.Index,
		}

		err = s.platform.LUKS.Open(ctx, volume.DevicePath, volume.MappingName, password, openOpts)
		if err == nil {
			s.logger.Infof("Successfully unlocked %s with password slot %d",
				volume.DevicePath, slot.Index)
			return nil
		}

		s.logger.Debugf("Password failed for slot %d: %v", slot.Index, err)
	}

	// Try without specifying a slot (let go-luks2 try all)
	s.logger.Debug("Trying password without slot specification")
	err = s.platform.LUKS.Open(ctx, volume.DevicePath, volume.MappingName, password, &luks.OpenOptions{
		AllowDiscards: volume.AllowDiscards,
		Timeout:       volume.Timeout,
	})
	if err == nil {
		s.logger.Infof("Successfully unlocked %s with password", volume.DevicePath)
		return nil
	}

	return fmt.Errorf("password authentication failed")
}

// Install performs installation-time setup for password strategy
func (s *PasswordStrategy) Install(ctx context.Context, volume *luks.VolumeConfig, password []byte) error {
	s.logger.Infof("Installing password strategy for %s", volume.DevicePath)

	// Password slot is typically the initial slot created during LUKS format
	// This strategy just verifies it exists and is functional

	// Find password slots
	var passwordSlot *luks.KeySlot
	for i := range volume.KeySlots {
		if volume.KeySlots[i].Type == luks.UnlockPassword {
			passwordSlot = &volume.KeySlots[i]
			break
		}
	}

	if passwordSlot == nil {
		return fmt.Errorf("no password key slot configured")
	}

	// Test that the password works
	testSlot := passwordSlot.Index
	err := s.platform.LUKS.TestKey(ctx, volume.DevicePath, password, &testSlot)
	if err != nil {
		return fmt.Errorf("password verification failed for slot %d: %w", testSlot, err)
	}

	s.logger.Infof("Password strategy verified for slot %d", passwordSlot.Index)
	return nil
}

// readPassword reads a password from stdin with context-aware timeout
// Uses term.ReadPassword to disable echo for secure password entry
func (s *PasswordStrategy) readPassword(ctx context.Context) ([]byte, error) {
	// Create a channel for the password read
	type result struct {
		password []byte
		err      error
	}
	resultCh := make(chan result, 1)

	// Start reading in a goroutine
	go func() {
		// Check if stdin is a terminal
		fd := int(os.Stdin.Fd())
		if term.IsTerminal(fd) {
			// Use secure password reading (no echo)
			password, err := term.ReadPassword(fd)
			fmt.Println() // New line after password input
			if err != nil {
				resultCh <- result{err: fmt.Errorf("terminal read failed: %w", err)}
				return
			}
			resultCh <- result{password: password}
		} else {
			// Fallback to buffered reader for non-terminal (pipes, testing)
			if s.reader == nil {
				s.reader = bufio.NewReader(os.Stdin)
			}
			input, err := s.reader.ReadString('\n')
			if err != nil {
				resultCh <- result{err: err}
				return
			}
			password := strings.TrimSpace(input)
			resultCh <- result{password: []byte(password)}
		}
	}()

	// Wait for result or context cancellation
	select {
	case res := <-resultCh:
		return res.password, res.err
	case <-ctx.Done():
		return nil, fmt.Errorf("password read cancelled: %w", ctx.Err())
	case <-time.After(5 * time.Minute): // 5 minute timeout for manual input
		return nil, fmt.Errorf("password read timeout")
	}
}

// SetReader allows injecting a custom reader for testing
func (s *PasswordStrategy) SetReader(reader *bufio.Reader) {
	s.reader = reader
}
