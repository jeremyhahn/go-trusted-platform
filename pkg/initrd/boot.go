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
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// Boot performs the normal boot sequence
func (m *initrdManager) Boot(ctx context.Context) error {
	fmt.Fprintf(os.Stderr, "[INITRD-BOOT] Starting normal boot sequence\n")

	startTime := time.Now()
	auditLog := &AuditLog{
		BootTimestamp: startTime.Unix(),
		Mode:          ModeBoot,
		Attempts:      make([]UnlockAttempt, 0),
	}

	// Initialize platform components
	fmt.Fprintf(os.Stderr, "[INITRD-BOOT] Initializing platform\n")
	if err := m.initializePlatform(ctx); err != nil {
		return &WrappedError{Msg: "failed to initialize platform", Err: err}
	}

	// Build volume configuration from config
	fmt.Fprintf(os.Stderr, "[INITRD-BOOT] Building volume config\n")
	volume, err := m.buildVolumeConfig()
	if err != nil {
		return &WrappedError{Msg: "failed to build volume config", Err: err}
	}

	// Execute unlock strategy chain
	fmt.Fprintf(os.Stderr, "[INITRD-BOOT] Executing unlock with audit\n")
	err = m.unlockWithAudit(ctx, volume, auditLog)
	if err != nil {
		m.saveAuditLog(auditLog)
		return &WrappedError{Msg: "failed to unlock volume", Err: err}
	}

	// Successfully unlocked
	auditLog.FinalStatus = true
	auditLog.TotalDuration = time.Since(startTime).Milliseconds()
	m.saveAuditLog(auditLog)

	// NOTE: platformd serve is started by OS init (systemd/openrc) AFTER switch_root
	// The initramfs handles security-critical TPM operations (provision, extend, seal/unseal)
	// The platform daemon cannot start here because root FS isn't mounted yet in initramfs
	//
	// Security is maintained because:
	// - All TPM operations happen in measured initramfs
	// - Root FS is protected by LUKS with TPM-sealed keys
	// - If root is tampered, PCRs won't match, LUKS won't decrypt, tampered binary never runs

	m.logger.Infof("Boot sequence completed in %dms", auditLog.TotalDuration)
	return nil
}

// initializePlatform initializes TPM, LUKS, and validates backend access
func (m *initrdManager) initializePlatform(ctx context.Context) error {
	// TPM should already be initialized from manager creation
	if m.platform.TPM == nil {
		return &MessageError{Msg: "TPM not initialized"}
	}

	// LUKS handler should be ready
	if m.platform.LUKS == nil {
		return &MessageError{Msg: "LUKS handler not initialized"}
	}

	// FIDO2 is optional
	if m.platform.FIDO2 == nil {
		m.logger.Debug("FIDO2 handler not available - FIDO2 unlock disabled")
	}

	// For boot, we need either a full XKMS OR a backend for direct TPM access
	// Minimal boot scenarios use Backend directly without full XKMS infrastructure
	if m.platform.XKMS == nil && m.platform.Backend == nil {
		return &MessageError{Msg: "neither xkms nor backend initialized"}
	}

	if m.platform.XKMS == nil {
		m.logger.Info("Using minimal boot mode with direct backend access")
	}

	return nil
}

// buildVolumeConfig creates a VolumeConfig from the initrd config
func (m *initrdManager) buildVolumeConfig() (*luks.VolumeConfig, error) {
	if m.platform.Config.RootDevice == "" {
		return nil, ErrVolumeNotConfigured
	}

	volume := &luks.VolumeConfig{
		DevicePath:    m.platform.Config.RootDevice,
		MappingName:   "cryptroot",
		LUKSVersion:   luks.LUKS2,
		AllowDiscards: true,
		Timeout:       m.platform.Config.UnlockTimeout,
		KeySlots:      make([]luks.KeySlot, 0),
		PCRBanks:      m.platform.Config.PCRBanks,
		PCRSelection:  m.platform.Config.PCRSelection,
		XKMSPath:      m.platform.Config.XKMSPath,
	}

	// Build key slots based on configured fallback methods
	slotIndex := 0
	for _, method := range m.platform.Config.FallbackMethods {
		slot := luks.KeySlot{
			Index: slotIndex,
			Type:  method,
		}

		// Set priority based on method type
		switch method {
		case luks.UnlockTPMPCR:
			slot.Priority = 1
		case luks.UnlockTPMUpgrade:
			slot.Priority = 2
		case luks.UnlockFIDO2:
			slot.Priority = 3
		case luks.UnlockPassword:
			slot.Priority = 100
		}

		volume.KeySlots = append(volume.KeySlots, slot)
		slotIndex++
	}

	return volume, nil
}

// unlockWithAudit attempts to unlock the volume with audit logging
func (m *initrdManager) unlockWithAudit(ctx context.Context, volume *luks.VolumeConfig, auditLog *AuditLog) error {
	// Sort strategies by priority
	fmt.Fprintf(os.Stderr, "[INITRD-BOOT] Getting strategy list\n")
	strategies := m.chain.List()
	fmt.Fprintf(os.Stderr, "[INITRD-BOOT] Found %d strategies\n", len(strategies))

	for i, strategy := range strategies {
		fmt.Fprintf(os.Stderr, "[INITRD-BOOT] Checking strategy %d: %s\n", i+1, strategy.Name())
		attemptStart := time.Now()

		attempt := UnlockAttempt{
			Strategy:  strategy.Name(),
			Timestamp: attemptStart.Unix(),
		}

		// Check if strategy can unlock
		fmt.Fprintf(os.Stderr, "[INITRD-BOOT] Calling CanUnlock for %s\n", strategy.Name())
		canUnlock := strategy.CanUnlock(ctx, volume)
		fmt.Fprintf(os.Stderr, "[INITRD-BOOT] CanUnlock returned: %v\n", canUnlock)
		if !canUnlock {
			fmt.Fprintf(os.Stderr, "[INITRD-BOOT] Strategy %s cannot unlock, skipping\n", strategy.Name())
			continue
		}

		fmt.Fprintf(os.Stderr, "[INITRD-BOOT] Attempting unlock with strategy: %s\n", strategy.Name())

		// Try unlock
		err := strategy.Unlock(ctx, volume)
		attempt.Duration = time.Since(attemptStart).Milliseconds()

		if err == nil {
			attempt.Success = true
			auditLog.Attempts = append(auditLog.Attempts, attempt)
			m.logger.Infof("Successfully unlocked with strategy: %s in %dms",
				strategy.Name(), attempt.Duration)
			// The winner is what the seal confirmation and the booted
			// system act on; recorded only here, on success, for the
			// reason recordWinner gives.
			m.unlockedWith = strategy.Name()
			m.chain.recordWinner(strategy.Name())
			return nil
		}

		attempt.Error = err.Error()
		auditLog.Attempts = append(auditLog.Attempts, attempt)
		m.logger.Warnf("Strategy %s failed: %v", strategy.Name(), err)
	}

	return ErrUnlockFailed
}

// saveAuditLog saves the audit log if enabled
func (m *initrdManager) saveAuditLog(auditLog *AuditLog) {
	if !m.platform.Config.EnableAuditLog {
		return
	}

	// In a real implementation, this would write to the configured audit log path
	// For now, just log the summary
	m.logger.Infof("Audit Log Summary:")
	m.logger.Infof("  Mode: %s", auditLog.Mode)
	m.logger.Infof("  Attempts: %d", len(auditLog.Attempts))
	m.logger.Infof("  Success: %t", auditLog.FinalStatus)
	m.logger.Infof("  Total Duration: %dms", auditLog.TotalDuration)

	for i, attempt := range auditLog.Attempts {
		status := "FAILED"
		if attempt.Success {
			status = "SUCCESS"
		}
		m.logger.Infof("  Attempt %d: %s - %s (%dms)",
			i+1, attempt.Strategy, status, attempt.Duration)
		if attempt.Error != "" {
			m.logger.Debugf("    Error: %s", attempt.Error)
		}
	}
}
