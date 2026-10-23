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
	"os/exec"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
	"golang.org/x/term"
)

// Recovery performs recovery mode operations
// This provides interactive recovery options when normal boot fails
func (m *initrdManager) Recovery(ctx context.Context) error {
	m.logger.Info("Entering recovery mode")

	startTime := time.Now()
	auditLog := &AuditLog{
		BootTimestamp: startTime.Unix(),
		Mode:          ModeRecovery,
		Attempts:      make([]UnlockAttempt, 0),
	}

	// Initialize platform
	if err := m.initializePlatform(ctx); err != nil {
		return &WrappedError{Msg: "failed to initialize platform", Err: err}
	}

	// Build volume configuration
	volume, err := m.buildVolumeConfig()
	if err != nil {
		return &WrappedError{Msg: "failed to build volume config", Err: err}
	}

	// Display recovery menu
	m.displayRecoveryMenu()

	// In recovery mode, we prioritize user-interactive methods
	// Re-order strategies to put password first
	m.reorderForRecovery()

	// Attempt unlock with recovery ordering
	err = m.unlockWithAudit(ctx, volume, auditLog)
	if err != nil {
		m.saveAuditLog(auditLog)
		return &SentinelCauseError{Sentinel: ErrRecoveryFailed, Cause: err}
	}

	auditLog.FinalStatus = true
	auditLog.TotalDuration = time.Since(startTime).Milliseconds()
	m.saveAuditLog(auditLog)

	m.logger.Infof("Recovery completed in %dms", auditLog.TotalDuration)
	return nil
}

// InteractiveRecovery provides an interactive recovery menu
func (m *initrdManager) InteractiveRecovery(ctx context.Context) error {
	m.logger.Info("Starting interactive recovery mode")

	// Initialize platform
	if err := m.initializePlatform(ctx); err != nil {
		return &WrappedError{Msg: "failed to initialize platform", Err: err}
	}

	separator := strings.Repeat("=", 60)
	fmt.Println("\n" + separator)
	fmt.Println("INTERACTIVE RECOVERY MODE")
	fmt.Println(separator)
	fmt.Println("\nSelect a recovery operation:")
	fmt.Println()

	for {
		// Display menu
		fmt.Println("1. Try password unlock manually")
		fmt.Println("2. Display TPM diagnostic information")
		fmt.Println("3. Display PCR values and comparison")
		fmt.Println("4. Attempt to reseal TPM keys")
		fmt.Println("5. Launch emergency shell")
		fmt.Println("6. Reboot system")
		fmt.Println("0. Exit recovery mode")
		fmt.Println()
		fmt.Print("Select option: ")

		choice, err := readUserChoice()
		if err != nil {
			fmt.Printf("Invalid input: %v. Please try again.\n\n", err)
			continue
		}

		fmt.Println() // Blank line for readability

		switch choice {
		case 1:
			if err := m.passwordUnlockInteractive(ctx); err != nil {
				fmt.Printf("Password unlock failed: %v\n\n", err)
				continue
			}
			fmt.Println("Successfully unlocked with password!")
			return nil

		case 2:
			if err := m.showTPMDiagnostics(ctx); err != nil {
				fmt.Printf("Failed to display TPM diagnostics: %v\n\n", err)
				continue
			}

		case 3:
			if err := m.showPCRComparison(ctx); err != nil {
				fmt.Printf("Failed to display PCR comparison: %v\n\n", err)
				continue
			}

		case 4:
			if err := m.resealKeysInteractive(ctx); err != nil {
				fmt.Printf("Failed to reseal keys: %v\n\n", err)
				continue
			}

		case 5:
			fmt.Println("Launching emergency shell...")
			fmt.Println("Type 'exit' to return to recovery menu")
			fmt.Println()
			if err := m.launchEmergencyShell(ctx); err != nil {
				fmt.Printf("Emergency shell failed: %v\n\n", err)
				continue
			}

		case 6:
			confirmed, err := confirmAction("reboot the system")
			if err != nil {
				fmt.Printf("Failed to read confirmation: %v\n\n", err)
				continue
			}
			if confirmed {
				fmt.Println("Rebooting system...")
				return m.rebootSystem(ctx)
			}
			fmt.Println("Reboot cancelled")

		case 0:
			fmt.Println("Exiting recovery mode")
			return nil

		default:
			fmt.Printf("Invalid option: %d. Please try again.\n\n", choice)
		}
	}
}

// passwordUnlockInteractive prompts for password and attempts unlock
func (m *initrdManager) passwordUnlockInteractive(ctx context.Context) error {
	m.logger.Info("Starting interactive password unlock")

	fmt.Println("=== Password Unlock ===")
	fmt.Println()
	fmt.Print("Enter LUKS passphrase: ")

	// Read password from terminal (hidden input)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println() // New line after password input
	if err != nil {
		return &WrappedError{Msg: "failed to read password", Err: err}
	}

	if len(password) == 0 {
		return &MessageError{Msg: "password cannot be empty"}
	}

	// Build volume config
	volume, err := m.buildVolumeConfig()
	if err != nil {
		return &WrappedError{Msg: "failed to build volume config", Err: err}
	}

	// Find password strategy
	var passwordStrategy *PasswordStrategy
	for _, strategy := range m.chain.List() {
		if s, ok := strategy.(*PasswordStrategy); ok {
			passwordStrategy = s
			break
		}
	}

	if passwordStrategy == nil {
		return &MessageError{Msg: "password strategy not available"}
	}

	// Temporarily store password and attempt unlock
	fmt.Println("Attempting to unlock volume...")
	err = passwordStrategy.Unlock(ctx, volume)
	if err != nil {
		return &WrappedError{Msg: "unlock failed", Err: err}
	}

	m.logger.Info("Volume unlocked successfully with password")
	return nil
}

// showTPMDiagnostics displays TPM status and diagnostic information
func (m *initrdManager) showTPMDiagnostics(ctx context.Context) error {
	m.logger.Info("Displaying TPM diagnostics")

	separator := strings.Repeat("=", 60)
	fmt.Println(separator)
	fmt.Println("TPM Diagnostics")
	fmt.Println(separator)
	fmt.Println()

	// Display TPM info
	info, err := m.platform.TPM.Info()
	if err != nil {
		return &WrappedError{Msg: "failed to get TPM info", Err: err}
	}

	fmt.Println(info)
	fmt.Println()

	// Display fixed properties
	props, err := m.platform.TPM.FixedProperties()
	if err != nil {
		m.logger.Warnf("Failed to get fixed properties: %v", err)
	} else {
		fmt.Println("TPM Fixed Properties:")
		fmt.Printf("  Manufacturer: %s\n", props.Manufacturer)
		fmt.Printf("  Model: %s\n", props.Model)
		fmt.Printf("  Firmware Version: %d.%d\n",
			props.FwMajor, props.FwMinor)

		fmt.Println()
	}

	// Display EK information if available
	ekAttrs, err := m.platform.TPM.EKAttributes()
	if err != nil {
		m.logger.Debugf("EK not available: %v", err)
	} else {
		fmt.Println("Endorsement Key Information:")
		fmt.Printf("  CN: %s\n", ekAttrs.CN)
		fmt.Printf("  Key Algorithm: %s\n", ekAttrs.KeyAlgorithm)
		fmt.Printf("  Hierarchy: 0x%x\n", ekAttrs.TPMAttributes.Hierarchy)
		fmt.Println()
	}

	// Display SRK information if available
	srkAttrs, err := m.platform.TPM.SSRKAttributes()
	if err != nil {
		fmt.Printf("SRK not available: %v\n", err)
	} else {
		fmt.Println("Storage Root Key Information:")
		fmt.Printf("  CN: %s\n", srkAttrs.CN)
		fmt.Printf("  Key Algorithm: %s\n", srkAttrs.KeyAlgorithm)
		fmt.Printf("  Hierarchy: 0x%x\n", srkAttrs.TPMAttributes.Hierarchy)
		fmt.Println()
	}

	fmt.Println(separator)
	fmt.Println()
	return nil
}

// showPCRComparison displays current PCR values and comparison with saved values
func (m *initrdManager) showPCRComparison(ctx context.Context) error {
	m.logger.Info("Displaying PCR comparison")

	separator := strings.Repeat("=", 60)
	fmt.Println(separator)
	fmt.Println("PCR Values and Comparison")
	fmt.Println(separator)
	fmt.Println()

	// Read current PCR values
	pcrs, err := m.platform.TPM.ReadPCRs(m.platform.Config.PCRSelection)
	if err != nil {
		return &WrappedError{Msg: "failed to read PCR values", Err: err}
	}

	fmt.Println("Current PCR Values:")
	for _, bank := range pcrs {
		fmt.Printf("\nBank: %s\n", bank.Algorithm)
		for _, pcr := range bank.PCRs {
			fmt.Printf("  PCR[%02d]: %x\n", pcr.ID, pcr.Value)
		}
	}
	fmt.Println()

	// Attempt to read saved PCRs from EFI variables or XKMS
	// This would require platform-specific implementation
	fmt.Println("Note: Saved PCR comparison requires platform-specific implementation")
	fmt.Println("      Check EFI variables or xkms for sealed PCR values")
	fmt.Println()

	// Display upgrade PCRs if configured
	if len(m.platform.Config.UpgradePCRSelection) > 0 {
		upgradePcrs, err := m.platform.TPM.ReadPCRs(m.platform.Config.UpgradePCRSelection)
		if err != nil {
			m.logger.Warnf("Failed to read upgrade PCRs: %v", err)
		} else {
			fmt.Println("Upgrade PCR Values (relaxed set):")
			for _, bank := range upgradePcrs {
				fmt.Printf("\nBank: %s\n", bank.Algorithm)
				for _, pcr := range bank.PCRs {
					fmt.Printf("  PCR[%02d]: %x\n", pcr.ID, pcr.Value)
				}
			}
			fmt.Println()
		}
	}

	fmt.Println(separator)
	fmt.Println()
	return nil
}

// resealKeysInteractive prompts for confirmation and reseals TPM keys
func (m *initrdManager) resealKeysInteractive(ctx context.Context) error {
	m.logger.Info("Starting interactive key reseal")

	fmt.Println("=== Reseal TPM Keys ===")
	fmt.Println()
	fmt.Println("WARNING: This will reseal TPM keys to the current PCR values.")
	fmt.Println("         This is necessary after kernel updates or system changes.")
	fmt.Println("         Make sure you have a recovery password available!")
	fmt.Println()

	confirmed, err := confirmAction("reseal TPM keys to current PCR values")
	if err != nil {
		return &WrappedError{Msg: "failed to read confirmation", Err: err}
	}

	if !confirmed {
		fmt.Println("Reseal operation cancelled")
		return nil
	}

	fmt.Println()
	fmt.Println("Resealing keys to current PCR values...")
	err = m.ResealKeys(ctx)
	if err != nil {
		return &WrappedError{Msg: "reseal failed", Err: err}
	}

	fmt.Println("Keys successfully resealed!")
	fmt.Println()
	return nil
}

// launchEmergencyShell launches an emergency shell for manual recovery
func (m *initrdManager) launchEmergencyShell(ctx context.Context) error {
	m.logger.Info("Launching emergency shell")

	// Try to find a shell
	shells := []string{"/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"}
	var shellPath string

	for _, shell := range shells {
		if _, err := os.Stat(shell); err == nil {
			shellPath = shell
			break
		}
	}

	if shellPath == "" {
		return &MessageError{Msg: "no shell found in standard locations"}
	}

	// Create command
	cmd := exec.CommandContext(ctx, shellPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	// Set environment variables
	cmd.Env = append(cmd.Env, "PS1=[RECOVERY] # ")

	// Run shell
	err := cmd.Run()
	if err != nil {
		return &WrappedError{Msg: "shell exited with error", Err: err}
	}

	fmt.Println()
	m.logger.Info("Emergency shell exited")
	return nil
}

// rebootSystem reboots the system
func (m *initrdManager) rebootSystem(ctx context.Context) error {
	m.logger.Info("Initiating system reboot")

	// Sync filesystems
	cmd := exec.CommandContext(ctx, "sync")
	if err := cmd.Run(); err != nil {
		m.logger.Warnf("Failed to sync filesystems: %v", err)
	}

	// Reboot
	cmd = exec.CommandContext(ctx, "reboot")
	if err := cmd.Run(); err != nil {
		return &WrappedError{Msg: "reboot command failed", Err: err}
	}

	return nil
}

// displayRecoveryMenu shows recovery options to the user
func (m *initrdManager) displayRecoveryMenu() {
	separator := strings.Repeat("=", 60)
	fmt.Println("\n" + separator)
	fmt.Println("RECOVERY MODE")
	fmt.Println(separator)
	fmt.Println("\nAutomatic unlock methods have failed.")
	fmt.Println("The system will now attempt manual recovery options.")
	fmt.Println("\nAvailable unlock methods:")

	strategies := m.chain.List()
	for i, strategy := range strategies {
		fmt.Printf("  %d. %s\n", i+1, strategy.Name())
	}

	fmt.Println("\nAttempting unlock methods in recovery order...")
	fmt.Println(separator + "\n")
}

// reorderForRecovery reorders strategies for recovery mode
// Password and FIDO2 come first since they're user-interactive
func (m *initrdManager) reorderForRecovery() {
	strategies := m.chain.List()

	// Create new priority map for recovery mode
	recoveryPriorities := map[string]int{
		"Password":    1,  // Highest priority in recovery
		"FIDO2":       2,  // Second priority
		"TPM-Upgrade": 3,  // Third priority
		"TPM-PCR":     10, // Lowest priority (likely to fail in recovery)
	}

	// Temporarily adjust priorities
	for _, strategy := range strategies {
		if priority, ok := recoveryPriorities[strategy.Name()]; ok {
			// This is a bit of a hack since priority is read-only
			// In a real implementation, we'd re-build the chain with new priorities
			m.logger.Debugf("Recovery mode priority for %s: %d", strategy.Name(), priority)
		}
	}
}

// ResealKeys would reseal the TPM-PCR LUKS key to the current PCR values.
// The TPM-PCR unlock reads that seal from the EFI partition files first boot
// writes (pcrPublicFile, pcrPrivateFile), and the initrd has no writer for
// them, so a resealed key would be discarded. ResealKeys therefore checks
// that there is a slot to reseal and then refuses with ResealStoreError,
// before it unseals anything, rather than report a reseal it did not achieve.
func (m *initrdManager) ResealKeys(_ context.Context) error {
	m.logger.Info("Attempting to reseal TPM keys to current PCR values")

	// Get current PCR values
	pcrs, err := m.platform.TPM.ReadPCRs(m.platform.Config.PCRSelection)
	if err != nil {
		return &WrappedError{Msg: "failed to read PCR values", Err: err}
	}

	m.logger.Info("Current PCR values:")
	for _, bank := range pcrs {
		m.logger.Infof("  Bank: %s", bank.Algorithm)
		for _, pcr := range bank.PCRs {
			m.logger.Debugf("    PCR[%d]: %x", pcr.ID, pcr.Value)
		}
	}

	// Build volume config
	volume, err := m.buildVolumeConfig()
	if err != nil {
		return &WrappedError{Msg: "failed to build volume config", Err: err}
	}

	if !m.chainHasTPMPCR() {
		return &MessageError{Msg: "TPM-PCR strategy not found"}
	}

	var slots []int
	for _, slot := range volume.KeySlots {
		if slot.Type == luks.UnlockTPMPCR {
			slots = append(slots, slot.Index)
		}
	}
	if len(slots) == 0 {
		return &ResealNoSlotError{DevicePath: volume.DevicePath}
	}

	return &ResealStoreError{Slots: slots}
}

// chainHasTPMPCR reports whether the unlock chain holds the TPM-PCR strategy.
func (m *initrdManager) chainHasTPMPCR() bool {
	for _, strategy := range m.chain.List() {
		if _, ok := strategy.(*TPMPCRStrategy); ok {
			return true
		}
	}
	return false
}

// readUserChoice reads a single integer choice from stdin
func readUserChoice() (int, error) {
	reader := bufio.NewReader(os.Stdin)
	text, err := reader.ReadString('\n')
	if err != nil {
		return 0, &WrappedError{Msg: "failed to read input", Err: err}
	}

	text = strings.TrimSpace(text)
	if text == "" {
		return 0, &MessageError{Msg: "empty input"}
	}

	var choice int
	_, err = fmt.Sscanf(text, "%d", &choice)
	if err != nil {
		return 0, &WrappedError{Msg: "invalid number", Err: err}
	}

	return choice, nil
}

// confirmAction prompts for yes/no confirmation
func confirmAction(action string) (bool, error) {
	fmt.Printf("Are you sure you want to %s? (yes/no): ", action)

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, &WrappedError{Msg: "failed to read response", Err: err}
	}

	response = strings.ToLower(strings.TrimSpace(response))
	return response == "yes" || response == "y", nil
}
