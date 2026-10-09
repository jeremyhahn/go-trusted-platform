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

package firstboot

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

// TPMType represents the type of TPM device
type TPMType int

const (
	// HardwareTPM represents a physical TPM device
	HardwareTPM TPMType = iota

	// SoftwareTPM represents a software TPM (swtpm)
	SoftwareTPM
)

func (t TPMType) String() string {
	switch t {
	case HardwareTPM:
		return "hardware"
	case SoftwareTPM:
		return "software"
	default:
		return "unknown"
	}
}

// PlatformConfig represents the platform configuration file structure.
// This is a minimal subset of the full platformd config used for TPM initialization.
type PlatformConfig struct {
	TPM *xkmssdk.TPMConfig `yaml:"tpm"`
}

// tpmConfigRaw is used for YAML unmarshaling to handle the keystore/platform-srk
// key mismatch between config files and the xkmssdk.TPMConfig struct.
type tpmConfigRaw struct {
	xkmssdk.TPMConfig `yaml:",inline"`
	// Keystore is the legacy YAML key used in all config files.
	// The struct field PlatformSRK uses yaml:"platform-srk" but configs use "keystore:".
	Keystore *xkmssdk.PlatformSRKConfig `yaml:"keystore"`
}

// unmarshalTPMConfig unmarshals YAML data into a xkmssdk.TPMConfig, handling the
// keystore/platform-srk key mismatch.
func unmarshalTPMConfig(data []byte) (*xkmssdk.TPMConfig, error) {
	var wrapper struct {
		TPM *tpmConfigRaw `yaml:"tpm"`
	}
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, err
	}
	if wrapper.TPM == nil {
		return nil, nil
	}
	cfg := &wrapper.TPM.TPMConfig
	// If PlatformSRK wasn't set via "platform-srk:" but "keystore:" was provided, use it
	if cfg.PlatformSRK == nil && wrapper.TPM.Keystore != nil {
		cfg.PlatformSRK = wrapper.TPM.Keystore
	}
	return cfg, nil
}

// Executor executes firstboot operations including TPM initialization and key sealing.
type Executor struct {
	tpm     xkmssdk.TrustedPlatformModule
	backend xkmssdk.TPMKeyBackend
	logger  *logging.Logger
	config  *Config
}

// rootDevice returns the LUKS-encrypted root partition the executor was
// configured for, or "" when no configuration was supplied. The EFI
// partition is located relative to it (see pkg/partition).
func (e *Executor) rootDevice() string {
	if e.config == nil {
		return ""
	}
	return e.config.LuksDevice
}

// NewExecutor creates a new Executor with TPM module initialized.
// It loads TPM configuration from the platform config file and initializes the TPM.
func NewExecutor(ctx context.Context, config *Config, logger *logging.Logger) (*Executor, error) {
	if config == nil {
		config = DefaultConfig()
	}
	if logger == nil {
		logger = logging.DefaultLogger()
	}

	logger.Info("Initializing firstboot executor")

	// Detect TPM device path
	tpmDevice, err := detectTPMDevice(logger)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to detect TPM device", Err: err}
	}
	logger.Info("Detected TPM device", "path", tpmDevice)

	// Load TPM configuration from available sources
	tpmConfig, err := loadTPMConfig(logger)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to load TPM configuration", Err: err}
	}

	// Override device path with detected value
	tpmConfig.Device = tpmDevice
	tpmConfig.UseSimulator = false
	tpmConfig.UseEntropy = false
	tpmConfig.FileIntegrity = []string{}

	srkHandle := "none"
	if tpmConfig.PlatformSRK != nil {
		srkHandle = fmt.Sprintf("0x%08x", tpmConfig.PlatformSRK.SRKHandle)
	}
	ssrkHandle := "none"
	if tpmConfig.SSRK != nil {
		ssrkHandle = fmt.Sprintf("0x%08x", tpmConfig.SSRK.Handle)
	}
	logger.Info("Using TPM config",
		"platform_pcr", tpmConfig.PlatformPCR,
		"platform_pcr_bank", tpmConfig.PlatformPCRBank,
		"keystore_srk_handle", srkHandle,
		"ssrk_handle", ssrkHandle)

	// Initialize TPM module with retry logic
	tpmModule, backend, err := initializeTPM(tpmConfig, logger)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to initialize TPM", Err: err}
	}

	return &Executor{
		tpm:     tpmModule,
		backend: backend,
		logger:  logger,
		config:  config,
	}, nil
}

// Run executes the firstboot workflow.
// This performs first-boot TPM PCR sealing workflow:
//  1. Check if already sealed (seal-platform.pub/priv exist) - skip if so
//  2. Detect TPM type (hardware vs software)
//  3. Read plain LUKS key from installer container or plain key file
//  4. Read current PCR values
//  5. Create PCR-sealed objects (if hardware TPM) or non-PCR sealed (if swtpm)
//  6. Write sealed objects to EFI partition
//  7. Delete plain key file for security
//  8. Create PCR banks file (if using PCR sealing)
//  9. Save PCR values for debugging
//  10. Copy swtpm state to EFI partition (if using swtpm)
//  11. Optionally remove password keyslot
//  12. Create platform initialized marker
func (e *Executor) Run(ctx context.Context) error {
	e.logger.Info("Starting firstboot TPM sealing workflow")

	// Check for re-seal condition: upgrade seals exist (TPM-Upgrade was used)
	resealNeeded := false
	_, errPub := os.Stat(EFISealUpgradePub)
	_, errPriv := os.Stat(EFISealUpgradePriv)
	if errPub == nil && errPriv == nil {
		e.logger.Info("Upgrade seals found on EFI partition - PCR re-sealing required")
		e.logger.Info("This indicates TPM-Upgrade was used (PCR seals failed during boot)")
		resealNeeded = true
	}

	// Check if already sealed by looking for the actual sealed objects (not a marker file)
	if !resealNeeded && e.isTPMSealed() {
		e.logger.Info("TPM already sealed (seal-platform.pub/priv exist), skipping")
		return nil
	}

	// Check if TPM auto-unseal is enabled
	if !e.config.TPMAutoUnseal {
		e.logger.Info("TPM auto-unseal is disabled, skipping sealing")
		if err := e.createMarkerFile(); err != nil {
			return &WrappedError{Msg: "failed to create marker file", Err: err}
		}
		return nil
	}

	// Detect TPM type
	detector := NewTPMDetector(e.logger)
	tpmType, _, shouldStop, err := detector.DetectOrStartTPM(e.config.SwtpmStateDir)
	if err != nil {
		return &WrappedError{Msg: "TPM detection failed", Err: err}
	}

	var swtpmCmd *exec.Cmd
	if shouldStop {
		// Start swtpm in background
		swtpmCmd, err = e.startSwtpm(e.config.SwtpmStateDir)
		if err != nil {
			return &WrappedError{Msg: "failed to start swtpm", Err: err}
		}
		defer e.stopSwtpm(swtpmCmd)

		// Update tpm device path
		tpmDevice := e.config.SwtpmStateDir + "/swtpm.sock"

		// Wait for socket to be created
		if err := e.waitForSocket(tpmDevice, 3*time.Second); err != nil {
			return &WrappedError{Msg: "swtpm socket not created", Err: err}
		}

		e.logger.Info("Software TPM started successfully")
	}

	// Determine if PCR sealing should be used
	usePCRSealing := tpmType == HardwareTPM
	if tpmType == SoftwareTPM {
		e.logger.Info("In-guest swtpm detected - PCR sealing will be DISABLED")
		e.logger.Warn("TPM auto-unlock enabled, but no boot integrity protection")
	} else {
		e.logger.Info("Hardware TPM detected - PCR sealing will be ENABLED")
		e.logger.Infof("PCR registers: %v", e.config.PCRSelection)
	}

	// Ensure EFI partition is mounted BEFORE trying to read key files from it
	e.logger.Info("Mounting EFI partition to access key files...")
	if err := e.ensureEFIMounted(e.config.EFIMountPoint); err != nil {
		return &WrappedError{Msg: "failed to mount EFI partition", Err: err}
	}

	// Check if initrd already sealed (Platform SRK seal files exist on EFI)
	if !resealNeeded {
		sealPubPath := filepath.Join(e.config.EFIMountPoint, "tpm2", "seal-platform.pub")
		sealPrivPath := filepath.Join(e.config.EFIMountPoint, "tpm2", "seal-platform.priv")
		_, errPub := os.Stat(sealPubPath)
		_, errPriv := os.Stat(sealPrivPath)
		if errPub == nil && errPriv == nil {
			e.logger.Info("Platform SRK seal files already exist on EFI - initrd already sealed")
			e.logger.Info("Creating marker file and skipping sealing")
			if err := e.createMarkerFile(); err != nil {
				e.logger.Warnf("Failed to create marker file: %v", err)
			}
			return nil
		}
	}

	// Read LUKS key - from installer container (new), plain key file (legacy), or upgrade seals (re-seal)
	var key []byte
	var recoveryKey string
	var configData []byte

	if resealNeeded {
		// Re-sealing: Read key from existing upgrade seals
		e.logger.Info("Re-sealing: Reading key from upgrade seal files on EFI partition...")
		var readErr error
		key, readErr = e.readKeyFromUpgradeSeals(ctx)
		if readErr != nil {
			return &WrappedError{Msg: "failed to read key from upgrade seals", Err: readErr}
		}
		e.logger.Info("Successfully read LUKS key from upgrade seals (32 bytes)")
	} else {
		// Initial firstboot: Try encrypted installer container first (new approach)
		// Fall back to plain key file for backwards compatibility

		if _, err := os.Stat(EFIInstallerFile); err == nil {
			// New approach: Extract keys from encrypted installer container
			e.logger.Info("Found encrypted installer container - extracting keys...")
			e.logger.Info("Installer container provides forensic protection against SSD spare block recovery")

			var extractErr error
			key, recoveryKey, configData, extractErr = e.extractKeysFromInstaller(ctx, EFIInstallerFile)
			if extractErr != nil {
				return &WrappedError{Msg: "failed to extract keys from installer", Err: extractErr}
			}

			e.logger.Info("Successfully extracted LUKS key from installer (32 bytes)")
			if recoveryKey != "" {
				e.logger.Info("Recovery key extracted from installer")
			}
			if configData != nil {
				e.logger.Infof("Config extracted from installer (%d bytes)", len(configData))
			}

			// Secure wipe the installer container after extraction
			e.logger.Info("Secure wiping installer container...")
			if err := e.secureWipeInstaller(EFIInstallerFile); err != nil {
				e.logger.Warnf("Failed to secure wipe installer: %v", err)
				// Try to at least delete it
				if rmErr := os.Remove(EFIInstallerFile); rmErr != nil {
					e.logger.Warnf("Failed to delete installer: %v", rmErr)
				}
			} else {
				e.logger.Info("Installer securely wiped - FORENSIC PROTECTION ACHIEVED")
			}
		} else {
			// No encrypted installer container found - installation may have failed
			// SECURITY: We no longer support plain key files on the EFI partition
			return &SentinelCauseError{Sentinel: ErrNoLUKSKey, Cause: &MessageError{Msg: fmt.Sprintf("encrypted installer container not found at %s - installation may have failed", EFIInstallerFile)}}
		}

		if len(key) != 32 {
			return &SentinelCauseError{Sentinel: ErrInvalidKeySize, Cause: &MessageError{Msg: fmt.Sprintf("got %d bytes", len(key))}}
		}
	}

	defer func() {
		// Clear key from memory
		for i := range key {
			key[i] = 0
		}
	}()

	// Create EFI TPM directory (EFI already mounted above)
	if err := os.MkdirAll(EFITPMDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create EFI TPM directory", Err: err}
	}

	// Flush TPM transient objects to free memory
	e.logger.Info("Flushing TPM transient objects...")
	e.flushTPMContext()

	// Always create non-PCR sealed objects for TPM-Upgrade strategy
	e.logger.Info("Creating non-PCR sealed objects for TPM-Upgrade strategy...")
	upgradePub, upgradePriv, err := e.createSealedObjects(ctx, key)
	if err != nil {
		return &WrappedError{Msg: "failed to create upgrade sealed objects", Err: err}
	}
	e.logger.Info("Upgrade sealed objects created successfully (no PCR policy)")

	// Write upgrade sealed objects to EFI partition
	e.logger.Info("Writing upgrade sealed objects to EFI partition...")
	if err := e.writeUpgradeSealedObjects(upgradePub, upgradePriv); err != nil {
		return &WrappedError{Msg: "failed to write upgrade sealed objects", Err: err}
	}

	// Create PCR-sealed objects if using hardware TPM
	var sealPub, sealPriv []byte
	if usePCRSealing {
		e.logger.Info("Creating PCR-sealed objects with PCR policy...")
		sealPub, sealPriv, err = e.createPCRSealedObjects(ctx, key, e.config.PCRSelection)
		if err != nil {
			return &WrappedError{Msg: "failed to create PCR-sealed objects", Err: err}
		}
		e.logger.Info("PCR-sealed objects created successfully")

		// Write PCR-sealed objects to EFI partition
		e.logger.Info("Writing PCR-sealed objects to EFI partition...")
		if err := e.writeSealedObjects(sealPub, sealPriv); err != nil {
			return &WrappedError{Msg: "failed to write sealed objects", Err: err}
		}
	} else {
		// For software TPM, use the upgrade seals as the primary seals too
		e.logger.Info("Software TPM - using upgrade seals as primary (no PCR policy)")
		sealPub = upgradePub
		sealPriv = upgradePriv

		// Write to primary seal location (same as upgrade for swtpm)
		e.logger.Info("Writing sealed objects to EFI partition...")
		if err := e.writeSealedObjects(sealPub, sealPriv); err != nil {
			return &WrappedError{Msg: "failed to write sealed objects", Err: err}
		}
	}

	// Create SECURE Platform KeyStore sealed objects for production runtime
	if usePCRSealing {
		e.logger.Info("Creating SECURE Platform KeyStore sealed objects...")
		e.logger.Info("This is the production seal with PlatformPCR policy + password protection")

		platformPub, platformPriv, err := e.createPlatformKeystoreSealedObjects(ctx, key)
		if err != nil {
			e.logger.Errorf("Failed to create Platform KeyStore sealed objects: %v", err)
			e.logger.Warn("System will only have SSRK seals (less secure)")
			e.logger.Warn("Verify platform provisioning completed and PCR 23 was extended")
		} else {
			// Write Platform KeyStore sealed objects to EFI partition
			e.logger.Info("Writing Platform KeyStore sealed objects to EFI partition...")
			if err := e.writePlatformKeystoreSealedObjects(platformPub, platformPriv); err != nil {
				e.logger.Errorf("Failed to write Platform KeyStore sealed objects: %v", err)
				e.logger.Warn("System will only have SSRK seals (less secure)")
			} else {
				e.logger.Info("Platform KeyStore sealed objects created successfully")
				e.logger.Info("SECURITY: System is now protected with PCR 23 policy + password")
			}
		}
	} else {
		e.logger.Info("Software TPM - skipping Platform KeyStore seals (not applicable)")
	}

	// SECURITY NOTE: The LUKS key is NEVER stored in plaintext on the EFI partition.
	// It only exists inside the encrypted installer.luks container which was already
	// securely wiped above. No additional key cleanup needed.
	e.logger.Info("Key cleanup complete - installer container was securely wiped")

	// Create PCR banks file if using PCR sealing
	if usePCRSealing {
		if err := e.writePCRBanks(e.config.PCRSelection); err != nil {
			return &WrappedError{Msg: "failed to write PCR banks file", Err: err}
		}
		e.logger.Info("PCR protection enabled - boot integrity will be verified")
	} else {
		// Remove PCR banks file to disable PCR verification
		os.Remove(EFIPCRBanks)
		e.logger.Info("No PCR banks file (in-guest swtpm - no PCR verification)")
	}

	// Save PCR values for debugging
	e.logger.Info("Saving PCR values at seal time for debugging...")
	if err := e.savePCRValues(e.config.PCRSelection); err != nil {
		e.logger.Warnf("Failed to save PCR values: %v", err)
	}

	// Save debug information if enabled
	if e.config.Debug {
		e.logger.Debug("Saving debug information...")
		e.saveDebugInfo()
	}

	// Copy swtpm state to EFI partition if using swtpm
	if tpmType == SoftwareTPM {
		e.logger.Info("Copying swtpm state to EFI partition...")
		if err := e.copySwtpmState(e.config.SwtpmStateDir); err != nil {
			e.logger.Warnf("Failed to copy swtpm state: %v", err)
		}
	}

	// Sync to ensure data is written to disk. One call, not three spaced by half
	// a second: sync(2) returns only once writeback has completed, so the second
	// and third calls had nothing left to write and the sleeps between them were
	// waiting on finished work. Calling the syscall directly also drops a fork
	// of /bin/sync whose exit status was being discarded.
	e.logger.Debug("Syncing filesystem...")
	unix.Sync()

	// Handle password keyslot removal if configured
	if e.config.LuksTPMOnly {
		e.logger.Info("Removing password keyslot from LUKS device (TPM-only unlock)...")
		if err := e.removeLuksPasswordKeyslot(e.config.LuksDevice, key); err != nil {
			e.logger.Warnf("Failed to remove password keyslot: %v", err)
		} else {
			e.logger.Info("Successfully removed password keyslot - system is now TPM-only")
		}
	} else {
		e.logger.Info("Keeping password keyslot as fallback")
		e.logger.Info("System can be unlocked with either TPM or password")
	}

	// Create marker file
	if err := e.createMarkerFile(); err != nil {
		return &WrappedError{Msg: "failed to create marker file", Err: err}
	}

	// Write recovery key to root filesystem (if extracted from installer container)
	if recoveryKey != "" {
		e.logger.Info("Writing recovery key to root filesystem...")
		if err := e.writeRecoveryKey(recoveryKey); err != nil {
			e.logger.Warnf("Failed to write recovery key: %v", err)
		}
	}

	// Write config data to platform directory (if extracted from installer container)
	if len(configData) > 0 {
		platformConfigPath := "/var/lib/trusted-platform/config.yaml"
		etcConfigPath := "/etc/trusted-platform/config.yaml"

		// Write to platform directory
		if err := os.MkdirAll(filepath.Dir(platformConfigPath), 0755); err == nil {
			if err := os.WriteFile(platformConfigPath, configData, 0644); err != nil {
				e.logger.Warnf("Failed to write config to %s: %v", platformConfigPath, err)
			} else {
				e.logger.Info("Config written to", "path", platformConfigPath)
			}
		}

		// Write to /etc/trusted-platform/ as well if not already present
		if _, err := os.Stat(etcConfigPath); os.IsNotExist(err) {
			if err := os.MkdirAll(filepath.Dir(etcConfigPath), 0755); err == nil {
				if err := os.WriteFile(etcConfigPath, configData, 0644); err != nil {
					e.logger.Warnf("Failed to write config to %s: %v", etcConfigPath, err)
				} else {
					e.logger.Info("Config written to", "path", etcConfigPath)
				}
			}
		}
	}

	// Install and enable platformd service
	if err := e.installPlatformdService(e.config.Debug); err != nil {
		e.logger.Warnf("Failed to install platformd service: %v", err)
	}

	// Gateway-role nodes also get gatewayd (#66): the OpenRC script, the
	// config projected from the platform config, and enablement. An
	// identity gap for the control-plane reporter is reported, not fatal.
	if err := e.installGatewaydService(configData); err != nil {
		var identity *ErrGatewaydIdentityMissing
		if errors.As(err, &identity) {
			e.logger.Warn("gatewayd installed without its control-plane identity", "error", err)
		} else {
			e.logger.Warnf("Failed to install gatewayd service: %v", err)
		}
	}

	if usePCRSealing {
		e.logger.Info("TPM sealing complete - PCR-sealed objects created")
		e.logger.Info("PCR protection enabled - boot integrity will be verified on unlock")

		// We do NOT auto-reboot here. The seal blobs are now on the EFI
		// partition; the LUKS root is already unlocked on this boot via
		// the keyfile fallback path; platformd is running. The next
		// *natural* reboot will exercise TPM-PCR unseal — on success the
		// keyfile is no longer needed and the upgrade seals get cleaned
		// up by the initrd; on failure the keyfile fallback continues
		// to cover us with zero operational impact.
		//
		// Auto-rebooting "to verify" was a self-defeating loop on
		// hardware where PCR 9 differs between the installer initramfs
		// and the production initramfs (X10/SLB9665 in particular):
		// every verify-reboot would TPM-PCR-fail, fall through to
		// keyfile, fire another verify-reboot, repeat indefinitely. The
		// keyfile-fallback path that just unlocked us this boot IS the
		// proof the system is operational. Verification is deferred to
		// the next operator-initiated reboot.
		if !resealNeeded {
			e.logger.Info("Seal staged. TPM-PCR unlock will be attempted on next natural reboot.")
			e.logger.Info("If TPM-PCR succeeds, upgrade seals will be auto-deleted by initrd.")
			e.logger.Info("If TPM-PCR fails, keyfile fallback continues to cover the unlock path.")
		} else {
			e.logger.Info("Re-seal staged. Next natural reboot will exercise the new PCR seal.")
		}
	} else {
		e.logger.Info("TPM sealing complete - sealed objects created (no PCR policy)")
		e.logger.Info("TPM auto-unlock enabled, but no boot integrity protection")
	}

	return nil
}

// Close closes the TPM module and releases resources.
func (e *Executor) Close() error {
	if e.tpm != nil {
		return e.tpm.Close()
	}
	return nil
}

// TPM returns the TPM module for external access.
func (e *Executor) TPM() xkmssdk.TrustedPlatformModule {
	return e.tpm
}

// Backend returns the TPM key backend used for sealed-object persistence.
func (e *Executor) Backend() xkmssdk.TPMKeyBackend {
	return e.backend
}

// Config returns the executor configuration.
func (e *Executor) Config() *Config {
	return e.config
}

// triggerReboot initiates a system reboot after a short delay
// rebootAnnounceDelay is the pause between logging that a reboot is imminent and
// performing it, so an operator watching the console can read the reason. It
// bounds nothing and waits for nothing; there is no event, because the machine
// is about to stop executing.
const rebootAnnounceDelay = 5 * time.Second

// swtpmShutdownGrace is how long swtpm is given to exit on SIGINT before it is
// killed. Unlike the delays above this IS a bound on an observable event — the
// process exiting — and the code waits for that event, using this only to decide
// when to stop being patient.
const swtpmShutdownGrace = 500 * time.Millisecond

func (e *Executor) triggerReboot() {
	e.logger.Info("Initiating system reboot in 5 seconds...")

	// Sync filesystems first — once; see the note in writeSealedState.
	unix.Sync()

	// Schedule reboot
	go func() {
		// An announcement delay, not a wait for anything: the log line above
		// promises five seconds so an operator watching the console can see
		// what is about to happen. There is no condition to observe, because
		// what follows is the machine going away.
		<-time.After(rebootAnnounceDelay)
		e.logger.Info("Rebooting NOW to verify PCR-sealed LUKS key...")

		// Try systemctl first (systemd)
		if err := exec.Command("systemctl", "reboot").Run(); err != nil {
			// Fall back to reboot command
			if err := exec.Command("reboot").Run(); err != nil {
				e.logger.Errorf("Failed to reboot: %v", err)
				e.logger.Errorf("MANUAL REBOOT REQUIRED to verify PCR seals!")
			}
		}
	}()
}

// getPlatformKeystoreSRKHandle returns the Platform KeyStore SRK handle from TPM config
func (e *Executor) getPlatformKeystoreSRKHandle() xkmssdk.TPMHandle {
	if e.tpm != nil {
		config := e.tpm.Config()
		if config != nil && config.PlatformSRK != nil && config.PlatformSRK.SRKHandle != 0 {
			return xkmssdk.TPMHandle(config.PlatformSRK.SRKHandle)
		}
	}
	return xkmssdk.TPMHandle(0x81000002)
}

// getPlatformPolicy returns whether platform policy (PCR binding) is enabled
func (e *Executor) getPlatformPolicy() bool {
	if e.tpm != nil {
		config := e.tpm.Config()
		if config != nil && config.PlatformSRK != nil {
			return config.PlatformSRK.PlatformPolicy
		}
	}
	return true
}

// getSSRKHandle returns the Shared SRK handle from TPM config
func (e *Executor) getSSRKHandle() xkmssdk.TPMHandle {
	if e.tpm != nil {
		config := e.tpm.Config()
		if config != nil && config.SSRK != nil && config.SSRK.Handle != 0 {
			return xkmssdk.TPMHandle(config.SSRK.Handle)
		}
	}
	return xkmssdk.TPMHandle(0x81000001)
}

// createPCRSealedObjects creates new sealed objects with PCR policy
func (e *Executor) createPCRSealedObjects(ctx context.Context, key []byte, pcrSelection []uint) ([]byte, []byte, error) {
	if e.tpm == nil {
		return nil, nil, ErrTPMNotAvailable
	}

	ssrkHandle := e.getSSRKHandle()

	e.logger.Info("Using SSRK for PCR-sealed LUKS key (no platform policy on parent)",
		"handle", fmt.Sprintf("0x%08x", ssrkHandle),
		"pcr_policy_on_object", true)

	srkAttrs, err := e.tpm.KeyAttributes(ssrkHandle)
	if err != nil {
		return nil, nil, &SentinelCauseError{Sentinel: ErrSSRKNotAccessible, Cause: &MessageError{Msg: fmt.Sprintf("SSRK (0x%08x) error: %v", ssrkHandle, err)}}
	}

	srkAttrs.PlatformPolicy = false

	attrs := &xkmssdk.KeyAttributes{
		CN:             "luks-root-pcr",
		KeyType:        xkmssdk.KeyTypeHMAC,
		PlatformPolicy: true,
		Parent:         srkAttrs,
	}

	sealOpts := &xkmssdk.SealOptions{
		KeyAttributes: attrs,
		Backend:       nil,
	}
	sealedData, err := e.tpm.Seal(ctx, key, sealOpts)
	if err != nil {
		return nil, nil, &WrappedError{Msg: "failed to seal key", Err: err}
	}

	return sealedData.TPMPublic, sealedData.TPMPrivate, nil
}

// createSealedObjects creates sealed objects WITHOUT PCR policy for upgrade scenarios
func (e *Executor) createSealedObjects(ctx context.Context, key []byte) ([]byte, []byte, error) {
	if e.tpm == nil {
		return nil, nil, ErrTPMNotAvailable
	}

	ssrkHandle := e.getSSRKHandle()
	e.logger.Info("Using SSRK for non-PCR upgrade seal", "handle", fmt.Sprintf("0x%08x", ssrkHandle))

	srkAttrs, err := e.tpm.KeyAttributes(ssrkHandle)
	if err != nil {
		return nil, nil, &SentinelCauseError{Sentinel: ErrSSRKNotAccessible, Cause: &MessageError{Msg: fmt.Sprintf("SSRK (0x%08x) error: %v", ssrkHandle, err)}}
	}

	srkAttrs.PlatformPolicy = false

	attrs := &xkmssdk.KeyAttributes{
		CN:             "luks-upgrade-seal",
		KeyType:        xkmssdk.KeyTypeHMAC,
		PlatformPolicy: false,
		Parent:         srkAttrs,
	}

	sealOpts := &xkmssdk.SealOptions{
		KeyAttributes: attrs,
		Backend:       nil,
	}
	sealedData, err := e.tpm.Seal(ctx, key, sealOpts)
	if err != nil {
		return nil, nil, &WrappedError{Msg: "failed to seal key", Err: err}
	}

	return sealedData.TPMPublic, sealedData.TPMPrivate, nil
}

// platformKeystoreSealAttrs builds the sealed-object attributes for the
// Platform KeyStore seal. PlatformPolicy carries DIFFERENT meanings on the
// two attribute sets (#52): on the PARENT it selects how the SRK is
// authorized (password vs platform-policy session) — that mode is recorded
// as keystore-platform-policy in pcr-banks and replayed by the initrd; on
// the CHILD it attaches the PCR-bound auth policy to the sealed object —
// the entire point of TPM-PCR sealing — and is therefore ALWAYS true,
// independent of how the parent authorizes.
func platformKeystoreSealAttrs(parent *xkmssdk.KeyAttributes) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:             "luks-root-platform",
		KeyType:        xkmssdk.KeyTypeHMAC,
		PlatformPolicy: true,
		Parent:         parent,
	}
}

// writeSealedObjects writes the Platform SRK sealed objects to the EFI partition
func (e *Executor) writeSealedObjects(pubBlob, privBlob []byte) error {
	if err := os.WriteFile(EFISealPlatformPub, pubBlob, 0600); err != nil {
		return &WrappedError{Msg: "failed to write seal-platform.pub", Err: err}
	}

	if err := os.WriteFile(EFISealPlatformPriv, privBlob, 0600); err != nil {
		return &WrappedError{Msg: "failed to write seal-platform.priv", Err: err}
	}

	e.logger.Info("Platform SRK sealed objects copied to EFI partition")
	return nil
}

// writeUpgradeSealedObjects writes the non-PCR sealed objects for TPM-Upgrade strategy
func (e *Executor) writeUpgradeSealedObjects(pubBlob, privBlob []byte) error {
	if err := os.WriteFile(EFISealUpgradePub, pubBlob, 0600); err != nil {
		return &WrappedError{Msg: "failed to write seal-upgrade.pub", Err: err}
	}

	if err := os.WriteFile(EFISealUpgradePriv, privBlob, 0600); err != nil {
		return &WrappedError{Msg: "failed to write seal-upgrade.priv", Err: err}
	}

	e.logger.Info("Upgrade sealed objects copied to EFI partition")
	return nil
}

// createPlatformKeystoreSealedObjects creates sealed objects using Platform KeyStore SRK
func (e *Executor) createPlatformKeystoreSealedObjects(ctx context.Context, key []byte) ([]byte, []byte, error) {
	if e.tpm == nil {
		return nil, nil, ErrTPMNotAvailable
	}

	platformSRKHandle := e.getPlatformKeystoreSRKHandle()

	e.logger.Info("Creating SECURE Platform KeyStore sealed objects",
		"srk_handle", fmt.Sprintf("0x%08x", platformSRKHandle),
		"has_pcr_policy", true,
		"has_password", true)

	platformSRKAttrs, err := e.tpm.KeyAttributes(platformSRKHandle)
	if err != nil {
		return nil, nil, &SentinelCauseError{Sentinel: ErrPlatformSRKNotAccessible, Cause: &MessageError{Msg: fmt.Sprintf("handle 0x%08x error: %v", platformSRKHandle, err)}}
	}

	platformSRKAttrs.PlatformPolicy = e.getPlatformPolicy()

	attrs := platformKeystoreSealAttrs(platformSRKAttrs)

	sealOpts := &xkmssdk.SealOptions{
		KeyAttributes: attrs,
		Backend:       nil,
	}
	sealedData, err := e.tpm.Seal(ctx, key, sealOpts)
	if err != nil {
		return nil, nil, &WrappedError{Msg: "failed to seal key to Platform KeyStore", Err: err}
	}

	e.logger.Info("Platform KeyStore sealed objects created successfully",
		"security", "PCR 23 policy + password required to unseal")

	return sealedData.TPMPublic, sealedData.TPMPrivate, nil
}

// writePlatformKeystoreSealedObjects writes the Platform KeyStore sealed objects to EFI partition
func (e *Executor) writePlatformKeystoreSealedObjects(pubBlob, privBlob []byte) error {
	if err := os.WriteFile(EFISealPlatformPub, pubBlob, 0600); err != nil {
		return &WrappedError{Msg: "failed to write seal-platform.pub", Err: err}
	}

	if err := os.WriteFile(EFISealPlatformPriv, privBlob, 0600); err != nil {
		return &WrappedError{Msg: "failed to write seal-platform.priv", Err: err}
	}

	e.logger.Info("Platform KeyStore sealed objects copied to EFI partition",
		"pub", EFISealPlatformPub,
		"priv", EFISealPlatformPriv)
	return nil
}

// readKeyFromUpgradeSeals reads the LUKS key from existing upgrade seal files
func (e *Executor) readKeyFromUpgradeSeals(ctx context.Context) ([]byte, error) {
	if e.tpm == nil {
		return nil, ErrTPMNotAvailable
	}

	if _, err := os.Stat(EFISealUpgradePub); err != nil {
		return nil, &WrappedError{Msg: "upgrade seal public file not found", Err: err}
	}
	if _, err := os.Stat(EFISealUpgradePriv); err != nil {
		return nil, &WrappedError{Msg: "upgrade seal private file not found", Err: err}
	}

	e.logger.Info("Reading upgrade seal files from EFI partition...")

	pubBlob, err := os.ReadFile(EFISealUpgradePub)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to read upgrade seal public", Err: err}
	}
	privBlob, err := os.ReadFile(EFISealUpgradePriv)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to read upgrade seal private", Err: err}
	}

	ssrkHandle := e.getSSRKHandle()
	e.logger.Infof("Using SSRK for unseal, handle=0x%08x", ssrkHandle)

	srkAttrs, err := e.tpm.KeyAttributes(ssrkHandle)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to get SSRK attributes", Err: err}
	}

	srkAttrs.PlatformPolicy = false

	upgradeAttrs := &xkmssdk.KeyAttributes{
		CN:             "luks-upgrade-seal",
		KeyType:        xkmssdk.KeyTypeHMAC,
		PlatformPolicy: false,
		Parent:         srkAttrs,
		StoreType:      xkmssdk.StoreSoftware,
	}

	sealedData := &xkmssdk.SealedData{
		Backend:    xkmssdk.BackendTypeTPM2,
		TPMPublic:  pubBlob,
		TPMPrivate: privBlob,
	}

	e.logger.Info("Unsealing LUKS key from upgrade seals...")
	unsealOpts := &xkmssdk.UnsealOptions{
		KeyAttributes: upgradeAttrs,
		Backend:       nil,
	}
	key, err := e.tpm.Unseal(ctx, sealedData, unsealOpts)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to unseal key from upgrade seals", Err: err}
	}

	if len(key) != 32 {
		return nil, &MessageError{Msg: fmt.Sprintf("invalid key size from upgrade seals: expected 32 bytes, got %d", len(key))}
	}

	return key, nil
}

// writePCRBanks writes the extended pcr-banks file with seal PCRs and platform config
func (e *Executor) writePCRBanks(pcrSelection []uint) error {
	if len(pcrSelection) == 0 {
		return &MessageError{Msg: "seal-pcrs not configured - cannot write pcr-banks"}
	}

	if e.tpm == nil {
		return &MessageError{Msg: "TPM not initialized - cannot write pcr-banks"}
	}
	tpmConfig := e.tpm.Config()
	if tpmConfig == nil {
		return &MessageError{Msg: "TPM config not loaded - cannot write pcr-banks"}
	}
	if tpmConfig.PlatformSRK == nil {
		return &MessageError{Msg: "TPM PlatformSRK config not set - cannot write pcr-banks"}
	}
	if tpmConfig.SSRK == nil {
		return &MessageError{Msg: "TPM SSRK config not set - cannot write pcr-banks"}
	}

	var pcrStrs []string
	for _, pcr := range pcrSelection {
		pcrStrs = append(pcrStrs, fmt.Sprintf("%d", pcr))
	}
	pcrList := strings.Join(pcrStrs, ",")

	platformPCR := tpmConfig.PlatformPCR
	platformPCRBank := tpmConfig.PlatformPCRBank
	keystoreSRKHandle := tpmConfig.PlatformSRK.SRKHandle
	ssrkHandle := tpmConfig.SSRK.Handle

	var goldenPCRsStr string
	if len(tpmConfig.GoldenPCRs) > 0 {
		goldenStrs := make([]string, len(tpmConfig.GoldenPCRs))
		for i, pcr := range tpmConfig.GoldenPCRs {
			goldenStrs[i] = fmt.Sprintf("%d", pcr)
		}
		goldenPCRsStr = strings.Join(goldenStrs, ",")
	}

	// Reuse the strategy-side formatter so every pcr-banks writer records
	// keystore-platform-policy — the parent authorization mode the unseal
	// side replays instead of assuming (#52). This writer's seals are
	// created with e.getPlatformPolicy(), so that is the mode recorded.
	content := formatPCRBanksContent(pcrList, goldenPCRsStr,
		platformPCR, platformPCRBank,
		uint32(keystoreSRKHandle), e.getPlatformPolicy(), uint32(ssrkHandle))

	if err := os.WriteFile(EFIPCRBanks, []byte(content), 0644); err != nil {
		return &WrappedError{Msg: "failed to write pcr-banks", Err: err}
	}

	e.logger.Infof("PCR banks file created with platform config: seal-pcrs=%s, platform-pcr=%d, golden-pcrs=%s",
		pcrList, platformPCR, goldenPCRsStr)
	return nil
}

// savePCRValues saves the current PCR values to a debug file
func (e *Executor) savePCRValues(pcrSelection []uint) error {
	if e.tpm == nil {
		return ErrTPMNotAvailable
	}

	pcrBanks, err := e.tpm.ReadPCRs(pcrSelection)
	if err != nil {
		return &WrappedError{Msg: "failed to read PCRs", Err: err}
	}

	var output strings.Builder
	output.WriteString("PCR Values at Seal Time\n")
	output.WriteString("========================\n\n")

	for _, bank := range pcrBanks {
		fmt.Fprintf(&output, "Bank: %s\n", bank.Algorithm)
		for pcr, value := range bank.PCRs {
			fmt.Fprintf(&output, "  PCR %2d: %x\n", pcr, value)
		}
		output.WriteString("\n")
	}

	if err := os.WriteFile(EFIPCRValues, []byte(output.String()), 0644); err != nil {
		return &WrappedError{Msg: "failed to write PCR values", Err: err}
	}

	e.logger.Info("PCR values saved", "file", EFIPCRValues)
	return nil
}

// copySwtpmState copies swtpm state files to the EFI partition
func (e *Executor) copySwtpmState(swtpmStateDir string) error {
	if err := os.MkdirAll(EFISwtpmStateDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create swtpm state directory", Err: err}
	}

	entries, err := os.ReadDir(swtpmStateDir)
	if err != nil {
		return &WrappedError{Msg: "failed to read swtpm state directory", Err: err}
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()

		if strings.HasSuffix(name, ".sock") || strings.HasSuffix(name, ".sock.ctrl") {
			e.logger.Debugf("Skipping socket file: %s", name)
			continue
		}

		srcPath := filepath.Join(swtpmStateDir, name)
		dstPath := filepath.Join(EFISwtpmStateDir, name)

		data, err := os.ReadFile(srcPath)
		if err != nil {
			e.logger.Warnf("Failed to read %s: %v", name, err)
			continue
		}

		if err := os.WriteFile(dstPath, data, 0644); err != nil {
			e.logger.Warnf("Failed to write %s: %v", name, err)
			continue
		}

		e.logger.Debugf("Copied swtpm state file: %s", name)
	}

	e.logger.Info("swtpm state copied to EFI partition")
	return nil
}

// removeLuksPasswordKeyslot removes the password keyslot from the LUKS device
func (e *Executor) removeLuksPasswordKeyslot(luksDevice string, key []byte) error {
	if luksDevice == "" {
		devices := []string{"/dev/vda3", "/dev/sda3", "/dev/nvme0n1p3", "/dev/sda2", "/dev/vda2"}
		for _, dev := range devices {
			if _, err := os.Stat(dev); err == nil {
				isLuks, err := luks2.IsLUKS(dev)
				if err == nil && isLuks {
					luksDevice = dev
					break
				}
			}
		}

		if luksDevice == "" {
			return &MessageError{Msg: "no LUKS device found"}
		}
	}

	e.logger.Infof("Found LUKS device: %s", luksDevice)

	if err := luks2.KillSlot(luksDevice, key, 0); err != nil {
		return &WrappedError{Msg: "failed to remove keyslot", Err: err}
	}

	return nil
}

// ensureEFIMounted ensures the EFI partition is mounted
func (e *Executor) ensureEFIMounted(mountPoint string) error {
	cmd := exec.Command("mountpoint", "-q", mountPoint)
	if err := cmd.Run(); err == nil {
		e.logger.Debug("EFI partition already mounted")
		return nil
	}

	e.logger.Info("Mounting EFI partition...")
	cmd = exec.Command("mount", mountPoint)
	if err := cmd.Run(); err != nil {
		return &WrappedError{Msg: "failed to mount EFI partition", Err: err}
	}

	e.logger.Info("EFI partition mounted successfully")
	return nil
}

// flushTPMContext flushes transient TPM contexts to free memory
func (e *Executor) flushTPMContext() {
	if e.tpm == nil {
		return
	}
	e.logger.Debug("TPM transient objects flushed")
}

// isTPMSealed checks if the TPM has been sealed by looking for the actual sealed objects
// on the EFI partition, rather than relying on a marker file
func (e *Executor) isTPMSealed() bool {
	_, errPub := os.Stat(EFISealPlatformPub)
	_, errPriv := os.Stat(EFISealPlatformPriv)
	return errPub == nil && errPriv == nil
}

// createMarkerFile creates the platform initialized marker file
// Note: TPM sealed state is detected by presence of seal-platform.pub/priv files
func (e *Executor) createMarkerFile() error {
	platformDir := filepath.Dir(PlatformInitializedMarker)
	if err := os.MkdirAll(platformDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create platform marker directory", Err: err}
	}

	if err := os.WriteFile(PlatformInitializedMarker, []byte("initialized\n"), 0644); err != nil {
		return &WrappedError{Msg: "failed to create platform initialized marker file", Err: err}
	}
	e.logger.Info("Platform initialized marker file created", "file", PlatformInitializedMarker)

	return nil
}

// startSwtpm starts the swtpm process in the background
func (e *Executor) startSwtpm(stateDir string) (*exec.Cmd, error) {
	socketPath := filepath.Join(stateDir, "swtpm.sock")
	ctrlPath := filepath.Join(stateDir, "swtpm.sock.ctrl")

	e.logger.Info("Initializing software TPM with SHA256 PCR banks...")
	setupCmd := exec.Command("swtpm_setup",
		"--tpm2",
		"--tpmstate", stateDir,
		"--pcr-banks", "sha256",
		"--overwrite",
	)

	setupOutput, err := setupCmd.CombinedOutput()
	if err != nil {
		return nil, &CommandOutputError{Msg: "swtpm_setup failed", Err: err, Detail: fmt.Sprintf("\nOutput: %s", setupOutput)}
	}

	cmd := exec.Command("swtpm",
		"socket",
		"--tpmstate", "dir="+stateDir,
		"--ctrl", "type=unixio,path="+ctrlPath,
		"--server", "type=unixio,path="+socketPath,
		"--tpm2",
		"--flags", "not-need-init,startup-clear",
		"--log", "level=1",
	)

	if err := cmd.Start(); err != nil {
		return nil, &WrappedError{Msg: "failed to start swtpm", Err: err}
	}

	e.logger.Infof("swtpm started with PID %d", cmd.Process.Pid)
	return cmd, nil
}

// stopSwtpm stops the swtpm process
func (e *Executor) stopSwtpm(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}

	e.logger.Infof("Stopping swtpm (PID %d)...", cmd.Process.Pid)

	// Wait for the process to actually exit rather than sleeping and killing it
	// regardless. The old sequence signalled, slept 500ms, then called Kill()
	// unconditionally — so a swtpm that shut down cleanly on SIGINT was killed
	// anyway, and one that needed longer than 500ms was killed before it could.
	// Graceful shutdown was requested but never actually taken.
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		e.logger.Warn("failed to signal swtpm", "error", err)
	}

	select {
	case err := <-exited:
		if err != nil {
			e.logger.Debug("swtpm exited", "error", err)
		}
	case <-time.After(swtpmShutdownGrace):
		e.logger.Warn("swtpm did not exit on SIGINT; killing", "grace", swtpmShutdownGrace)
		if err := cmd.Process.Kill(); err != nil {
			e.logger.Warn("failed to kill swtpm", "error", err)
		}
		<-exited
	}

	e.logger.Info("swtpm stopped")
}

// waitForSocket waits for a Unix domain socket to be created
func (e *Executor) waitForSocket(socketPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	// Polling that re-checks the real condition each pass, with the wait between
	// passes on a channel. This shape is permitted precisely because it observes
	// the socket rather than assuming a duration.
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		info, err := os.Stat(socketPath)
		if err == nil && info.Mode()&os.ModeSocket != 0 {
			return nil
		}
		<-ticker.C
	}

	return &MessageError{Msg: fmt.Sprintf("timeout waiting for socket: %s", socketPath)}
}

// saveDebugInfo saves additional debug information
func (e *Executor) saveDebugInfo() {
	debugFile := EFITPMDir + "/boot-env.txt"

	var output strings.Builder
	output.WriteString("=== Boot Order ===\n")

	cmd := exec.Command("efibootmgr", "-v")
	if out, err := cmd.CombinedOutput(); err == nil {
		output.Write(out)
	} else {
		output.WriteString("efibootmgr not available\n")
	}

	output.WriteString("\n=== Secure Boot Status ===\n")

	sbPath := "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
	if data, err := os.ReadFile(sbPath); err == nil {
		fmt.Fprintf(&output, "SecureBoot: %x\n", data)
	} else {
		output.WriteString("SecureBoot variable not available\n")
	}

	os.WriteFile(debugFile, []byte(output.String()), 0644)
	e.logger.Debug("debug info saved", "file", debugFile)
}

// platformdServiceContent is the systemd service unit content for platformd
const platformdServiceContent = `[Unit]
Description=Trusted Platform :: Trusted / Confidential Computing Platform
After=network.target
Wants=network.target

[Service]
Type=simple
Restart=always
RestartSec=5s
WorkingDirectory=/var/lib/trusted-platform

# Environment file for runtime configuration (set during install)
EnvironmentFile=-/etc/trusted-platform/platformd.env

# Start the platform daemon (web services auto-start if configured)
# Platform provisioning (TPM, CA) is handled by platformd platform provision in initramfs
ExecStart=/usr/sbin/platformd serve --platform-dir=/var/lib/trusted-platform --config-dir=/etc/trusted-platform --log-dir=/var/log/trusted-platform ${PLATFORMD_DEBUG}

# Security hardening
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/trusted-platform /var/log/trusted-platform /etc/trusted-platform /var/lib/tpm2 /boot/efi

# TPM access
DeviceAllow=/dev/tpm0 rw
DeviceAllow=/dev/tpmrm0 rw

# Allow read access to TPM event log (binary_bios_measurements)
# Required for TCG-CSR-IDEVID enrollment attestation
ReadOnlyPaths=/sys/kernel/security

[Install]
WantedBy=multi-user.target
`

// platformdOpenRCScript is the OpenRC init script for Alpine Linux
const platformdOpenRCScript = `#!/sbin/openrc-run
# OpenRC init script for Trusted Platform
#
# NOTE: This service starts the full platform daemon including all API servers.
# Platform provisioning (TPM, CA) is handled by platformd platform provision in initramfs.

name="platformd"
description="Trusted Platform :: Trusted / Confidential Computing Platform"

command="/usr/sbin/platformd"
command_args="serve --platform-dir=/var/lib/trusted-platform --config-dir=/etc/trusted-platform --log-dir=/var/log/trusted-platform ${PLATFORMD_DEBUG}"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
directory="/var/lib/trusted-platform"
start_stop_daemon_args="--stdout /var/log/trusted-platform/platformd.log --stderr /var/log/trusted-platform/platformd.log"

depend() {
    need net
    after firewall charon
}

start_pre() {
    # Ensure required directories exist
    checkpath --directory --owner root:root --mode 0755 /var/log/trusted-platform
    checkpath --directory --owner root:root --mode 0755 /var/lib/trusted-platform
    checkpath --directory --owner root:root --mode 0755 /etc/trusted-platform

    # Load environment file
    if [ -f /etc/trusted-platform/platformd.env ]; then
        . /etc/trusted-platform/platformd.env
    fi
}
`

// detectInitSystem returns "openrc", "systemd", or "unknown"
func detectInitSystem() string {
	if _, err := os.Stat("/sbin/openrc-run"); err == nil {
		return "openrc"
	}
	if _, err := os.Stat("/etc/init.d"); err == nil {
		if _, err := exec.LookPath("rc-service"); err == nil {
			return "openrc"
		}
	}
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return "systemd"
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		return "systemd"
	}
	return "unknown"
}

// installPlatformdService installs and enables the platformd service
func (e *Executor) installPlatformdService(debug bool) error {
	initSystem := detectInitSystem()
	e.logger.Info("Detected init system", "type", initSystem)

	configDir := "/etc/trusted-platform"
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to create config directory %s", configDir), Err: err}
	}

	envContent := "# Trusted Platform Environment Configuration\n"
	envContent += "# Generated during firstboot installation\n\n"
	envContent += "# Debug mode flag\n"
	if debug {
		envContent += "PLATFORMD_DEBUG=\"--debug\"\n"
	} else {
		envContent += "PLATFORMD_DEBUG=\"\"\n"
	}

	envFile := configDir + "/platformd.env"
	if err := os.WriteFile(envFile, []byte(envContent), 0644); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to write environment file %s", envFile), Err: err}
	}
	e.logger.Info("Created environment file", "path", envFile, "debug", debug)

	switch initSystem {
	case "openrc":
		return e.installOpenRCService()
	case "systemd":
		return e.installSystemdService()
	default:
		e.logger.Warn("Unknown init system, attempting systemd installation")
		return e.installSystemdService()
	}
}

// installOpenRCService installs the OpenRC init script for Alpine Linux
func (e *Executor) installOpenRCService() error {
	e.logger.Info("Installing platformd OpenRC service (Alpine Linux)...")

	if err := os.MkdirAll("/var/log/trusted-platform", 0755); err != nil {
		e.logger.Warnf("Failed to create log directory: %v", err)
	}

	initScript := "/etc/init.d/platformd"
	if err := os.WriteFile(initScript, []byte(platformdOpenRCScript), 0755); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to write init script %s", initScript), Err: err}
	}
	e.logger.Info("Created OpenRC init script", "path", initScript)

	if output, err := exec.Command("rc-update", "add", "platformd", "default").CombinedOutput(); err != nil {
		return &CommandOutputError{Msg: "failed to enable platformd service", Err: err, Detail: fmt.Sprintf(" (output: %s)", string(output))}
	}
	e.logger.Info("Enabled platformd service at default runlevel")

	if output, err := exec.Command("rc-service", "platformd", "start").CombinedOutput(); err != nil {
		e.logger.Warnf("Failed to start platformd service: %v (output: %s)", err, string(output))
	} else {
		e.logger.Info("Started platformd service")
	}

	return nil
}

// installSystemdService installs the systemd service unit
func (e *Executor) installSystemdService() error {
	e.logger.Info("Installing platformd systemd service...")

	serviceFile := "/lib/systemd/system/platformd.service"
	if _, err := os.Stat("/lib/systemd/system"); os.IsNotExist(err) {
		serviceFile = "/etc/systemd/system/platformd.service"
		if err := os.MkdirAll("/etc/systemd/system", 0755); err != nil {
			return &WrappedError{Msg: "failed to create systemd directory", Err: err}
		}
	}

	if err := os.WriteFile(serviceFile, []byte(platformdServiceContent), 0644); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to write service file %s", serviceFile), Err: err}
	}
	e.logger.Info("Created systemd service file", "path", serviceFile)

	if output, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		e.logger.Warnf("Failed to reload systemd daemon: %v (output: %s)", err, string(output))
	}

	if output, err := exec.Command("systemctl", "enable", "platformd.service").CombinedOutput(); err != nil {
		return &CommandOutputError{Msg: "failed to enable platformd service", Err: err, Detail: fmt.Sprintf(" (output: %s)", string(output))}
	}
	e.logger.Info("Enabled platformd service")

	if output, err := exec.Command("systemctl", "start", "platformd.service").CombinedOutput(); err != nil {
		e.logger.Warnf("Failed to start platformd service: %v (output: %s)", err, string(output))
	} else {
		e.logger.Info("Started platformd service")
	}

	return nil
}

// extractKeysFromInstaller opens the encrypted installer container and extracts files
func (e *Executor) extractKeysFromInstaller(ctx context.Context, installerPath string) ([]byte, string, []byte, error) {
	// Clean up any leftover installer device mapper from initramfs failures
	if _, err := os.Stat("/dev/mapper/installer"); err == nil {
		e.logger.Warn("Found leftover installer device mapper from initramfs, cleaning up...")

		syscall.Unmount("/mnt/installer", 0)
		syscall.Unmount("/mnt/installer", syscall.MNT_DETACH)
		syscall.Unmount("/tmp/installer-mount", 0)
		syscall.Unmount("/tmp/installer-mount", syscall.MNT_DETACH)

		if err := luks2.Lock("installer"); err != nil {
			e.logger.Warnf("Failed to close leftover installer LUKS: %v", err)
		} else {
			e.logger.Info("Closed leftover installer LUKS container")
		}

		for i := 0; i < 8; i++ {
			loopPath := fmt.Sprintf("/dev/loop%d", i)
			if info, err := exec.Command("losetup", loopPath).Output(); err == nil {
				if strings.Contains(string(info), "installer.luks") {
					if err := exec.Command("losetup", "-d", loopPath).Run(); err == nil {
						e.logger.Infof("Detached leftover loop device %s", loopPath)
					}
				}
			}
		}

		if _, err := os.Stat("/dev/mapper/installer"); err == nil {
			e.logger.Warn("Could not fully clean up leftover installer device mapper")
		} else {
			e.logger.Info("Installer device mapper cleaned up successfully")
		}
	}

	e.logger.Info("Setting up loop device for installer...")

	loopDev, err := luks2.SetupLoopDevice(installerPath)
	if err != nil {
		return nil, "", nil, &WrappedError{Msg: "failed to setup loop device", Err: err}
	}

	e.logger.Info("Unlocking installer container...")
	if err := luks2.Unlock(loopDev, []byte(installer.InstallerPassword), "installer"); err != nil {
		luks2.DetachLoopDevice(loopDev)
		return nil, "", nil, &WrappedError{Msg: "failed to unlock installer", Err: err}
	}

	installerDevPath, err := luks2.GetMappedDevicePath("installer")
	if err != nil {
		e.logger.Warnf("GetMappedDevicePath failed, using default path: %v", err)
		installerDevPath = "/dev/mapper/installer"
	}
	e.logger.Info("Installer unlocked", "device", installerDevPath)

	mountPoint := "/tmp/installer-mount"
	if err := os.MkdirAll(mountPoint, 0700); err != nil {
		luks2.Lock("installer")
		luks2.DetachLoopDevice(loopDev)
		return nil, "", nil, &WrappedError{Msg: "failed to create mount point", Err: err}
	}

	if err := syscall.Mount(installerDevPath, mountPoint, "ext4", syscall.MS_RDONLY, ""); err != nil {
		luks2.Lock("installer")
		luks2.DetachLoopDevice(loopDev)
		return nil, "", nil, &WrappedError{Msg: "failed to mount installer", Err: err}
	}

	var luksKey []byte
	var recoveryKey string
	var configData []byte

	luksKeyPath := filepath.Join(mountPoint, "luks-key.bin")
	luksKey, err = os.ReadFile(luksKeyPath)
	if err != nil {
		syscall.Unmount(mountPoint, 0)
		luks2.Lock("installer")
		luks2.DetachLoopDevice(loopDev)
		return nil, "", nil, &WrappedError{Msg: "failed to read luks-key.bin", Err: err}
	}

	recoveryKeyInInstaller := filepath.Join(mountPoint, "recovery-key.txt")
	if recoveryData, err := os.ReadFile(recoveryKeyInInstaller); err == nil {
		recoveryKey = string(recoveryData)
	} else {
		e.logger.Info("No recovery key found in installer")
	}

	configPath := filepath.Join(mountPoint, "etc", "trusted-platform", "config.yaml")
	if data, err := os.ReadFile(configPath); err == nil {
		configData = data
	} else {
		configPath = filepath.Join(mountPoint, "config.yaml")
		if data, err := os.ReadFile(configPath); err == nil {
			configData = data
		} else {
			e.logger.Info("No config found in installer")
		}
	}

	syscall.Unmount(mountPoint, 0)
	os.Remove(mountPoint)
	luks2.Lock("installer")
	luks2.DetachLoopDevice(loopDev)

	e.logger.Info("Keys extracted from installer successfully")
	return luksKey, recoveryKey, configData, nil
}

// secureWipeInstaller securely wipes the installer container using go-luks2
func (e *Executor) secureWipeInstaller(installerPath string) error {
	e.logger.Info("Secure wiping installer container (overwrite + TRIM)...")

	wipeOpts := luks2.WipeOptions{
		Device:     installerPath,
		Passes:     1,
		Random:     true,
		HeaderOnly: false,
		Trim:       true,
	}

	if err := luks2.Wipe(wipeOpts); err != nil {
		return &WrappedError{Msg: "secure wipe failed", Err: err}
	}

	if err := os.Remove(installerPath); err != nil {
		return &WrappedError{Msg: "failed to delete installer", Err: err}
	}

	return nil
}

// writeRecoveryKey writes the recovery key to the root filesystem
func (e *Executor) writeRecoveryKey(recoveryKey string) error {
	if recoveryKey == "" {
		e.logger.Info("No recovery key to write")
		return nil
	}

	dir := filepath.Dir(RecoveryKeyPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return &WrappedError{Msg: "failed to create recovery key directory", Err: err}
	}

	if err := os.WriteFile(RecoveryKeyPath, []byte(recoveryKey), 0600); err != nil {
		return &WrappedError{Msg: "failed to write recovery key", Err: err}
	}

	e.logger.Info("Recovery key written to", "path", RecoveryKeyPath)
	e.logger.Warn("IMPORTANT: Back up this recovery key and store it securely!")

	return nil
}

// TPMDetector provides TPM type detection functionality
type TPMDetector struct {
	logger *logging.Logger
}

// NewTPMDetector creates a new TPM detector
func NewTPMDetector(logger *logging.Logger) *TPMDetector {
	return &TPMDetector{
		logger: logger,
	}
}

// DetectTPMType detects whether the system has a hardware or software TPM
func (d *TPMDetector) DetectTPMType() (TPMType, string, error) {
	swtpmSocket := "/var/lib/swtpm/swtpm.sock"
	if d.isSocket(swtpmSocket) {
		d.logger.Info("Detected software TPM (swtpm) - already running")
		d.logger.Info("In-guest swtpm detected - PCR sealing should be disabled")
		return SoftwareTPM, swtpmSocket, nil
	}

	if d.isDevice("/dev/tpmrm0") {
		d.logger.Info("Detected hardware TPM (tpmrm0)")
		return HardwareTPM, "/dev/tpmrm0", nil
	}

	if d.isDevice("/dev/tpm0") {
		d.logger.Info("Detected hardware TPM (tpm0)")
		return HardwareTPM, "/dev/tpm0", nil
	}

	return 0, "", &MessageError{Msg: "no TPM device found"}
}

// DetectOrStartTPM detects TPM and optionally starts swtpm if no hardware TPM exists
func (d *TPMDetector) DetectOrStartTPM(swtpmStateDir string) (TPMType, string, bool, error) {
	tpmType, device, err := d.DetectTPMType()
	if err == nil {
		return tpmType, device, false, nil
	}

	d.logger.Info("No TPM device found, attempting to start swtpm")

	if swtpmStateDir == "" {
		swtpmStateDir = "/var/lib/swtpm"
	}

	if err := os.MkdirAll(swtpmStateDir, 0755); err != nil {
		return 0, "", false, &WrappedError{Msg: "failed to create swtpm state directory", Err: err}
	}

	if !d.commandExists("swtpm") {
		return 0, "", false, &MessageError{Msg: "no TPM device available and swtpm not installed"}
	}

	d.logger.Info("Starting software TPM (swtpm)...")

	swtpmSocket := swtpmStateDir + "/swtpm.sock"
	swtpmCtrlSocket := swtpmStateDir + "/swtpm.sock.ctrl"

	os.Remove(swtpmSocket)
	os.Remove(swtpmCtrlSocket)

	lockFiles := []string{
		swtpmStateDir + "/.lock",
		swtpmStateDir + "/tpm2-00.permall.lock",
	}
	for _, lockFile := range lockFiles {
		os.Remove(lockFile)
	}

	return SoftwareTPM, swtpmSocket, true, nil
}

func (d *TPMDetector) isSocket(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSocket != 0
}

func (d *TPMDetector) isDevice(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeDevice != 0
}

func (d *TPMDetector) commandExists(cmd string) bool {
	_, err := os.Stat("/usr/bin/" + cmd)
	if err == nil {
		return true
	}
	_, err = os.Stat("/usr/sbin/" + cmd)
	if err == nil {
		return true
	}
	_, err = os.Stat("/sbin/" + cmd)
	return err == nil
}

// detectTPMDevice detects the TPM device path from environment or filesystem
func detectTPMDevice(logger *logging.Logger) (string, error) {
	if tpmPath := os.Getenv("TPM2TOOLS_TCTI"); tpmPath != "" {
		logger.Info("TPM2TOOLS_TCTI detected", "tcti", tpmPath)

		if after, found := strings.CutPrefix(tpmPath, "device:"); found {
			logger.Info("Stripped 'device:' prefix", "result", after)
			return after, nil
		} else if strings.HasPrefix(tpmPath, "swtpm:") {
			logger.Info("Using swtpm format as-is")
			return tpmPath, nil
		}
		logger.Info("Using TPM2TOOLS_TCTI as direct path")
		return tpmPath, nil
	}

	if _, err := os.Stat("/dev/tpmrm0"); err == nil {
		logger.Info("Found TPM device at /dev/tpmrm0")
		return "/dev/tpmrm0", nil
	}
	if _, err := os.Stat("/dev/tpm0"); err == nil {
		logger.Info("Found TPM device at /dev/tpm0")
		return "/dev/tpm0", nil
	}

	return "", ErrNoTPMDevice
}

// loadTPMConfig loads TPM configuration from available sources
func loadTPMConfig(logger *logging.Logger) (*xkmssdk.TPMConfig, error) {
	var loadedTPMConfig *xkmssdk.TPMConfig

	pcrBanksPath := "/boot/efi/tpm2/pcr-banks"
	if pcrBanksConfig := parsePCRBanksConfig(pcrBanksPath, logger); pcrBanksConfig != nil {
		loadedTPMConfig = pcrBanksConfig
		srkHandle := "none"
		if loadedTPMConfig.PlatformSRK != nil {
			srkHandle = fmt.Sprintf("0x%08x", loadedTPMConfig.PlatformSRK.SRKHandle)
		}
		logger.Info("Loaded TPM config from pcr-banks",
			"path", pcrBanksPath,
			"platform_pcr", loadedTPMConfig.PlatformPCR,
			"keystore_srk_handle", srkHandle)
		return loadedTPMConfig, nil
	}

	configPaths := []string{
		"/mnt/installer/etc/trusted-platform/config.yaml",
		"/etc/trusted-platform/config.yaml",
		"/etc/trusted-platform/platformd.yaml",
		"/boot/efi/configs/platformd.yaml",
		"/media/cdrom/configs/platformd.yaml",
	}

	for _, configPath := range configPaths {
		data, err := os.ReadFile(configPath)
		if err != nil {
			continue
		}
		tpmCfg, err := unmarshalTPMConfig(data)
		if err != nil {
			continue
		}
		if tpmCfg != nil {
			loadedTPMConfig = tpmCfg
			srkHandle := "none"
			if loadedTPMConfig.PlatformSRK != nil {
				srkHandle = fmt.Sprintf("0x%08x", loadedTPMConfig.PlatformSRK.SRKHandle)
			}
			logger.Info("Loaded platform config from file",
				"path", configPath,
				"platform_pcr", loadedTPMConfig.PlatformPCR,
				"keystore_srk_handle", srkHandle)
			return loadedTPMConfig, nil
		}
	}

	return nil, ErrNoTPMConfig
}

// parsePCRBanksConfig parses the pcr-banks file from EFI partition
func parsePCRBanksConfig(path string, logger *logging.Logger) *xkmssdk.TPMConfig {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		return nil
	}

	if !strings.Contains(content, "=") {
		logger.Warn("pcr-banks file is in old format - reinstall required")
		return nil
	}

	values := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			values[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	var platformPCR uint
	if platformPCRStr, ok := values["platform-pcr"]; ok {
		if _, err := fmt.Sscanf(platformPCRStr, "%d", &platformPCR); err != nil {
			logger.Warn("pcr-banks: invalid platform-pcr value", "value", platformPCRStr)
			return nil
		}
	} else {
		logger.Warn("pcr-banks: missing required platform-pcr")
		return nil
	}

	platformPCRBank, ok := values["platform-pcr-bank"]
	if !ok || platformPCRBank == "" {
		logger.Warn("pcr-banks: missing required platform-pcr-bank")
		return nil
	}

	var keystoreSRKHandle uint32
	if handleStr, ok := values["keystore-srk-handle"]; ok {
		if _, err := fmt.Sscanf(handleStr, "0x%x", &keystoreSRKHandle); err != nil {
			if _, err := fmt.Sscanf(handleStr, "%d", &keystoreSRKHandle); err != nil {
				logger.Warn("pcr-banks: invalid keystore-srk-handle", "value", handleStr)
				return nil
			}
		}
	} else {
		logger.Warn("pcr-banks: missing required keystore-srk-handle")
		return nil
	}

	var ssrkHandle uint32
	if handleStr, ok := values["ssrk-handle"]; ok {
		if _, err := fmt.Sscanf(handleStr, "0x%x", &ssrkHandle); err != nil {
			if _, err := fmt.Sscanf(handleStr, "%d", &ssrkHandle); err != nil {
				logger.Warn("pcr-banks: invalid ssrk-handle", "value", handleStr)
				return nil
			}
		}
	} else {
		logger.Warn("pcr-banks: missing required ssrk-handle")
		return nil
	}

	var goldenPCRs []uint
	// keystore-platform-policy: the parent authorization mode recorded at
	// seal time. Same contract as pkg/boot/commands parsePCRBanksConfig:
	// absent defaults to false (the strategy seal path's default), an
	// invalid value rejects the file (#52).
	keystorePlatformPolicy := false
	if policyStr, ok := values["keystore-platform-policy"]; ok {
		parsed, err := strconv.ParseBool(policyStr)
		if err != nil {
			logger.Warn("pcr-banks: invalid keystore-platform-policy", "value", policyStr)
			return nil
		}
		keystorePlatformPolicy = parsed
	}

	if goldenPCRsStr, ok := values["golden-pcrs"]; ok && goldenPCRsStr != "" {
		for _, pcrStr := range strings.Split(goldenPCRsStr, ",") {
			pcrStr = strings.TrimSpace(pcrStr)
			if pcrStr == "" {
				continue
			}
			var pcr uint
			if _, err := fmt.Sscanf(pcrStr, "%d", &pcr); err == nil {
				goldenPCRs = append(goldenPCRs, pcr)
			}
		}
	}

	logger.Info("Parsed pcr-banks from installer config",
		"platform_pcr", platformPCR,
		"platform_pcr_bank", platformPCRBank,
		"golden_pcrs", goldenPCRs,
		"keystore_srk_handle", fmt.Sprintf("0x%08x", keystoreSRKHandle),
		"ssrk_handle", fmt.Sprintf("0x%08x", ssrkHandle))

	defaultCfg := xkmssdk.DefaultTPMConfig
	return &xkmssdk.TPMConfig{
		Hash:            defaultCfg.Hash,
		EK:              defaultCfg.EK,
		IAK:             defaultCfg.IAK,
		IDevID:          defaultCfg.IDevID,
		PlatformPCR:     platformPCR,
		PlatformPCRBank: platformPCRBank,
		GoldenPCRs:      goldenPCRs,
		PlatformSRK: &xkmssdk.PlatformSRKConfig{
			SRKHandle:      keystoreSRKHandle,
			PlatformPolicy: keystorePlatformPolicy,
		},
		SSRK: &xkmssdk.SRKConfig{
			Handle: ssrkHandle,
		},
	}
}

// initializeTPM initializes the TPM module with retry logic.
// It creates a storage backend at /boot/efi/tpm2 for sealed key persistence.
func initializeTPM(tpmConfig *xkmssdk.TPMConfig, logger *logging.Logger) (xkmssdk.TrustedPlatformModule, xkmssdk.TPMKeyBackend, error) {
	xkmsLogger := slog.Default()

	// Create storage backend for TPM sealed keys
	// Use /boot/efi/tpm2 as the storage location for sealed blobs
	storagePath := "/boot/efi/tpm2"
	if err := os.MkdirAll(storagePath, 0700); err != nil {
		logger.Warn("Failed to create TPM storage directory", "path", storagePath, "error", err)
	}
	storageBackend, err := xkmssdk.NewFileStorageBackend(storagePath)
	if err != nil {
		logger.Warn("Failed to create storage backend, TPM sealing may not work", "error", err)
	}

	var backend xkmssdk.TPMKeyBackend
	if storageBackend != nil {
		backend = xkmssdk.NewFileBackend(xkmsLogger, storageBackend)
	}

	tpmParams := &xkmssdk.TPMParams{
		Config:       tpmConfig,
		Logger:       xkmsLogger,
		DebugSecrets: false,
		Backend:      backend,
		BlobStore:    nil,
		CertStore:    nil,
		SignerStore:  nil,
	}

	var tpmModule xkmssdk.TrustedPlatformModule
	maxRetries := 5
	retryDelay := 2 * time.Second

	for i := 0; i < maxRetries; i++ {
		tpmModule, err = xkmssdk.NewTPM2(tpmParams)
		if err == nil || err == xkmssdk.ErrTPMNotInitialized {
			if err == xkmssdk.ErrTPMNotInitialized {
				logger.Info("TPM opened successfully (not yet provisioned)", "attempt", i+1)
			} else {
				logger.Info("TPM initialized successfully", "attempt", i+1)
			}
			return tpmModule, backend, nil
		}

		if i < maxRetries-1 {
			logger.Warn("TPM initialization failed, retrying",
				"attempt", i+1,
				"max_retries", maxRetries,
				"error", err,
				"retry_delay", retryDelay)
			<-time.After(retryDelay)
		}
	}

	return nil, nil, &WrappedError{Msg: fmt.Sprintf("failed to initialize TPM2 after %d attempts", maxRetries), Err: err}
}
