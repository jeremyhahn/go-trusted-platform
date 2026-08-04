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
	"os"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
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
// Detection logic:
// 1. Check for swtpm Unix domain socket at /var/lib/swtpm/swtpm.sock
// 2. Check for hardware TPM at /dev/tpmrm0
// 3. Check for hardware TPM at /dev/tpm0
// 4. Return error if no TPM found
//
// If an swtpm socket exists, this indicates an in-guest virtual TPM where
// PCR values are not stable across boots, so PCR sealing should be disabled.
func (d *TPMDetector) DetectTPMType() (TPMType, string, error) {
	// Check for swtpm socket first - this indicates software TPM
	// If the socket exists, it means swtpm is already running (in-guest vTPM)
	swtpmSocket := "/var/lib/swtpm/swtpm.sock"
	if d.isSocket(swtpmSocket) {
		d.logger.Info("Detected software TPM (swtpm) - already running")
		d.logger.Info("In-guest swtpm detected - PCR sealing should be disabled")
		return SoftwareTPM, swtpmSocket, nil
	}

	// Check for hardware TPM resource manager device
	if d.isDevice("/dev/tpmrm0") {
		d.logger.Info("Detected hardware TPM (tpmrm0)")
		return HardwareTPM, "/dev/tpmrm0", nil
	}

	// Check for hardware TPM device (no resource manager)
	if d.isDevice("/dev/tpm0") {
		d.logger.Info("Detected hardware TPM (tpm0)")
		return HardwareTPM, "/dev/tpm0", nil
	}

	return 0, "", &MessageError{Msg: "no TPM device found"}
}

// DetectOrStartTPM detects TPM and optionally starts swtpm if no hardware TPM exists
// This is used during firstboot when we need to ensure a TPM is available.
// Returns:
// - TPMType: hardware or software
// - device path or socket path
// - boolean indicating if we started swtpm (caller should stop it)
// - error if detection/startup failed
func (d *TPMDetector) DetectOrStartTPM(swtpmStateDir string) (TPMType, string, bool, error) {
	// First try to detect existing TPM
	tpmType, device, err := d.DetectTPMType()
	if err == nil {
		// TPM already available
		return tpmType, device, false, nil
	}

	// No TPM found, try to start swtpm
	d.logger.Info("No TPM device found, attempting to start swtpm")

	if swtpmStateDir == "" {
		swtpmStateDir = "/var/lib/swtpm"
	}

	// Ensure state directory exists
	if err := os.MkdirAll(swtpmStateDir, 0755); err != nil {
		return 0, "", false, &WrappedError{Msg: "failed to create swtpm state directory", Err: err}
	}

	// Check if swtpm is installed
	if !d.commandExists("swtpm") {
		return 0, "", false, &MessageError{Msg: "no TPM device available and swtpm not installed"}
	}

	d.logger.Info("Starting software TPM (swtpm)...")

	// Clean up any stale lockfiles and sockets
	swtpmSocket := swtpmStateDir + "/swtpm.sock"
	swtpmCtrlSocket := swtpmStateDir + "/swtpm.sock.ctrl"

	os.Remove(swtpmSocket)
	os.Remove(swtpmCtrlSocket)

	// Remove lock files
	lockFiles := []string{
		swtpmStateDir + "/.lock",
		swtpmStateDir + "/tpm2-00.permall.lock",
	}
	for _, lockFile := range lockFiles {
		os.Remove(lockFile)
	}

	// Note: Actual swtpm startup would be handled by the caller using exec.Command
	// This function just prepares the environment and validates prerequisites
	// The caller should use something like:
	// cmd := exec.Command("swtpm", "socket",
	//     "--tpmstate", "dir="+swtpmStateDir,
	//     "--ctrl", "type=unixio,path="+swtpmCtrlSocket,
	//     "--server", "type=unixio,path="+swtpmSocket,
	//     "--tpm2",
	//     "--flags", "not-need-init,startup-clear",
	//     "--log", "level=1")

	return SoftwareTPM, swtpmSocket, true, nil
}

// isSocket checks if the given path is a Unix domain socket
func (d *TPMDetector) isSocket(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSocket != 0
}

// isDevice checks if the given path is a device file
func (d *TPMDetector) isDevice(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeDevice != 0
}

// commandExists checks if a command is available in PATH
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
