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

package vtpm

import (
	"fmt"
	"os"
	"strings"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/initrd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TPMDeviceAuto is the sentinel value for the tpm.device configuration key
// that requests runtime TPM detection (swtpm socket, then /dev/tpmrm0, then
// /dev/tpm0 — the same order as the initrd detector). An empty device with
// simulator disabled is treated identically.
const TPMDeviceAuto = "auto"

// TPMTarget identifies which kind of TPM the platform configuration resolves
// to. It is the single source of truth for the hardware-vs-swtpm-vs-simulator
// decision consumed by pkg/app OpenTPM, the TPMProvider, and the CLI.
type TPMTarget int

const (
	// TPMTargetHardware is a physical TPM character device (/dev/tpmrm0 or
	// /dev/tpm0).
	TPMTargetHardware TPMTarget = iota

	// TPMTargetSwtpm is a software TPM reached over a swtpm Unix domain
	// socket.
	TPMTargetSwtpm

	// TPMTargetSimulator is the in-process TPM simulator (tpm.simulator: true).
	TPMTargetSimulator
)

func (t TPMTarget) String() string {
	switch t {
	case TPMTargetHardware:
		return "hardware"
	case TPMTargetSwtpm:
		return "swtpm"
	case TPMTargetSimulator:
		return "simulator"
	default:
		return "unknown"
	}
}

// ResolvedTPMTarget is the outcome of resolving the platform TPM
// configuration: the target kind plus the concrete device or socket path the
// go-xkms transport must open. Device is empty for the in-process simulator.
type ResolvedTPMTarget struct {
	Target TPMTarget
	Device string
}

// ErrNilTPMConfig indicates ResolveTPMTarget was called without a TPM
// configuration.
type ErrNilTPMConfig struct{}

func (e ErrNilTPMConfig) Error() string {
	return "vtpm: tpm configuration is nil"
}

// ErrHardwareTPMUnavailable indicates the configuration demands a hardware
// TPM character device that is not present. The platform fails closed rather
// than silently downgrading to a software TPM.
type ErrHardwareTPMUnavailable struct {
	Device string
	Cause  error
}

func (e ErrHardwareTPMUnavailable) Error() string {
	return fmt.Sprintf("vtpm: hardware TPM device %s unavailable: %v", e.Device, e.Cause)
}

func (e ErrHardwareTPMUnavailable) Unwrap() error { return e.Cause }

// ErrSwtpmSocketUnavailable indicates the configuration demands a swtpm Unix
// domain socket that is not present. The platform fails closed rather than
// silently switching to a hardware device.
type ErrSwtpmSocketUnavailable struct {
	Socket string
	Cause  error
}

func (e ErrSwtpmSocketUnavailable) Error() string {
	return fmt.Sprintf("vtpm: swtpm socket %s unavailable: %v", e.Socket, e.Cause)
}

func (e ErrSwtpmSocketUnavailable) Unwrap() error { return e.Cause }

// ErrNoTPMDetected indicates automatic detection (tpm.device: auto) found
// neither a swtpm socket nor a hardware TPM device.
type ErrNoTPMDetected struct {
	Cause error
}

func (e ErrNoTPMDetected) Error() string {
	return fmt.Sprintf("vtpm: no TPM detected (device: auto): %v", e.Cause)
}

func (e ErrNoTPMDetected) Unwrap() error { return e.Cause }

// ErrNotCharDevice indicates the configured hardware TPM path exists but is
// not a character device.
type ErrNotCharDevice struct {
	Path string
}

func (e ErrNotCharDevice) Error() string {
	return fmt.Sprintf("vtpm: %s exists but is not a TPM character device", e.Path)
}

// ErrNotUnixSocket indicates the configured swtpm path exists but is not a
// Unix domain socket.
type ErrNotUnixSocket struct {
	Path string
}

func (e ErrNotUnixSocket) Error() string {
	return fmt.Sprintf("vtpm: %s exists but is not a unix domain socket", e.Path)
}

// ResolveTPMTarget resolves the platform tpm: configuration into a single
// explicit TPM target. It is the ONE decision point for hardware vs swtpm vs
// simulator selection:
//
//   - tpm.simulator: true        -> TPMTargetSimulator (explicit; device ignored,
//     matching go-xkms semantics)
//   - tpm.device: auto (or "")   -> runtime detection via the initrd TPM
//     detector: swtpm socket first, then
//     /dev/tpmrm0, then /dev/tpm0
//   - tpm.device: *.sock         -> TPMTargetSwtpm; the socket MUST exist
//   - tpm.device: /dev/...       -> TPMTargetHardware; the character device
//     MUST exist
//
// Explicit configuration always wins: a config that demands hardware never
// silently falls back to a software TPM (ErrHardwareTPMUnavailable) and a
// config that demands swtpm never silently opens a hardware device
// (ErrSwtpmSocketUnavailable).
func ResolveTPMTarget(cfg *xkmssdk.TPMConfig, logger *logging.Logger) (*ResolvedTPMTarget, error) {
	if cfg == nil {
		return nil, ErrNilTPMConfig{}
	}
	if logger == nil {
		logger = logging.DefaultLogger()
	}

	if cfg.UseSimulator {
		return &ResolvedTPMTarget{Target: TPMTargetSimulator}, nil
	}

	device := strings.TrimSpace(cfg.Device)
	if device == "" || strings.EqualFold(device, TPMDeviceAuto) {
		detector := initrd.NewTPMDetector(logger)
		tpmType, path, err := detector.DetectTPMType()
		if err != nil {
			return nil, ErrNoTPMDetected{Cause: err}
		}
		if tpmType == initrd.SoftwareTPM {
			return &ResolvedTPMTarget{Target: TPMTargetSwtpm, Device: path}, nil
		}
		return &ResolvedTPMTarget{Target: TPMTargetHardware, Device: path}, nil
	}

	if strings.HasSuffix(device, ".sock") {
		info, err := os.Stat(device)
		if err != nil {
			return nil, ErrSwtpmSocketUnavailable{Socket: device, Cause: err}
		}
		if info.Mode()&os.ModeSocket == 0 {
			return nil, ErrSwtpmSocketUnavailable{Socket: device, Cause: ErrNotUnixSocket{Path: device}}
		}
		return &ResolvedTPMTarget{Target: TPMTargetSwtpm, Device: device}, nil
	}

	info, err := os.Stat(device)
	if err != nil {
		return nil, ErrHardwareTPMUnavailable{Device: device, Cause: err}
	}
	if info.Mode()&os.ModeDevice == 0 {
		return nil, ErrHardwareTPMUnavailable{Device: device, Cause: ErrNotCharDevice{Path: device}}
	}
	return &ResolvedTPMTarget{Target: TPMTargetHardware, Device: device}, nil
}
