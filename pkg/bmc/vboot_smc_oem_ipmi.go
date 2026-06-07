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

package bmc

import (
	"context"
	"log/slog"
)

// vbootSmcOEMIPMI is the Supermicro OEM IPMI raw boot-override backend.
// It targets IPMI command NetFn 0x30 / Cmd 0x70 / Sub-cmd 0x0c "Set Boot
// Option Override", documented in the Supermicro Update Manager (SUM)
// reference and used by the ATEN iKVM HTML5 client when an operator
// flips boot device via the BMC web UI.
//
// WHY THIS EXISTS — X10 ATEN firmware (4.0.x) silently ignores the
// standard Redfish BootSourceOverrideTarget when the disk already has
// a UEFI "Linux" boot entry registered in NVRAM. The BIOS reads the
// override, fires its UEFI POST, sees a higher-priority NVRAM entry,
// and falls through to the disk — bypassing the CDROM/PXE target the
// operator asked for. The OEM 0x30/0x70/0x0c override path lives
// underneath the UEFI BootOrder logic and is honored even when the
// NVRAM list would otherwise win, so it's the only software path
// that works on already-provisioned X10 nodes.
//
// X10 FIRMWARE LIMITATIONS — the OEM command only accepts a narrow
// range of "next boot device" codes on this firmware revision:
//
//	0x00 — disable override (clear)
//	0x01 — force PXE
//	0x02 — force PXE (alias / state echo on this firmware)
//
// The wider set documented elsewhere (0x03 BIOS-CD, 0x05 BIOS-Setup,
// 0x12 UEFI-CD, 0x13 UEFI-HDD, 0x14 UEFI-Floppy, etc.) all return
// completion code 0x80 "Unknown" on this firmware. PXE is therefore
// the ONLY boot device this backend can route via OEM — CD and disk
// targets must fall back to the standard DMTF Redfish PATCH path
// (which works for those devices on greenfield nodes).
//
// LIFECYCLE — the backend reuses the redfishClient's stored BMC
// Config to open a short-lived RMCP+ session, sends the single OEM
// command, and tears the session down. No long-lived IPMI state is
// kept.
type vbootSmcOEMIPMI struct {
	c *redfishClient
}

// newVbootSmcOEMIPMI constructs the OEM IPMI boot-override backend.
func newVbootSmcOEMIPMI(c *redfishClient) *vbootSmcOEMIPMI {
	return &vbootSmcOEMIPMI{c: c}
}

// Supermicro OEM IPMI command for "Set Boot Option Override".
const (
	smcOEMNetFn          = 0x30
	smcOEMCmdBootOption  = 0x70
	smcOEMSubBootOverride = 0x0c
	smcOEMBootSet        = 0x01

	// Boot device override values that this X10 ATEN firmware
	// (4.0.x) accepts. Other documented values return CC=0x80
	// "Unknown" — see file doc for the rejection set.
	smcOEMBootDisable = 0x00
	smcOEMBootPXE     = 0x01

	// ipmiDefaultPort is the standard IPMI RMCP+ UDP port. The
	// redfishClient's Config carries the HTTPS port (443/8443);
	// the OEM IPMI session has to switch to 623 for the
	// underlying RMCP+ transport.
	ipmiDefaultPort = 623
)

// Name returns the stable identifier used in dispatch logs, errors,
// and quirks-registry routing (BootOverrideStrategy: "smc-oem-ipmi").
func (b *vbootSmcOEMIPMI) Name() string { return "smc-oem-ipmi" }

// SetBootDevice issues the Supermicro OEM "Set Boot Option Override"
// IPMI command via a freshly-opened RMCP+ session. The persistent
// flag is informational — the OEM override is one-shot on this
// firmware regardless, so the caller is expected to re-issue the
// override on each retry. Persistence is achieved by the orchestrator's
// retry loop, not by an underlying "Continuous" bit.
//
// Returns ErrBootOverrideUnsupported for devices the OEM command
// cannot route (currently anything other than PXE). The dispatcher
// in redfish.go.SetBootDevice falls back to the standard Redfish
// PATCH path on that signal.
func (b *vbootSmcOEMIPMI) SetBootDevice(ctx context.Context, device BootDevice, persistent bool) error {
	bootCode, ok := smcOEMBootDeviceCode(device)
	if !ok {
		return ErrBootOverrideUnsupported{
			Backend: b.Name(),
			Vendor:  "Supermicro",
			Device:  string(device),
			Reason:  "OEM IPMI 0x30/0x70/0x0c on X10 ATEN firmware accepts PXE only; other devices use Redfish PATCH",
		}
	}

	// The redfishClient was constructed with a Config whose Port
	// field is the Redfish HTTPS port (443/8443). IPMI RMCP+ lives
	// on UDP 623. Clone the Config and switch the port so the
	// session opens on the right transport. Address / Username /
	// Password / EncryptionKey are reused as-is — the BMC accepts
	// the same Redfish credentials over IPMI on the same X10/X11
	// ATEN firmware revisions we target.
	ipmiCfg := *b.c.config
	ipmiCfg.Port = ipmiDefaultPort

	session := newRMCPSession(&ipmiCfg, b.c.logger)
	if err := session.Open(ctx); err != nil {
		return ErrBootDevice{
			Device: string(device),
			Cause:  ErrConnectionFailed{Address: ipmiCfg.Endpoint(), Cause: err},
		}
	}
	defer session.Close()

	payload := []byte{smcOEMSubBootOverride, smcOEMBootSet, bootCode}
	if _, err := session.Send(smcOEMNetFn, smcOEMCmdBootOption, payload); err != nil {
		return ErrBootDevice{Device: string(device), Cause: err}
	}

	b.c.logger.Info("bmc: smc-oem-ipmi boot override set",
		slog.String("device", string(device)),
		slog.Bool("persistent", persistent),
		slog.String("oem_value", "0x01"))
	return nil
}

// smcOEMBootDeviceCode maps a BootDevice to the corresponding OEM
// "Set Boot Option Override" code byte. Returns (0, false) for any
// device this firmware cannot route via OEM — the dispatcher uses
// the false return as the signal to fall back to Redfish PATCH.
//
// Mapping rationale: this X10 ATEN firmware only honors PXE-class
// codes. UEFI-CD (0x12) and UEFI-HDD (0x13) return CC=0x80 on the
// wire, so we don't claim them here. The orchestrator's deploy
// flow on X10 SHOULD use boot_method: pxe in bootstrap.yaml when
// the deploy hardware has an existing UEFI NVRAM entry; the OEM
// override then forces PXE even when the BIOS would otherwise
// follow its NVRAM disk entry.
func smcOEMBootDeviceCode(device BootDevice) (byte, bool) {
	switch device {
	case BootDevicePXE:
		return smcOEMBootPXE, true
	case BootDeviceNone:
		return smcOEMBootDisable, true
	}
	return 0, false
}
