package quirks

// buildRegistry constructs the static vendor quirk table.
//
// To add a new vendor or board: append a new entry to the slice below.
// The match fields (all lower-case) are:
//   - manufacturer:     equality match against Redfish System.Manufacturer.
//   - model:            substring match against Redfish System.Model.
//   - partNumberPrefix: prefix match against Redfish System.PartNumber, for
//     firmware that serves a placeholder Model.
//
// Leave both model and partNumberPrefix empty for a manufacturer-wide
// default that applies when no board-specific entry matches. The most
// specific matching entry wins (exact model, then the longest matching
// key); declaration order only breaks exact ties, so a narrower entry may
// be appended after the broader one it refines.
//
// This is the ONLY place in the codebase that may contain vendor names or
// model strings. Core install/ISO paths call Resolve and act on the returned
// Quirk fields only.
func buildRegistry() []entry {
	entries := []entry{
		// ---------------------------------------------------------------
		// Supermicro — manufacturer-wide default
		//
		// Applies to all Supermicro boards not matched by a more specific
		// entry below.  X10 and X11 BMC firmware only speaks SMB1 (NT1)
		// for virtual-media mounts; SMB2 negotiation fails silently and the
		// BMC reports "ISO file does not exist".  Serial console is routed
		// to COM1 (ttyS0 / 0x3f8) on most Supermicro boards — the
		// manufacturer-wide default follows that wiring.
		//
		// Cert-backend fallback: Supermicro X10 ATEN BMCs frequently
		// advertise the Redfish CertificateService but reject uploads;
		// the documented fallback is the legacy ATEN CGI endpoint. Newer
		// X11+ firmware accepts the Redfish path. Listing both, with
		// "redfish" first, lets AutoCertManager probe the standard path
		// and fall through on 501/"not implemented".
		// ---------------------------------------------------------------
		{
			match: match{manufacturer: "supermicro"},
			quirk: Quirk{
				Manufacturer: "Supermicro",
				// Dual UART coverage matching the Supermicro default COM1
				// wiring; ttyS0 is listed last so it wins as primary.
				KernelCmdline: []string{
					"earlyprintk=efi,keep",
					"earlycon=uart8250,io,0x3f8,115200n8",
					"console=tty0",
					"console=ttyS1,115200n8",
					"console=ttyS0,115200n8",
					"loglevel=7",
				},
				SOLPort:            "ttyS0",
				SOLPayloadInstance: 0x01,
				EarlyconSpec:       "uart8250,io,0x3f8,115200n8",
				// SMB1 required for X10/X11 BMC virtual-media.
				SambaMinProtocol: "NT1",
				// Cleartext SMB — the bootstrap network is L2-only and
				// some Supermicro BMC stacks cannot negotiate SMB encryption.
				SambaEncryption: "disabled",
				// X10 ATEN BMCs advertise "CD/DVD" (with slash) for the
				// BIOS-mode virtual CD slot; the UEFI-mode slot is the
				// DMTF-spelled "UefiCd". Newer Supermicro firmware also
				// accepts these aliases.
				BootMediaType: MediaType{
					CDDVDAlias: "CD/DVD",
					// ATEN virtual media enumerates as a USB CD/DVD device, so
					// the UEFI boot target is "UefiUsbCd" — NOT "UefiCd" (the
					// empty physical/SATA optical class). Verified on X10SDV-TP8F:
					// BIOS FIXED BOOT ORDER lists the ATEN virtual CD under
					// "UEFI USB CD/DVD"; targeting "UefiCd" points the boot
					// override at the empty class and the node skips to PXE/disk.
					UEFICDAlias: "UefiUsbCd",
				},
				// Try standard Redfish CertificateService first; on
				// "unsupported" responses fall through to the legacy
				// ATEN CGI endpoint.
				CertBackendFallback: []string{
					"redfish",
					"smc-cgi",
				},
				// X10 ATEN BMC returns 404 for the standard
				// VirtualMedia.EjectMedia action; the dispatch layer
				// falls through to the SMC OEM backend on this signal.
				VmediaRedfishOEMFallback: true,
				// X10 ATEN BMC silently erases "Once" boot overrides
				// before BIOS POST sees them (the reflash trap that
				// burned lab-node-2 in the 2026-04-30 session). Continuous
				// is the only mode that survives the X10 reset cycle.
				BootOverrideContinuous: true,
				// Try the Supermicro OEM IPMI 0x30/0x70/0x0c "Set
				// Boot Option Override" before the standard Redfish
				// PATCH. The OEM path is honored by ATEN firmware even
				// when the disk has a UEFI Linux entry in NVRAM that
				// would otherwise win against BootSourceOverrideTarget.
				// On X10 the OEM command only accepts PXE on the wire
				// (other documented codes return CC=0x80); the
				// dispatcher in redfish.go falls back to Redfish PATCH
				// for non-PXE devices automatically. See
				// pkg/bmc/vboot_smc_oem_ipmi.go for the wire details.
				BootOverrideStrategy: "smc-oem-ipmi",
			},
		},

		// ---------------------------------------------------------------
		// Supermicro X10SDV-TP8F
		//
		// SOL is wired to COM1 (ttyS0 / 0x3f8) on this board, the same as
		// the manufacturer-wide entry. Measured 2026-08-29 on lab-node-2
		// (SYS-5018D-FN8T-AS001, ATEN FW 4.00): with the ISO cmdline
		// naming both UARTs and the installed UKI ending in console=ttyS0,
		// kernel printk, autoinstall (via kmsg), platform-initrd and
		// OpenRC output all appeared on IPMI SOL payload instance 0x01;
		// instance 0x02 activated successfully and stayed silent
		// throughout. The entry once said COM2 / instance 0x02 and
		// earlycon 0x2f8 — that was wrong for this board and would have
		// made the installed system silent on SOL. Both UARTs stay on
		// the cmdline; ttyS0 is last so it is /dev/console.
		//
		// Identity: the ATEN firmware on these boards (FW 4.00, BIOS 2.6)
		// serves a placeholder System.Model of "Super Server" and an SKU
		// of "To be filled by O.E.M."; the board is only named by
		// System.PartNumber. The SuperServer SKUs built on X10SDV are
		// SYS-5018D-FN8T (X10SDV-TP8F, Supermicro MNL-1868 — the mini
		// fleet, part number "SYS-5018D-FN8T-AS001") and SYS-5018D-FN4T
		// (X10SDV-TLN4F, MNL-1775), hence the "sys-5018d-fn" prefix. The
		// rest of the SYS-5018D family (-MTF, -MTLN4F, -MF) is X10SLM-F,
		// a Xeon E3 board with SOL on COM1, and must resolve to the
		// manufacturer-wide entry. The model substring stays for firmware
		// that does fill in the board name.
		// ---------------------------------------------------------------
		{
			match: match{
				manufacturer:     "supermicro",
				model:            "x10sdv",
				partNumberPrefix: "sys-5018d-fn",
			},
			quirk: Quirk{
				Manufacturer: "Supermicro",
				Model:        "X10SDV",
				KernelCmdline: []string{
					"earlyprintk=efi,keep",
					// COM1 (0x3f8): the UART SOL is wired to (see above).
					"earlycon=uart8250,io,0x3f8,115200n8",
					"console=tty0",
					"console=ttyS1,115200n8",
					// ttyS0 last → wins as primary (/dev/console).
					"console=ttyS0,115200n8",
					"loglevel=7",
				},
				// ttyS0 / 0x01 per the 2026-08-29 lab-node-2 measurement above.
				SOLPort:            "ttyS0",
				SOLPayloadInstance: 0x01,
				EarlyconSpec:       "uart8250,io,0x3f8,115200n8",
				SambaMinProtocol:   "NT1",
				SambaEncryption:    "disabled",
				BootMediaType: MediaType{
					CDDVDAlias: "CD/DVD",
					// ATEN virtual media enumerates as a USB CD/DVD device, so
					// the UEFI boot target is "UefiUsbCd" — NOT "UefiCd" (the
					// empty physical/SATA optical class). Verified on X10SDV-TP8F:
					// BIOS FIXED BOOT ORDER lists the ATEN virtual CD under
					// "UEFI USB CD/DVD"; targeting "UefiCd" points the boot
					// override at the empty class and the node skips to PXE/disk.
					UEFICDAlias: "UefiUsbCd",
				},
				CertBackendFallback: []string{
					"redfish",
					"smc-cgi",
				},
				VmediaRedfishOEMFallback: true,
				BootOverrideContinuous:   true,
				// Same OEM IPMI override as the manufacturer-wide entry:
				// it is the only software path proven to force PXE on an
				// X10 whose disk already holds a UEFI Linux NVRAM entry.
				BootOverrideStrategy: "smc-oem-ipmi",
			},
		},

		// ---------------------------------------------------------------
		// VeloCloud Networks EDGE840 — Supermicro X10SDV silicon under
		// a VeloCloud OEM SMBIOS skin.
		//
		// The EDGE840 is a Supermicro-built SD-WAN appliance for
		// VeloCloud Networks (now part of VMware). Hardware identity:
		//
		//   System.Manufacturer = "VeloCloud Networks, Inc."
		//   System.Model        = "EDGE840"
		//   System.BiosVersion  = "2.6"          (matches X10 BIOS)
		//   Manager.Model       = "ASPEED"       (X10 ATEN BMC stack)
		//   Manager.FirmwareVer = "4.0"          (same ATEN firmware)
		//   Boot.AllowableValues includes "UefiCd", "Pxe", "CD/DVD".
		//
		// Because the BMC + BIOS + UART wiring are byte-identical to a
		// Supermicro X10SDV, every X10 quirk applies: SMB1 vmedia,
		// COM1 SOL, "UefiCd" alias, BootOverrideContinuous to survive
		// the X10 ATEN "Once → cleared before POST" trap, and the
		// smc-oem-ipmi 0x30/0x70/0x0c override backend for PXE
		// fallback when the disk has an existing UEFI Linux entry in
		// NVRAM. Without this entry, Resolve() returns the generic
		// Default() quirk and BootSourceOverrideTarget=UefiCd lands
		// with enabled=Once — which the X10 BIOS silently erases,
		// falling back to the on-disk Linux entry and causing the
		// orchestrator's install-log probe to time out.
		// ---------------------------------------------------------------
		{
			match: match{manufacturer: "velocloud networks, inc."},
			quirk: Quirk{
				Manufacturer: "VeloCloud Networks, Inc.",
				KernelCmdline: []string{
					"earlyprintk=efi,keep",
					"earlycon=uart8250,io,0x3f8,115200n8",
					"console=tty0",
					"console=ttyS1,115200n8",
					"console=ttyS0,115200n8",
					"loglevel=7",
				},
				SOLPort:            "ttyS0",
				SOLPayloadInstance: 0x01,
				EarlyconSpec:       "uart8250,io,0x3f8,115200n8",
				SambaMinProtocol:   "NT1",
				SambaEncryption:    "disabled",
				BootMediaType: MediaType{
					CDDVDAlias: "CD/DVD",
					// ATEN virtual media enumerates as a USB CD/DVD device, so
					// the UEFI boot target is "UefiUsbCd" — NOT "UefiCd" (the
					// empty physical/SATA optical class). Verified on X10SDV-TP8F:
					// BIOS FIXED BOOT ORDER lists the ATEN virtual CD under
					// "UEFI USB CD/DVD"; targeting "UefiCd" points the boot
					// override at the empty class and the node skips to PXE/disk.
					UEFICDAlias: "UefiUsbCd",
				},
				CertBackendFallback: []string{
					"redfish",
					"smc-cgi",
				},
				VmediaRedfishOEMFallback: true,
				BootOverrideContinuous:   true,
				BootOverrideStrategy:     "smc-oem-ipmi",
			},
		},

		// ---------------------------------------------------------------
		// Aspeed AST2400 / AST2500 vUART boards
		//
		// These boards expose a virtual UART through the Aspeed BMC at
		// ttyS4 when the 8250_aspeed_vuart kernel module is loaded.
		// NOTE: The Alpine LTS kernel packages do NOT include
		// 8250_aspeed_vuart; this entry is provided for distributions that
		// do ship the module (e.g. Ubuntu, RHEL).  Do not enable it for
		// Alpine unless the module is confirmed present in the initramfs.
		// ---------------------------------------------------------------
		{
			match: match{manufacturer: "aspeed"},
			quirk: Quirk{
				Manufacturer: "Aspeed",
				KernelModules: []string{
					"8250_aspeed_vuart",
				},
				KernelCmdline: []string{
					"earlyprintk=efi,keep",
					"earlycon=uart8250,io,0x3f8,115200n8",
					"console=tty0",
					"console=ttyS0,115200n8",
					// ttyS4 is the Aspeed vUART device; listed last so it
					// wins as primary when the module is present.
					"console=ttyS4,115200n8",
					"loglevel=7",
				},
				SOLPort:            "ttyS4",
				SOLPayloadInstance: 0x01,
				EarlyconSpec:       "uart8250,io,0x3f8,115200n8",
				SambaMinProtocol:   "SMB2",
				SambaEncryption:    "required",
			},
		},

		// ---------------------------------------------------------------
		// Dell — manufacturer-wide default
		//
		// Dell iDRAC routes SOL to COM1 (ttyS0).  SMB2+ is supported by
		// all relevant Dell iDRAC firmware revisions. Redfish
		// CertificateService is fully supported; no fallback chain.
		// ---------------------------------------------------------------
		{
			match: match{manufacturer: "dell inc."},
			quirk: Quirk{
				Manufacturer: "Dell Inc.",
				KernelCmdline: []string{
					"earlyprintk=efi,keep",
					"earlycon=uart8250,io,0x3f8,115200n8",
					"console=tty0",
					"console=ttyS1,115200n8",
					"console=ttyS0,115200n8",
					"loglevel=7",
				},
				SOLPort:            "ttyS0",
				SOLPayloadInstance: 0x01,
				EarlyconSpec:       "uart8250,io,0x3f8,115200n8",
				SambaMinProtocol:   "SMB2",
				SambaEncryption:    "required",
			},
		},

		// ---------------------------------------------------------------
		// HPE — manufacturer-wide default
		//
		// HPE iLO routes SOL to COM1 (ttyS0). Redfish CertificateService
		// is fully supported on iLO 5+; no fallback chain.
		// ---------------------------------------------------------------
		{
			match: match{manufacturer: "hpe"},
			quirk: Quirk{
				Manufacturer: "HPE",
				KernelCmdline: []string{
					"earlyprintk=efi,keep",
					"earlycon=uart8250,io,0x3f8,115200n8",
					"console=tty0",
					"console=ttyS1,115200n8",
					"console=ttyS0,115200n8",
					"loglevel=7",
				},
				SOLPort:            "ttyS0",
				SOLPayloadInstance: 0x01,
				EarlyconSpec:       "uart8250,io,0x3f8,115200n8",
				SambaMinProtocol:   "SMB2",
				SambaEncryption:    "required",
			},
		},
		// ---------------------------------------------------------------
		// Raspberry Pi — manufacturer-wide default
		//
		// No BMC, no Redfish: the identity comes from the media generator
		// (installer hardware-manufacturer/-model overrides). The primary
		// UART is the PL011 on GPIO14/15 (ttyAMA0 once Bluetooth is moved
		// off it with dtoverlay=disable-bt); the same device is what the
		// QEMU virt machine used for emulated boots presents. No earlycon:
		// the PL011 base address differs per board and per emulator, and a
		// wrong one faults before the console exists. rootwait covers the
		// SD card appearing after the initramfs starts.
		// ---------------------------------------------------------------
		{
			match: match{manufacturer: "raspberry pi"},
			quirk: Quirk{
				Manufacturer: "Raspberry Pi",
				KernelCmdline: []string{
					"console=ttyAMA0,115200",
					"console=tty1",
					"rootwait",
					"loglevel=7",
				},
				SOLPort:            "ttyAMA0",
				SOLPayloadInstance: 0x01,
				EarlyconSpec:       "",
				SambaMinProtocol:   "SMB2",
				SambaEncryption:    "required",
			},
		},
		// ---------------------------------------------------------------
		// Raspberry Pi / QEMU virt stand-in — the emulated boot of the
		// factory image (pkg/diskimage/qemuvirt).
		//
		// Same UART as the Pi, opposite console order. The Pi's last
		// console= is tty1 so an operator at the HDMI port sees OpenRC
		// and the firstboot seal; the stand-in has no display, only the
		// serial the integration suite reads, so ttyAMA0 must be
		// /dev/console or everything after switch_root is invisible.
		// ---------------------------------------------------------------
		{
			match: match{manufacturer: "raspberry pi", model: "qemu virt"},
			quirk: Quirk{
				Manufacturer: "Raspberry Pi",
				Model:        "QEMU virt stand-in",
				KernelCmdline: []string{
					"console=tty1",
					// ttyAMA0 last → wins as primary (/dev/console).
					"console=ttyAMA0,115200",
					"rootwait",
					"loglevel=7",
				},
				SOLPort:            "ttyAMA0",
				SOLPayloadInstance: 0x01,
				EarlyconSpec:       "",
				SambaMinProtocol:   "SMB2",
				SambaEncryption:    "required",
			},
		},
	}

	for i := range entries {
		entries[i].quirk.Key = entryKey(entries[i].match)
	}
	return entries
}

// entryKey derives the informational Quirk.Key for a match predicate:
// "<manufacturer>" for a manufacturer-wide entry, "<manufacturer>/<board>"
// otherwise, where board is the model substring or, failing that, the
// part-number prefix.
func entryKey(m match) string {
	switch {
	case m.model != "":
		return m.manufacturer + "/" + m.model
	case m.partNumberPrefix != "":
		return m.manufacturer + "/" + m.partNumberPrefix
	default:
		return m.manufacturer
	}
}
