package quirks

// buildRegistry constructs the static vendor quirk table.
//
// To add a new vendor or board: append a new entry to the slice below.
// The key fields are:
//   - manufacturer: case-insensitive match against Redfish System.Manufacturer.
//   - model:        case-insensitive substring match against Redfish System.Model.
//     Leave empty for a manufacturer-wide default that applies
//     when no model-specific entry matches.
//
// This is the ONLY place in the codebase that may contain vendor names or
// model strings. Core install/ISO paths call Resolve and act on the returned
// Quirk fields only.
func buildRegistry() map[key]Quirk {
	entries := []struct {
		mfr   string
		model string
		quirk Quirk
	}{
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
			mfr:   "supermicro",
			model: "",
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
		// SOL is wired to COM2 (ttyS1 / 0x2f8) rather than COM1 on this
		// board.  "console=ttyS1" is therefore listed last so it wins as
		// the primary kmsg consumer.  earlycon must also point to COM2.
		//
		// IPMI SOL payload instance 0x02 follows the same wiring: the BMC
		// routes COM2 bytes to instance 0x02. Activating instance 0x01
		// (the IPMI default) on this board produces a successful Activate
		// Payload response but no UART bytes — the receive loop times
		// out silently. SOLPayloadInstance below corrects that.
		// ---------------------------------------------------------------
		{
			mfr:   "supermicro",
			model: "x10sdv",
			quirk: Quirk{
				Manufacturer: "Supermicro",
				Model:        "X10SDV",
				KernelCmdline: []string{
					"earlyprintk=efi,keep",
					// COM2 (0x2f8) for boards where BIOS routes SOL to COM2.
					"earlycon=uart8250,io,0x2f8,115200n8",
					"console=tty0",
					"console=ttyS0,115200n8",
					// ttyS1 last → wins as primary on X10SDV SOL path.
					"console=ttyS1,115200n8",
					"loglevel=7",
				},
				SOLPort:            "ttyS1",
				SOLPayloadInstance: 0x02,
				EarlyconSpec:       "uart8250,io,0x2f8,115200n8",
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
				BootOverrideStrategy:     "smc-cgi",
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
			mfr:   "velocloud networks, inc.",
			model: "",
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
			mfr:   "aspeed",
			model: "",
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
			mfr:   "dell inc.",
			model: "",
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
			mfr:   "hpe",
			model: "",
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
	}

	m := make(map[key]Quirk, len(entries))
	for _, e := range entries {
		k := key{
			manufacturer: e.mfr,
			model:        e.model,
		}
		m[k] = e.quirk
	}
	return m
}
