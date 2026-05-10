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
					CDDVDAlias:  "CD/DVD",
					UEFICDAlias: "UefiCd",
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
				// Try the legacy CGI op.cgi boot-device endpoint
				// before the standard Redfish PATCH. The CGI path is
				// documented as a stub today (see vboot_smc_cgi.go);
				// the strategy value is wired so once the wire
				// protocol is captured the dispatcher routes to it
				// without further code changes.
				BootOverrideStrategy: "smc-cgi",
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
					CDDVDAlias:  "CD/DVD",
					UEFICDAlias: "UefiCd",
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
