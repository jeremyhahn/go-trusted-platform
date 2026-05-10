// Package quirks provides a data-driven registry of hardware vendor quirks
// that affect platform installation and boot behaviour.
//
// Design intent: every vendor-specific deviation from standard behaviour is
// captured as data in the static registry table below. Core installer and ISO
// paths call Resolve to obtain the quirk set for a given host and act on the
// returned struct fields — they contain no manufacturer comparisons or
// hardcoded device strings themselves.
//
// Adding support for a new board is a data-only change: add a new entry to
// registry in registry.go. No code changes are needed.
package quirks

import (
	"strings"
)

// MediaType captures vendor-specific aliases for Redfish virtual CD/DVD
// boot-source-override target strings.
//
// DMTF compliant BMCs (Dell iDRAC, HPE iLO, OpenBMC) advertise the standard
// "Cd" / "UefiCd" values. Some Supermicro X10/X11 ATEN BMCs deviate from the
// DMTF spec and advertise "CD/DVD" (with a slash) or "UefiCd". The platform
// Redfish client consults the resolved Quirk's MediaType to know which extra
// non-DMTF aliases to consider when matching the BMC's advertised
// BootSourceOverrideTarget@Redfish.AllowableValues.
//
// Empty strings on either field mean "no vendor alias — DMTF defaults only".
type MediaType struct {
	// CDDVDAlias is the BIOS-mode CD/DVD alias the BMC advertises in
	// place of the DMTF "Cd" value (e.g. Supermicro X10 advertises
	// "CD/DVD" with a slash).
	CDDVDAlias string

	// UEFICDAlias is the UEFI-mode CD/DVD alias the BMC advertises
	// alongside or in place of the DMTF "UefiCd" value. Some boards
	// label the UEFI CD slot identically to the DMTF spec ("UefiCd")
	// even when the BIOS-mode alias deviates.
	UEFICDAlias string
}

// Quirk describes hardware-specific deviations that the platform must apply
// during installation or at runtime.
//
// Fields that are nil/empty slices/empty strings indicate "use the generic
// default for that feature". Consumers should treat an empty slice as
// equivalent to the generic default list returned by the Default quirk.
type Quirk struct {
	// Manufacturer is the Redfish System.Manufacturer string this entry
	// was resolved from. Informational — callers should not branch on it.
	Manufacturer string

	// Model is the Redfish System.Model string this entry was resolved
	// from. Informational — callers should not branch on it.
	Model string

	// KernelModules is the ordered list of additional kernel modules to
	// include in the initramfs (dracut add_drivers). An empty slice means
	// no extra modules beyond the generic baseline.
	KernelModules []string

	// KernelCmdline is the ordered list of additional kernel command-line
	// parameters to append to the UKI/GRUB command line. The installer
	// concatenates these after its own fixed parameters. An empty slice
	// means no extras.
	//
	// The generic default already includes:
	//   earlyprintk=efi,keep
	//   earlycon=uart8250,io,0x3f8,115200n8
	//   console=tty0
	//   console=ttyS1,115200n8
	//   console=ttyS0,115200n8
	//   loglevel=7
	//
	// Override this only when the vendor wires SOL to a different UART
	// or IO base (e.g. Aspeed vUART boards that use ttyS4).
	KernelCmdline []string

	// SOLPort is the Linux tty device name the BMC's Serial-over-LAN
	// concentrator is wired to (e.g. "ttyS0", "ttyS1", "ttyS4"). An
	// empty string means "use the generic default" (ttyS0/ttyS1 pair).
	SOLPort string

	// SOLPayloadInstance is the IPMI 2.0 SOL payload instance the BMC
	// routes serial-console bytes to. The IPMI 2.0 spec (Table 24-2)
	// allows instances 0x01-0x0F; almost all BMCs use 0x01 by default.
	// A few boards (notably Supermicro X10SDV-TP8F where SOL is wired to
	// COM2 / ttyS1) route to instance 0x02 instead. Activating instance
	// 0x01 against such a BMC succeeds at the protocol level (the BMC
	// accepts the Activate Payload command) but no UART bytes ever
	// stream — the receive loop sees EOF and the operator gets a
	// silent zero-byte SOL log.
	//
	// Zero means "use the generic default" (instance 0x01).
	SOLPayloadInstance byte

	// EarlyconSpec is the complete earlycon= parameter value for the
	// platform UART (e.g. "uart8250,io,0x3f8,115200n8" for COM1 or
	// "uart8250,io,0x2f8,115200n8" for COM2). An empty string means
	// "use the generic default".
	EarlyconSpec string

	// SambaMinProtocol is the value for "server min protocol" in the
	// bootstrap Samba share. An empty string means use "SMB2" (the
	// modern default). Set to "NT1" only for platforms whose BMC
	// virtual-media stack cannot negotiate SMB2.
	SambaMinProtocol string

	// SambaEncryption is the value for "smb encrypt" in the bootstrap
	// Samba share. An empty string means "required". Set to "disabled"
	// only for platforms whose BMC cannot negotiate SMB encryption.
	SambaEncryption string

	// BootMediaType holds vendor-specific Redfish virtual CD/DVD aliases
	// that deviate from the DMTF standard. The platform's Redfish boot-
	// device picker walks these aliases when matching against the BMC's
	// advertised BootSourceOverrideTarget@Redfish.AllowableValues. Zero-
	// value MediaType means DMTF-only.
	BootMediaType MediaType

	// CertBackendFallback is the ordered list of CertBackend names the
	// AutoCertManager should try, in order, when the explicit backend is
	// "auto" and policy permits a fallback chain. The first entry is the
	// primary backend; any subsequent entries are fallbacks attempted in
	// sequence on "unsupported" responses.
	//
	// Backend names are package-defined string identifiers from pkg/bmc
	// (e.g. "redfish", "smc-cgi"). pkg/quirks does not import pkg/bmc and
	// treats these as opaque strings — vendor entries simply list the
	// names that match registered CertBackend values.
	//
	// An empty slice means "no vendor-specific fallback chain — use the
	// caller-recommended single backend with no fallback". This is the
	// generic default for vendors with a single supported backend
	// (Dell iDRAC, HPE iLO, generic Redfish).
	CertBackendFallback []string

	// VmediaRedfishOEMFallback indicates that a 404 response from the
	// standard DMTF Redfish virtual-media EjectMedia / InsertMedia action
	// should be translated into an "unsupported" signal so the dispatch
	// layer can fall through to a vendor OEM virtual-media backend.
	//
	// Only set true for boards whose BMC firmware advertises the standard
	// VirtualMedia collection but does not actually implement the standard
	// actions on it (notably Supermicro X10 ATEN BMCs).
	VmediaRedfishOEMFallback bool

	// BootOverrideContinuous, when true, tells the platform Redfish
	// SetBootDevice path to ALWAYS request
	// BootSourceOverrideEnabled="Continuous" regardless of the
	// caller-requested persistent flag. Required on Supermicro X10
	// hardware: the X10 ATEN BMC silently erases "Once" overrides on
	// every reset such that the BIOS POST never sees the override and
	// falls through to the on-disk UEFI NVRAM entry (the X10 reflash
	// trap). Continuous keeps the override visible across the install
	// reboot dance; the orchestrator clears it explicitly on success
	// or on Phase 6 teardown via SetBootDevice(None, false).
	//
	// Default false (DMTF semantics: persistent=false → Once,
	// persistent=true → Continuous).
	BootOverrideContinuous bool

	// BootOverrideStrategy names the fallback boot-override mechanism
	// the dispatcher should attempt before/after the standard Redfish
	// PATCH on Systems/{id}.Boot. Valid values:
	//
	//   ""          — DMTF Redfish PATCH only (default).
	//   "smc-cgi"   — Try the legacy Supermicro CGI op.cgi boot
	//                 device endpoint first; fall back to Redfish PATCH
	//                 on CGI failure. Used on X10 boards whose BIOS
	//                 ignores the standard override.
	//
	// pkg/quirks does not import pkg/bmc; the value is treated as an
	// opaque string by the dispatcher.
	BootOverrideStrategy string
}

// key is the internal registry key.
type key struct {
	// manufacturer is lowercased.
	manufacturer string
	// model is lowercased and may be empty (manufacturer-wide match).
	model string
}

// registry is the static, data-driven table of known vendor quirks.
// The lookup order in Resolve is: (manufacturer, model) > (manufacturer, "").
// Manufacturers and model strings are stored lower-cased.
var registry map[key]Quirk

func init() {
	registry = buildRegistry()
}

// Resolve returns the Quirk that best matches the provided Redfish
// System.Manufacturer and System.Model strings. Matching is
// case-insensitive. An exact (manufacturer, model) match wins over a
// manufacturer-wide match, which wins over the generic default.
//
// Resolve always returns a valid Quirk; callers do not need to check for
// a zero value.
func Resolve(manufacturer, model string) Quirk {
	mfr := strings.ToLower(strings.TrimSpace(manufacturer))
	mdl := strings.ToLower(strings.TrimSpace(model))

	// Exact match first.
	if q, ok := registry[key{mfr, mdl}]; ok {
		return q
	}

	// Manufacturer-wide match (model substring).
	// Walk all keys looking for a model glob that is a substring of mdl.
	// This handles entries like modelMatch="x10sdv" matching "X10SDV-TP8F".
	for k, q := range registry {
		if k.manufacturer != mfr {
			continue
		}
		if k.model == "" {
			continue // manufacturer-wide default — keep as fallback below
		}
		if strings.Contains(mdl, k.model) {
			return q
		}
	}

	// Manufacturer-wide default (no model specified in the key).
	if q, ok := registry[key{mfr, ""}]; ok {
		return q
	}

	return Default()
}

// Default returns the generic quirk set used when no vendor-specific
// entry matches. It represents the conservative, broadly-compatible
// settings that work on the majority of server-class hardware.
func Default() Quirk {
	return Quirk{
		Manufacturer: "",
		Model:        "",
		// Generic kernel cmdline: dual UART coverage (COM1+COM2), EFI
		// early console, VGA mirror, verbose logging.
		KernelCmdline: []string{
			"earlyprintk=efi,keep",
			"earlycon=uart8250,io,0x3f8,115200n8",
			"console=tty0",
			"console=ttyS1,115200n8",
			"console=ttyS0,115200n8",
			"loglevel=7",
		},
		KernelModules:      nil,
		SOLPort:            "ttyS0",
		SOLPayloadInstance: 0x01,
		EarlyconSpec:       "uart8250,io,0x3f8,115200n8",
		SambaMinProtocol: "SMB2",
		SambaEncryption:  "required",
		// DMTF baseline: no vendor alias for CD/DVD.
		BootMediaType: MediaType{},
		// No vendor-specific cert-backend fallback chain.
		CertBackendFallback: nil,
		// Standard Redfish virtual media is assumed to work; only set
		// true for boards that 404 the DMTF actions.
		VmediaRedfishOEMFallback: false,
	}
}
