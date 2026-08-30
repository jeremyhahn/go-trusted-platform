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
	// Key names the registry entry this Quirk came from, in the form
	// "<manufacturer>" for a manufacturer-wide entry, "<manufacturer>/<board>"
	// for a board-specific entry, or "default" for Default(). Informational —
	// it exists so callers can log which entry won; never branch on it.
	Key string

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
	// A board whose BMC wires SOL to a second UART may route to instance
	// 0x02 instead. Activating instance
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

	// BootOverrideStrategy names the vendor boot-override mechanism the
	// dispatcher should attempt before the standard Redfish PATCH on
	// Systems/{id}.Boot. Valid values:
	//
	//   ""             — DMTF Redfish PATCH only (default).
	//   "smc-oem-ipmi" — Try the Supermicro OEM IPMI 0x30/0x70/0x0c
	//                    "Set Boot Option Override" first; fall back to
	//                    Redfish PATCH for devices the OEM command
	//                    cannot route. The proven path on X10 ATEN
	//                    firmware, used by every Supermicro entry.
	//
	// pkg/quirks does not import pkg/bmc; the value is treated as an
	// opaque string by the dispatcher, which rejects a name with no
	// registered backend as a registry defect.
	BootOverrideStrategy string
}

// Identity is the hardware identity a registry entry is matched against.
// Callers fill in whatever their BMC exposes; empty fields simply never
// match. Every field is compared case-insensitively after trimming.
type Identity struct {
	// Manufacturer is Redfish System.Manufacturer (or the vendor name an
	// IPMI client derives from the IANA enterprise number).
	Manufacturer string

	// Model is Redfish System.Model. Some firmware serves a generic
	// placeholder here ("Super Server") that identifies nothing.
	Model string

	// PartNumber is Redfish System.PartNumber — the chassis/system SKU
	// (e.g. "SYS-5018D-FN8T-AS001"). On firmware that blanks Model this is
	// the only field that still names the board.
	PartNumber string
}

// match is the identity predicate of one registry entry. All strings are
// stored lower-cased. manufacturer is required; model and partNumberPrefix
// are optional and make the entry board-specific — an entry with neither
// is the manufacturer-wide default.
type match struct {
	manufacturer     string
	model            string
	partNumberPrefix string
}

// boardSpecific reports whether the entry names a board rather than a
// manufacturer-wide default.
func (m match) boardSpecific() bool {
	return m.model != "" || m.partNumberPrefix != ""
}

// matchTier orders the kinds of match an identity can make against an
// entry, weakest first.
type matchTier int

const (
	// tierNone: the entry does not apply to the identity.
	tierNone matchTier = iota
	// tierManufacturer: a manufacturer-wide entry.
	tierManufacturer
	// tierBoard: the model key is a substring of the identity's model, or
	// the part-number prefix matches.
	tierBoard
	// tierExactModel: the model key equals the identity's model.
	tierExactModel
)

// rank scores how specifically a predicate selects an identity. tier is
// compared first; within a tier keyLen — the length of the board key that
// matched — makes a narrower key beat a broader one, so an entry appended
// after a broader entry it overlaps with is never shadowed by declaration
// order. Declaration order only breaks exact ties.
type rank struct {
	tier   matchTier
	keyLen int
}

// beats reports whether r is strictly more specific than o.
func (r rank) beats(o rank) bool {
	if r.tier != o.tier {
		return r.tier > o.tier
	}
	return r.keyLen > o.keyLen
}

// rank scores this predicate against a normalized identity. The
// manufacturer must be equal; a board-specific entry then scores the
// stronger of its model and part-number keys.
func (m match) rank(id Identity) rank {
	if m.manufacturer != id.Manufacturer {
		return rank{}
	}
	if !m.boardSpecific() {
		return rank{tier: tierManufacturer}
	}
	best := rank{}
	if m.model != "" && strings.Contains(id.Model, m.model) {
		best = rank{tier: tierBoard, keyLen: len(m.model)}
		if id.Model == m.model {
			best.tier = tierExactModel
		}
	}
	if m.partNumberPrefix != "" && strings.HasPrefix(id.PartNumber, m.partNumberPrefix) {
		if pn := (rank{tier: tierBoard, keyLen: len(m.partNumberPrefix)}); pn.beats(best) {
			best = pn
		}
	}
	return best
}

// entry pairs a match predicate with its quirk set.
type entry struct {
	match match
	quirk Quirk
}

// registry is the static, data-driven table of known vendor quirks. The
// most specific matching entry wins (see rank); declaration order only
// decides between entries of identical specificity.
var registry []entry

func init() {
	registry = buildRegistry()
}

// Resolve returns the Quirk that best matches the provided Redfish
// System.Manufacturer and System.Model strings. It is a convenience over
// ResolveIdentity for callers that have no part number.
func Resolve(manufacturer, model string) Quirk {
	return ResolveIdentity(Identity{Manufacturer: manufacturer, Model: model})
}

// ResolveIdentity returns the Quirk that best matches the hardware identity.
// Matching is case-insensitive. An entry whose model key equals the model
// wins over one whose model key is a substring of it or whose part-number
// prefix matches; among those, the longer key wins; a board-specific entry
// wins over the manufacturer-wide entry, which wins over the generic
// default. Entries of equal specificity resolve to the first declared.
//
// ResolveIdentity always returns a valid Quirk; callers do not need to check
// for a zero value.
func ResolveIdentity(id Identity) Quirk {
	return resolveIn(registry, id)
}

// resolveIn is ResolveIdentity over an explicit table, so the precedence
// rules can be tested against synthetic entries.
func resolveIn(entries []entry, id Identity) Quirk {
	id = Identity{
		Manufacturer: normalize(id.Manufacturer),
		Model:        normalize(id.Model),
		PartNumber:   normalize(id.PartNumber),
	}

	best := rank{}
	var winner *Quirk
	for i := range entries {
		r := entries[i].match.rank(id)
		if r.tier == tierNone || !r.beats(best) {
			continue
		}
		best = r
		winner = &entries[i].quirk
	}
	if winner == nil {
		return Default()
	}
	return *winner
}

// normalize lower-cases and trims an identity string for comparison.
func normalize(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// Default returns the generic quirk set used when no vendor-specific
// entry matches. It represents the conservative, broadly-compatible
// settings that work on the majority of server-class hardware.
func Default() Quirk {
	return Quirk{
		Key:          "default",
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
		SambaMinProtocol:   "SMB2",
		SambaEncryption:    "required",
		// DMTF baseline: no vendor alias for CD/DVD.
		BootMediaType: MediaType{},
		// No vendor-specific cert-backend fallback chain.
		CertBackendFallback: nil,
		// Standard Redfish virtual media is assumed to work; only set
		// true for boards that 404 the DMTF actions.
		VmediaRedfishOEMFallback: false,
	}
}
