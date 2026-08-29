package quirks

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefault verifies that the Default quirk contains the generic
// cross-vendor values that serve as the safe fallback for unknown hardware.
func TestDefault(t *testing.T) {
	d := Default()

	assert.Equal(t, "ttyS0", d.SOLPort)
	assert.Equal(t, "uart8250,io,0x3f8,115200n8", d.EarlyconSpec)
	assert.Equal(t, "SMB2", d.SambaMinProtocol)
	assert.Equal(t, "required", d.SambaEncryption)
	assert.Nil(t, d.KernelModules)

	// New typed-effect fields default to zero/empty (DMTF baseline).
	assert.Equal(t, MediaType{}, d.BootMediaType, "Default quirk must not advertise any vendor CD/DVD aliases")
	assert.Empty(t, d.CertBackendFallback, "Default quirk must not specify a vendor cert-backend chain")
	assert.False(t, d.VmediaRedfishOEMFallback, "Default quirk must not signal an OEM vmedia fallback")

	// Cmdline must contain the minimum set of generic console parameters.
	require.NotEmpty(t, d.KernelCmdline)
	assertContainsParam(t, d.KernelCmdline, "earlyprintk=efi,keep")
	assertContainsParam(t, d.KernelCmdline, "console=ttyS0,115200n8")
	assertContainsParam(t, d.KernelCmdline, "loglevel=7")
}

// TestResolveUnknownVendor verifies that an unrecognized manufacturer string
// returns the Default quirk without panic.
func TestResolveUnknownVendor(t *testing.T) {
	q := Resolve("Acme Corp", "Widget 9000")
	want := Default()

	assert.Equal(t, want.SOLPort, q.SOLPort)
	assert.Equal(t, want.EarlyconSpec, q.EarlyconSpec)
	assert.Equal(t, want.SambaMinProtocol, q.SambaMinProtocol)
	assert.Equal(t, want.SambaEncryption, q.SambaEncryption)
	assert.Equal(t, want.KernelCmdline, q.KernelCmdline)
	assert.Equal(t, want.BootMediaType, q.BootMediaType)
	assert.Equal(t, want.CertBackendFallback, q.CertBackendFallback)
	assert.Equal(t, want.VmediaRedfishOEMFallback, q.VmediaRedfishOEMFallback)
}

// TestResolveUnknownVendorEmptyStrings verifies that empty manufacturer and
// model strings also resolve to the Default quirk.
func TestResolveUnknownVendorEmptyStrings(t *testing.T) {
	q := Resolve("", "")
	want := Default()

	assert.Equal(t, want.SOLPort, q.SOLPort)
	assert.Equal(t, want.SambaMinProtocol, q.SambaMinProtocol)
}

// TestResolveSupermicroManufacturerWide verifies that a generic Supermicro
// board (model not in the registry) returns the manufacturer-wide default
// with SMB1/disabled-encryption quirks and COM1 SOL wiring.
func TestResolveSupermicroManufacturerWide(t *testing.T) {
	q := Resolve("Supermicro", "X11SPM-F")

	assert.Equal(t, "ttyS0", q.SOLPort)
	assert.Equal(t, "NT1", q.SambaMinProtocol, "Supermicro BMC requires NT1 for virtual-media")
	assert.Equal(t, "disabled", q.SambaEncryption)
	assertContainsParam(t, q.KernelCmdline, "console=ttyS0,115200n8")
}

// TestResolveSupermicroManufacturerWideCaseInsensitive ensures the lookup is
// case-insensitive on the manufacturer string.
func TestResolveSupermicroManufacturerWideCaseInsensitive(t *testing.T) {
	q1 := Resolve("SUPERMICRO", "X11SPM-F")
	q2 := Resolve("supermicro", "X11SPM-F")
	q3 := Resolve("Supermicro", "X11SPM-F")

	assert.Equal(t, q1, q2)
	assert.Equal(t, q2, q3)
}

// TestResolveSupermicroX10SDV verifies that the X10SDV board is identified
// by model substring match and returns its COM2 SOL wiring.
func TestResolveSupermicroX10SDV(t *testing.T) {
	// Redfish returns the full model string including suffix.
	q := Resolve("Supermicro", "X10SDV-TP8F")

	assert.Equal(t, "ttyS1", q.SOLPort, "X10SDV routes SOL to COM2 (ttyS1)")
	assert.Equal(t, "uart8250,io,0x2f8,115200n8", q.EarlyconSpec, "COM2 IO base is 0x2f8")
	assert.Equal(t, "NT1", q.SambaMinProtocol)
	assert.Equal(t, "disabled", q.SambaEncryption)
	// IPMI 2.0 SOL payload instance follows the same wiring: the BMC
	// routes COM2 bytes to instance 0x02. Activating instance 0x01 (the
	// IPMI default) yields a successful Activate Payload response and
	// silence on the receive loop.
	assert.Equal(t, byte(0x02), q.SOLPayloadInstance,
		"X10SDV must request SOL payload instance 0x02 to receive COM2 bytes")

	// ttyS1 must be the last console= param (last wins as primary).
	assertLastConsoleParam(t, q.KernelCmdline, "console=ttyS1,115200n8")
}

// TestResolveSupermicroX10SDVModelCaseInsensitive verifies model matching is
// case-insensitive.
func TestResolveSupermicroX10SDVModelCaseInsensitive(t *testing.T) {
	q1 := Resolve("Supermicro", "x10sdv-tp8f")
	q2 := Resolve("Supermicro", "X10SDV-TP8F")

	assert.Equal(t, q1.SOLPort, q2.SOLPort)
	assert.Equal(t, q1.EarlyconSpec, q2.EarlyconSpec)
}

// TestResolveDefaultSOLPayloadInstance verifies the generic default
// returns the IPMI 2.0 default payload instance (0x01) so callers that
// don't yet consult the quirk registry preserve prior behaviour.
func TestResolveDefaultSOLPayloadInstance(t *testing.T) {
	d := Default()
	assert.Equal(t, byte(0x01), d.SOLPayloadInstance,
		"Default quirk must request IPMI 2.0 default SOL payload instance (0x01)")

	// Manufacturer-wide Supermicro should also default to 0x01 (X10/X11
	// boards that aren't X10SDV use COM1).
	q := Resolve("Supermicro", "X11SPM-F")
	assert.Equal(t, byte(0x01), q.SOLPayloadInstance,
		"Supermicro manufacturer-wide default must use SOL instance 0x01")
}

// TestResolveAspeedVUART verifies that the Aspeed manufacturer-wide quirk
// activates the 8250_aspeed_vuart kernel module and routes to ttyS4.
func TestResolveAspeedVUART(t *testing.T) {
	q := Resolve("Aspeed", "AST2400")

	assert.Equal(t, "ttyS4", q.SOLPort)
	assert.Contains(t, q.KernelModules, "8250_aspeed_vuart")
	assertContainsParam(t, q.KernelCmdline, "console=ttyS4,115200n8")
	// Aspeed does not need SMB1.
	assert.Equal(t, "SMB2", q.SambaMinProtocol)
}

// TestResolveMostSpecificWins verifies that an exact (manufacturer, model)
// match beats a manufacturer-wide default.  We use the X10SDV vs the generic
// Supermicro manufacturer-wide entry.
func TestResolveMostSpecificWins(t *testing.T) {
	generic := Resolve("Supermicro", "X11SPM-F") // manufacturer-wide
	specific := Resolve("Supermicro", "X10SDV-TP8F")

	// They must be different: X10SDV has COM2, generic has COM1.
	assert.NotEqual(t, generic.SOLPort, specific.SOLPort,
		"model-specific entry must win over manufacturer-wide default")
	assert.Equal(t, "ttyS0", generic.SOLPort)
	assert.Equal(t, "ttyS1", specific.SOLPort)
}

// TestResolveDell verifies Dell iDRAC defaults (COM1, SMB2).
func TestResolveDell(t *testing.T) {
	q := Resolve("Dell Inc.", "PowerEdge R640")

	assert.Equal(t, "ttyS0", q.SOLPort)
	assert.Equal(t, "SMB2", q.SambaMinProtocol)
	assert.Equal(t, "required", q.SambaEncryption)
}

// TestResolveHPE verifies HPE iLO defaults.
func TestResolveHPE(t *testing.T) {
	q := Resolve("HPE", "ProLiant DL380 Gen10")

	assert.Equal(t, "ttyS0", q.SOLPort)
	assert.Equal(t, "SMB2", q.SambaMinProtocol)
	assert.Equal(t, "required", q.SambaEncryption)
}

// TestKernelCmdlineContainsEarlycon ensures all registered quirks include
// an earlycon parameter for early boot visibility.
func TestKernelCmdlineContainsEarlycon(t *testing.T) {
	vendors := []struct {
		mfr, model string
	}{
		{"Supermicro", "X11SPM-F"},
		{"Supermicro", "X10SDV-TP8F"},
		{"Aspeed", "AST2400"},
		{"Dell Inc.", "PowerEdge R640"},
		{"HPE", "ProLiant DL380 Gen10"},
		{"", ""},
	}
	for _, v := range vendors {
		q := Resolve(v.mfr, v.model)
		hasEarlycon := false
		for _, p := range q.KernelCmdline {
			if len(p) > 9 && p[:9] == "earlycon=" {
				hasEarlycon = true
				break
			}
		}
		assert.True(t, hasEarlycon, "quirk for %q/%q missing earlycon param", v.mfr, v.model)
	}
}

// TestRegistryEveryEntryHasManufacturerAndKey ensures no registry entry
// lacks a manufacturer (it would never match anything useful) and that every
// entry carries the informational Key derived from its match predicate.
func TestRegistryEveryEntryHasManufacturerAndKey(t *testing.T) {
	for _, e := range registry {
		assert.NotEmpty(t, e.match.manufacturer, "entry %q has an empty manufacturer", e.quirk.Key)
		assert.NotEmpty(t, e.quirk.Key, "entry for %q has no Key", e.match.manufacturer)
		assert.Equal(t, entryKey(e.match), e.quirk.Key)
	}
}

// TestResolveKeyNamesTheWinningEntry verifies Key identifies which entry a
// resolution came from, so the BMC clients can log it.
func TestResolveKeyNamesTheWinningEntry(t *testing.T) {
	assert.Equal(t, "supermicro/x10sdv", Resolve("Supermicro", "X10SDV-TP8F").Key)
	assert.Equal(t, "supermicro", Resolve("Supermicro", "X11SPM-F").Key)
	assert.Equal(t, "velocloud networks, inc.", Resolve("VeloCloud Networks, Inc.", "EDGE840").Key)
	assert.Equal(t, "default", Resolve("Acme Corp", "Widget 9000").Key)
	assert.Equal(t, "default", Default().Key)
}

// TestEntryKeyPartNumberOnlyEntry verifies the key derivation for a
// board-specific entry that has no model substring, only a part-number
// prefix.
func TestEntryKeyPartNumberOnlyEntry(t *testing.T) {
	assert.Equal(t, "acme/pn-", entryKey(match{manufacturer: "acme", partNumberPrefix: "pn-"}))
	assert.Equal(t, "acme", entryKey(match{manufacturer: "acme"}))
}

// miniFleetIdentity is exactly what the ATEN FW 4.00 / BIOS 2.6 BMC on
// lab-node-2 serves (issue #101): a placeholder Model and SKU, with the board
// named only by PartNumber.
var miniFleetIdentity = Identity{
	Manufacturer: "Supermicro",
	Model:        "Super Server",
	PartNumber:   "SYS-5018D-FN8T-AS001",
}

// TestResolveIdentityMiniFleetSelectsX10SDV verifies the live mini-fleet
// identity strings select the X10SDV set — COM2 SOL and payload instance
// 0x02 — rather than falling through to the manufacturer-wide entry.
func TestResolveIdentityMiniFleetSelectsX10SDV(t *testing.T) {
	q := ResolveIdentity(miniFleetIdentity)

	assert.Equal(t, "supermicro/x10sdv", q.Key)
	assert.Equal(t, "ttyS1", q.SOLPort, "X10SDV routes SOL to COM2 (ttyS1)")
	assert.Equal(t, byte(0x02), q.SOLPayloadInstance)
	assert.Equal(t, "uart8250,io,0x2f8,115200n8", q.EarlyconSpec)
	assertLastConsoleParam(t, q.KernelCmdline, "console=ttyS1,115200n8")
}

// TestResolveIdentityMiniFleetKeepsOEMIPMIOverride verifies the X10SDV entry
// keeps the proven smc-oem-ipmi boot override: "smc-cgi" is a documented stub
// in pkg/bmc, and selecting it would drop the override the moment the entry
// matched.
func TestResolveIdentityMiniFleetKeepsOEMIPMIOverride(t *testing.T) {
	q := ResolveIdentity(miniFleetIdentity)

	assert.Equal(t, "smc-oem-ipmi", q.BootOverrideStrategy)
	assert.True(t, q.BootOverrideContinuous)
	assert.True(t, q.VmediaRedfishOEMFallback)
	assert.Equal(t, "NT1", q.SambaMinProtocol)
}

// TestResolveIdentityPartNumberCaseAndWhitespace verifies the part-number
// prefix match tolerates case and padding the same way the other fields do.
func TestResolveIdentityPartNumberCaseAndWhitespace(t *testing.T) {
	q := ResolveIdentity(Identity{
		Manufacturer: " SUPERMICRO ",
		Model:        "super server",
		PartNumber:   "  sys-5018d-fn4t  ",
	})

	assert.Equal(t, "supermicro/x10sdv", q.Key)
}

// TestResolveIdentityPlaceholderModelWithoutPartNumber verifies the
// placeholder model alone still falls back to the manufacturer-wide entry
// (no part number means nothing names the board).
func TestResolveIdentityPlaceholderModelWithoutPartNumber(t *testing.T) {
	q := ResolveIdentity(Identity{Manufacturer: "Supermicro", Model: "Super Server"})

	assert.Equal(t, "supermicro", q.Key)
	assert.Equal(t, "ttyS0", q.SOLPort)
	assert.Equal(t, byte(0x01), q.SOLPayloadInstance)
}

// TestResolveIdentityPartNumberWrongPrefixFallsBack verifies a Supermicro
// part number outside the X10SDV family is not mistaken for one.
func TestResolveIdentityPartNumberWrongPrefixFallsBack(t *testing.T) {
	q := ResolveIdentity(Identity{
		Manufacturer: "Supermicro",
		Model:        "Super Server",
		PartNumber:   "SYS-5019D-FN8TP",
	})

	assert.Equal(t, "supermicro", q.Key)
}

// TestResolveIdentityPartNumberNeedsMatchingManufacturer verifies the
// part-number prefix never matches across manufacturers.
func TestResolveIdentityPartNumberNeedsMatchingManufacturer(t *testing.T) {
	q := ResolveIdentity(Identity{
		Manufacturer: "Dell Inc.",
		Model:        "PowerEdge R640",
		PartNumber:   "SYS-5018D-FN8T-AS001",
	})

	assert.Equal(t, "dell inc.", q.Key)
	assert.Equal(t, "ttyS0", q.SOLPort)
}

// TestResolveIdentityEmpty verifies an all-empty identity resolves to the
// generic default without panic.
func TestResolveIdentityEmpty(t *testing.T) {
	q := ResolveIdentity(Identity{})

	assert.Equal(t, "default", q.Key)
	assert.Equal(t, Default().SOLPort, q.SOLPort)
}

// TestResolveDelegatesToResolveIdentity verifies the two-argument
// convenience form is exactly ResolveIdentity with no part number.
func TestResolveDelegatesToResolveIdentity(t *testing.T) {
	assert.Equal(t,
		ResolveIdentity(Identity{Manufacturer: "Supermicro", Model: "X10SDV-TP8F"}),
		Resolve("Supermicro", "X10SDV-TP8F"))
}

// TestErrUnknownManufacturerError verifies that ErrUnknownManufacturer produces
// a well-formed error string that includes the manufacturer name.
func TestErrUnknownManufacturerError(t *testing.T) {
	err := &ErrUnknownManufacturer{Manufacturer: "WidgetCo"}
	msg := err.Error()

	assert.Contains(t, msg, "WidgetCo", "error message must contain the manufacturer name")
	assert.Contains(t, msg, "quirks:", "error message must be prefixed with package name")
}

// TestErrUnknownManufacturerEmptyName verifies that an empty manufacturer name
// does not cause a panic or empty message.
func TestErrUnknownManufacturerEmptyName(t *testing.T) {
	err := &ErrUnknownManufacturer{Manufacturer: ""}
	msg := err.Error()

	assert.NotEmpty(t, msg)
}

// TestResolveSupermicroNoModelMatchFallsBackToMfrDefault verifies the fallback
// path where a known manufacturer is supplied with a model that has no
// substring match — the manufacturer-wide default is returned (not Default()).
func TestResolveSupermicroNoModelMatchFallsBackToMfrDefault(t *testing.T) {
	// "X99" is not a substring of any Supermicro model key in the registry.
	q := Resolve("Supermicro", "X99-SomethingNew")

	// Should match the Supermicro manufacturer-wide default (NT1, disabled).
	assert.Equal(t, "NT1", q.SambaMinProtocol, "unknown Supermicro model must fall back to manufacturer-wide default")
	assert.Equal(t, "disabled", q.SambaEncryption)
	// SOL wiring for the manufacturer-wide default is COM1.
	assert.Equal(t, "ttyS0", q.SOLPort)
}

// TestResolveWhitespaceTrimming verifies that leading/trailing whitespace in
// manufacturer or model strings does not prevent a match.
func TestResolveWhitespaceTrimming(t *testing.T) {
	q1 := Resolve("  Supermicro  ", "  X10SDV-TP8F  ")
	q2 := Resolve("Supermicro", "X10SDV-TP8F")

	assert.Equal(t, q1.SOLPort, q2.SOLPort)
	assert.Equal(t, q1.EarlyconSpec, q2.EarlyconSpec)
}

// TestResolveEmptyModelSelectsManufacturerWide verifies that a known
// manufacturer with an empty model string still resolves to that
// manufacturer's entry rather than Default().
func TestResolveEmptyModelSelectsManufacturerWide(t *testing.T) {
	q := Resolve("Dell Inc.", "")

	assert.Equal(t, "dell inc.", q.Key)
	assert.Equal(t, "ttyS0", q.SOLPort)
	assert.Equal(t, "SMB2", q.SambaMinProtocol)
	assert.Equal(t, "required", q.SambaEncryption)
	assert.Equal(t, "Dell Inc.", q.Manufacturer)
}

// syntheticTable is a registry with two board-specific entries for one
// manufacturer that both match the same identity, declared with the
// manufacturer-wide entry FIRST, so precedence is observable.
var syntheticTable = []entry{
	{match: match{manufacturer: "acme"}, quirk: Quirk{Key: "acme"}},
	{match: match{manufacturer: "acme", partNumberPrefix: "pn-1"}, quirk: Quirk{Key: "acme/pn-1"}},
	{match: match{manufacturer: "acme", model: "widget"}, quirk: Quirk{Key: "acme/widget"}},
}

// TestResolveInBoardSpecificBeatsManufacturerWide verifies a board-specific
// entry wins even when the manufacturer-wide entry is declared before it.
func TestResolveInBoardSpecificBeatsManufacturerWide(t *testing.T) {
	q := resolveIn(syntheticTable, Identity{Manufacturer: "Acme", Model: "Widget 9000"})

	assert.Equal(t, "acme/widget", q.Key)
}

// TestResolveInFirstDeclaredBoardSpecificWins verifies that when two
// board-specific entries both match, the earlier declaration wins.
func TestResolveInFirstDeclaredBoardSpecificWins(t *testing.T) {
	q := resolveIn(syntheticTable, Identity{
		Manufacturer: "Acme",
		Model:        "Widget 9000",
		PartNumber:   "PN-1000",
	})

	assert.Equal(t, "acme/pn-1", q.Key)
}

// TestResolveInNoBoardMatchFallsToManufacturerWide verifies the
// manufacturer-wide entry is used when no board-specific predicate hits.
func TestResolveInNoBoardMatchFallsToManufacturerWide(t *testing.T) {
	q := resolveIn(syntheticTable, Identity{Manufacturer: "Acme", Model: "Gadget", PartNumber: "PN-2000"})

	assert.Equal(t, "acme", q.Key)
}

// TestResolveInUnknownManufacturerIsDefault verifies an unlisted
// manufacturer never picks up another manufacturer's entries.
func TestResolveInUnknownManufacturerIsDefault(t *testing.T) {
	q := resolveIn(syntheticTable, Identity{Manufacturer: "Other", Model: "Widget", PartNumber: "PN-1"})

	assert.Equal(t, "default", q.Key)
}

// ---------------------------------------------------------------------------
// BootMediaType field
// ---------------------------------------------------------------------------

// TestX10SDVBootMediaType verifies the Supermicro X10SDV-TP8F entry advertises
// the non-DMTF "CD/DVD" alias (with slash) for the BIOS-mode CD slot, and the
// USB class "UefiUsbCd" for the UEFI-mode slot (ATEN virtual media enumerates
// as a USB CD/DVD device; "UefiCd" is the empty SATA optical class).
func TestX10SDVBootMediaType(t *testing.T) {
	q := Resolve("Supermicro", "X10SDV-TP8F")

	assert.Equal(t, "CD/DVD", q.BootMediaType.CDDVDAlias,
		"X10 ATEN BMC advertises 'CD/DVD' (with slash) for BIOS-mode virtual CD")
	assert.Equal(t, "UefiUsbCd", q.BootMediaType.UEFICDAlias,
		"ATEN virtual media boots from the UEFI USB CD/DVD class")
}

// TestSupermicroManufacturerWideBootMediaType verifies that all Supermicro
// boards inherit the X10/X11 ATEN CD aliases via the manufacturer-wide entry.
func TestSupermicroManufacturerWideBootMediaType(t *testing.T) {
	q := Resolve("Supermicro", "X11SPM-F")

	assert.Equal(t, "CD/DVD", q.BootMediaType.CDDVDAlias)
	assert.Equal(t, "UefiUsbCd", q.BootMediaType.UEFICDAlias)
}

// TestDefaultBootMediaTypeEmpty verifies the generic-fallback Quirk advertises
// no vendor-specific CD aliases (DMTF baseline only).
func TestDefaultBootMediaTypeEmpty(t *testing.T) {
	d := Default()

	assert.Empty(t, d.BootMediaType.CDDVDAlias,
		"Default Quirk must not advertise a non-DMTF CD/DVD alias")
	assert.Empty(t, d.BootMediaType.UEFICDAlias,
		"Default Quirk must not advertise a non-DMTF UEFI CD alias")
}

// TestUnknownVendorBootMediaTypeEmpty verifies that an unrecognized vendor
// resolves to the empty MediaType (DMTF only).
func TestUnknownVendorBootMediaTypeEmpty(t *testing.T) {
	q := Resolve("Acme Corp", "Widget 9000")

	assert.Equal(t, MediaType{}, q.BootMediaType,
		"Unknown vendor must resolve to the empty MediaType — no aliases")
}

// TestDellBootMediaTypeEmpty verifies that DMTF-compliant Dell iDRAC has no
// vendor-specific CD aliases.
func TestDellBootMediaTypeEmpty(t *testing.T) {
	q := Resolve("Dell Inc.", "PowerEdge R640")

	assert.Empty(t, q.BootMediaType.CDDVDAlias)
	assert.Empty(t, q.BootMediaType.UEFICDAlias)
}

// ---------------------------------------------------------------------------
// CertBackendFallback field
// ---------------------------------------------------------------------------

// TestX10SDVCertBackendFallback verifies the X10SDV entry lists the two-stage
// "redfish" -> "smc-cgi" fallback chain.
func TestX10SDVCertBackendFallback(t *testing.T) {
	q := Resolve("Supermicro", "X10SDV-TP8F")

	require.Len(t, q.CertBackendFallback, 2,
		"X10SDV must list both Redfish and SMC-CGI as fallback chain")
	assert.Equal(t, "redfish", q.CertBackendFallback[0],
		"primary cert backend must be Redfish CertificateService")
	assert.Equal(t, "smc-cgi", q.CertBackendFallback[1],
		"secondary cert backend must be the SMC ATEN CGI endpoint")
}

// TestSupermicroManufacturerWideCertBackendFallback verifies the manufacturer-
// wide Supermicro entry inherits the same fallback chain.
func TestSupermicroManufacturerWideCertBackendFallback(t *testing.T) {
	q := Resolve("Supermicro", "X11SPM-F")

	require.Len(t, q.CertBackendFallback, 2)
	assert.Equal(t, "redfish", q.CertBackendFallback[0])
	assert.Equal(t, "smc-cgi", q.CertBackendFallback[1])
}

// TestDefaultCertBackendFallbackEmpty verifies the generic-fallback Quirk has
// no vendor-specific cert backend chain.
func TestDefaultCertBackendFallbackEmpty(t *testing.T) {
	d := Default()

	assert.Empty(t, d.CertBackendFallback,
		"Default Quirk must not specify a vendor cert backend fallback chain")
}

// TestUnknownVendorCertBackendFallbackEmpty verifies that an unrecognized
// vendor resolves to an empty CertBackendFallback slice.
func TestUnknownVendorCertBackendFallbackEmpty(t *testing.T) {
	q := Resolve("Acme Corp", "Widget 9000")

	assert.Empty(t, q.CertBackendFallback,
		"Unknown vendor must not advertise a fallback chain")
}

// TestDellCertBackendFallbackEmpty verifies DMTF-compliant Dell iDRAC has no
// fallback chain (Redfish CertificateService is fully supported).
func TestDellCertBackendFallbackEmpty(t *testing.T) {
	q := Resolve("Dell Inc.", "PowerEdge R640")

	assert.Empty(t, q.CertBackendFallback,
		"Dell iDRAC supports Redfish CertificateService — no fallback expected")
}

// TestHPECertBackendFallbackEmpty verifies HPE iLO has no fallback chain.
func TestHPECertBackendFallbackEmpty(t *testing.T) {
	q := Resolve("HPE", "ProLiant DL380 Gen10")

	assert.Empty(t, q.CertBackendFallback,
		"HPE iLO 5+ supports Redfish CertificateService — no fallback expected")
}

// ---------------------------------------------------------------------------
// VmediaRedfishOEMFallback field
// ---------------------------------------------------------------------------

// TestX10SDVVmediaRedfishOEMFallback verifies the X10SDV entry signals that
// the standard Redfish vmedia path may 404 and the dispatch layer should fall
// through to the OEM backend.
func TestX10SDVVmediaRedfishOEMFallback(t *testing.T) {
	q := Resolve("Supermicro", "X10SDV-TP8F")

	assert.True(t, q.VmediaRedfishOEMFallback,
		"X10SDV ATEN BMC 404s standard EjectMedia — fallback signal must be set")
}

// TestSupermicroManufacturerWideVmediaRedfishOEMFallback verifies the
// manufacturer-wide Supermicro entry inherits the OEM-fallback signal.
func TestSupermicroManufacturerWideVmediaRedfishOEMFallback(t *testing.T) {
	q := Resolve("Supermicro", "X11SPM-F")

	assert.True(t, q.VmediaRedfishOEMFallback,
		"Supermicro manufacturer-wide entry must signal the OEM vmedia fallback")
}

// TestDefaultVmediaRedfishOEMFallbackFalse verifies the generic-fallback Quirk
// does not request OEM fallback (DMTF baseline assumes standard works).
func TestDefaultVmediaRedfishOEMFallbackFalse(t *testing.T) {
	d := Default()

	assert.False(t, d.VmediaRedfishOEMFallback,
		"Default Quirk must not request an OEM vmedia fallback")
}

// TestUnknownVendorVmediaRedfishOEMFallbackFalse verifies that an unrecognized
// vendor resolves to false.
func TestUnknownVendorVmediaRedfishOEMFallbackFalse(t *testing.T) {
	q := Resolve("Acme Corp", "Widget 9000")

	assert.False(t, q.VmediaRedfishOEMFallback)
}

// TestDellVmediaRedfishOEMFallbackFalse verifies Dell iDRAC does not request
// OEM fallback (standard Redfish vmedia is fully supported).
func TestDellVmediaRedfishOEMFallbackFalse(t *testing.T) {
	q := Resolve("Dell Inc.", "PowerEdge R640")

	assert.False(t, q.VmediaRedfishOEMFallback,
		"Dell iDRAC supports standard Redfish vmedia — no OEM fallback expected")
}

// TestHPEVmediaRedfishOEMFallbackFalse verifies HPE iLO does not request OEM
// fallback.
func TestHPEVmediaRedfishOEMFallbackFalse(t *testing.T) {
	q := Resolve("HPE", "ProLiant DL380 Gen10")

	assert.False(t, q.VmediaRedfishOEMFallback)
}

// TestResolveVeloCloudEDGE840 verifies the VeloCloud Networks EDGE840
// (Supermicro X10SDV silicon under an OEM SMBIOS skin) inherits every
// X10 quirk the orchestrator needs to bootstrap a node whose disk
// already holds a UEFI Linux entry. Without these, the X10 BIOS erases
// "Once" overrides before POST and the node falls back to the on-disk
// installation, causing the install-log probe to time out.
func TestResolveVeloCloudEDGE840(t *testing.T) {
	q := Resolve("VeloCloud Networks, Inc.", "EDGE840")

	assert.Equal(t, "VeloCloud Networks, Inc.", q.Manufacturer,
		"VeloCloud entry must be selected (not the generic Default)")
	assert.True(t, q.BootOverrideContinuous,
		"X10 ATEN BMC erases Once overrides before BIOS POST — must force Continuous")
	assert.Equal(t, "smc-oem-ipmi", q.BootOverrideStrategy,
		"OEM IPMI 0x30/0x70/0x0c is honored by ATEN firmware where standard PATCH is not")
	assert.True(t, q.VmediaRedfishOEMFallback,
		"X10 ATEN BMC 404s standard EjectMedia — fallback signal must be set")
	assert.Equal(t, "NT1", q.SambaMinProtocol,
		"X10 ATEN BMC only speaks SMB1 for virtual-media mounts")
	assert.Equal(t, "UefiUsbCd", q.BootMediaType.UEFICDAlias,
		"ATEN virtual media boots from the UEFI USB CD/DVD class on this BMC")
}

// TestResolveVeloCloudCaseInsensitive verifies the lookup matches even
// when Redfish returns mixed-case or trimmed manufacturer/model strings.
func TestResolveVeloCloudCaseInsensitive(t *testing.T) {
	q := Resolve("  velocloud networks, inc.  ", "edge840")

	assert.Equal(t, "VeloCloud Networks, Inc.", q.Manufacturer,
		"manufacturer match must be case- and whitespace-insensitive")
}

// --- helpers ---

// assertContainsParam checks that params contains the expected string.
func assertContainsParam(t *testing.T, params []string, expected string) {
	t.Helper()
	for _, p := range params {
		if p == expected {
			return
		}
	}
	t.Errorf("expected kernel param %q not found in %v", expected, params)
}

// assertLastConsoleParam checks that the last console= entry in params
// equals expected (last wins as the primary Linux console).
func assertLastConsoleParam(t *testing.T, params []string, expected string) {
	t.Helper()
	last := ""
	for _, p := range params {
		if len(p) >= 8 && p[:8] == "console=" {
			last = p
		}
	}
	assert.Equal(t, expected, last, "expected %q to be the last console= param", expected)
}
