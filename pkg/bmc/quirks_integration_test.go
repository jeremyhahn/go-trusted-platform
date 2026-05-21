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
	"errors"
	"log/slog"
	"net/http"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/quirks"
)

// ---------------------------------------------------------------------------
// pickBootSourceOverrideTarget / buildBootTargetCandidates
// ---------------------------------------------------------------------------

// TestPickBootSourceOverrideTarget_NoAllowableValuesReturnsDMTF verifies the
// older-BMC fallback path: when AllowableValues is empty, the DMTF-standard
// value from redfishBootDeviceMap is returned regardless of vendor quirks.
func TestPickBootSourceOverrideTarget_NoAllowableValuesReturnsDMTF(t *testing.T) {
	q := quirks.Resolve("Supermicro", "X10SDV-TP8F")
	got := pickBootSourceOverrideTarget(BootDeviceCDROM, nil, q)
	if got != "Cd" {
		t.Errorf("pickBootSourceOverrideTarget with empty allowable = %q, want %q", got, "Cd")
	}
}

// TestPickBootSourceOverrideTarget_NoAllowableValuesUnknownDevice verifies the
// empty-string fallthrough when device has no entry in redfishBootDeviceMap.
func TestPickBootSourceOverrideTarget_NoAllowableValuesUnknownDevice(t *testing.T) {
	q := quirks.Default()
	got := pickBootSourceOverrideTarget(BootDevice("nonexistent"), nil, q)
	if got != "" {
		t.Errorf("pickBootSourceOverrideTarget with unknown device = %q, want empty", got)
	}
}

// TestPickBootSourceOverrideTarget_X10WithCDDVDAlias verifies the Supermicro
// X10 path: the BMC advertises "CD/DVD" with a slash and "UefiCd"; the picker
// must select the UEFI variant first.
func TestPickBootSourceOverrideTarget_X10WithCDDVDAlias(t *testing.T) {
	q := quirks.Resolve("Supermicro", "X10SDV-TP8F")
	allowable := []string{"None", "Pxe", "Hdd", "CD/DVD", "BiosSetup", "UefiCd"}

	got := pickBootSourceOverrideTarget(BootDeviceCDROM, allowable, q)
	if got != "UefiCd" {
		t.Errorf("X10 picker = %q, want %q (UEFI wins)", got, "UefiCd")
	}
}

// TestPickBootSourceOverrideTarget_X10OnlyCDDVDAdvertised verifies that when
// only the BIOS-mode "CD/DVD" alias is advertised, the picker picks it over
// the DMTF default.
func TestPickBootSourceOverrideTarget_X10OnlyCDDVDAdvertised(t *testing.T) {
	q := quirks.Resolve("Supermicro", "X10SDV-TP8F")
	allowable := []string{"None", "Pxe", "Hdd", "CD/DVD"}

	got := pickBootSourceOverrideTarget(BootDeviceCDROM, allowable, q)
	if got != "CD/DVD" {
		t.Errorf("X10 picker (only CD/DVD) = %q, want %q", got, "CD/DVD")
	}
}

// TestPickBootSourceOverrideTarget_X10PrefersVendorUEFIOverUSBCD verifies
// that when the BMC advertises both "UefiCd" (the slot the BMC actually
// routes virtual media to on X10) AND "UefiUsbCd" (an empty USB CD slot),
// the vendor UEFI CD alias wins. The previous implementation preferred
// UefiUsbCd on Supermicro hardware and silently broke vmedia boot — the
// X10 BIOS would set boot target = UefiUsbCd, find no media in that
// USB CD slot, and fall through to disk.
func TestPickBootSourceOverrideTarget_X10PrefersVendorUEFIOverUSBCD(t *testing.T) {
	q := quirks.Resolve("Supermicro", "X10SDV-TP8F")
	allowable := []string{"None", "Pxe", "Hdd", "CD/DVD", "UefiCd", "UefiUsbCd"}

	got := pickBootSourceOverrideTarget(BootDeviceCDROM, allowable, q)
	if got != "UefiCd" {
		t.Errorf("X10 picker = %q, want %q (vendor UEFI alias must beat USB-CD)", got, "UefiCd")
	}
}

// TestPickBootSourceOverrideTarget_X10USBCDOnlyLastResort verifies the
// final-fallback behavior: when the BMC advertises ONLY USB-CD targets
// and no real CD/DVD slot, the picker reluctantly returns UefiUsbCd as
// the last-resort match. This is the only configuration where the USB
// alias should be selected.
func TestPickBootSourceOverrideTarget_X10USBCDOnlyLastResort(t *testing.T) {
	q := quirks.Resolve("Supermicro", "X10SDV-TP8F")
	allowable := []string{"None", "Pxe", "Hdd", "UefiUsbCd"}

	got := pickBootSourceOverrideTarget(BootDeviceCDROM, allowable, q)
	if got != "UefiUsbCd" {
		t.Errorf("X10 picker with only USB-CD = %q, want %q (last-resort fallback)", got, "UefiUsbCd")
	}
}

// TestPickBootSourceOverrideTarget_DellDMTF verifies the Dell path: only DMTF
// values are advertised and selected.
func TestPickBootSourceOverrideTarget_DellDMTF(t *testing.T) {
	q := quirks.Resolve("Dell Inc.", "PowerEdge R640")
	allowable := []string{"None", "Pxe", "Hdd", "Cd", "UefiCd", "UefiHdd"}

	got := pickBootSourceOverrideTarget(BootDeviceCDROM, allowable, q)
	if got != "UefiCd" {
		t.Errorf("Dell picker = %q, want %q", got, "UefiCd")
	}
}

// TestPickBootSourceOverrideTarget_DellDoesNotMatchVendorAlias ensures Dell
// does not pick "CD/DVD" even if the BMC happens to advertise it — Dell's
// quirk does not declare the alias.
func TestPickBootSourceOverrideTarget_DellDoesNotMatchVendorAlias(t *testing.T) {
	q := quirks.Resolve("Dell Inc.", "PowerEdge R640")
	allowable := []string{"None", "CD/DVD", "Cd"}

	got := pickBootSourceOverrideTarget(BootDeviceCDROM, allowable, q)
	if got != "Cd" {
		t.Errorf("Dell picker should pick DMTF Cd not CD/DVD; got %q", got)
	}
}

// TestPickBootSourceOverrideTarget_PXEUnaffectedByVendorAliases verifies that
// non-CD boot devices (PXE) are not affected by the BootMediaType quirk.
func TestPickBootSourceOverrideTarget_PXEUnaffectedByVendorAliases(t *testing.T) {
	q := quirks.Resolve("Supermicro", "X10SDV-TP8F")
	allowable := []string{"Pxe", "UefiPxe"}

	got := pickBootSourceOverrideTarget(BootDevicePXE, allowable, q)
	if got != "UefiPxe" {
		t.Errorf("PXE picker = %q, want %q", got, "UefiPxe")
	}
}

// TestPickBootSourceOverrideTarget_DMTFCDViaPreferenceLoop verifies that for
// the default (non-vendor) Quirk, the DMTF "Cd" value is selected via the
// preference loop.
func TestPickBootSourceOverrideTarget_DMTFCDViaPreferenceLoop(t *testing.T) {
	q := quirks.Default()
	allowable := []string{"Cd"}
	got := pickBootSourceOverrideTarget(BootDeviceCDROM, allowable, q)
	if got != "Cd" {
		t.Errorf("picker = %q, want %q", got, "Cd")
	}
}

// TestPickBootSourceOverrideTarget_NoMatchAtAll verifies that when the BMC
// advertises no recognizable boot targets, an empty string is returned.
func TestPickBootSourceOverrideTarget_NoMatchAtAll(t *testing.T) {
	q := quirks.Default()
	allowable := []string{"Floppy", "Tape"} // nothing recognizable

	got := pickBootSourceOverrideTarget(BootDeviceCDROM, allowable, q)
	if got != "" {
		t.Errorf("picker = %q, want empty (no match)", got)
	}
}

// TestBuildBootTargetCandidates_NonCDDeviceUsesDefaults verifies that for
// non-CD devices the candidate list is the unmodified DMTF preference list.
func TestBuildBootTargetCandidates_NonCDDeviceUsesDefaults(t *testing.T) {
	q := quirks.Resolve("Supermicro", "X10SDV-TP8F")
	candidates := buildBootTargetCandidates(BootDevicePXE, q)
	want := []string{"UefiPxe", "Pxe"}

	if len(candidates) != len(want) {
		t.Fatalf("PXE candidates = %v, want %v", candidates, want)
	}
	for i, v := range want {
		if candidates[i] != v {
			t.Errorf("candidates[%d] = %q, want %q", i, candidates[i], v)
		}
	}
}

// TestBuildBootTargetCandidates_NoneDevice verifies the BootDeviceNone path.
func TestBuildBootTargetCandidates_NoneDevice(t *testing.T) {
	q := quirks.Default()
	candidates := buildBootTargetCandidates(BootDeviceNone, q)
	if len(candidates) != 1 || candidates[0] != "None" {
		t.Errorf("None candidates = %v, want [None]", candidates)
	}
}

// TestBuildBootTargetCandidates_X10HasFullVendorChain verifies that for the
// X10SDV quirk the candidate list includes the vendor UEFI alias, USB-CD
// aliases, the BIOS-mode alias, and the DMTF defaults — without duplicates.
func TestBuildBootTargetCandidates_X10HasFullVendorChain(t *testing.T) {
	q := quirks.Resolve("Supermicro", "X10SDV-TP8F")
	candidates := buildBootTargetCandidates(BootDeviceCDROM, q)

	// Must contain each expected alias exactly once.
	mustContain := []string{"UefiCd", "UefiUsbCd", "UsbCd", "CD/DVD", "Cd"}
	count := make(map[string]int, len(candidates))
	for _, v := range candidates {
		count[v]++
	}
	for _, v := range mustContain {
		if count[v] != 1 {
			t.Errorf("candidate %q appeared %d times, want 1; full list: %v", v, count[v], candidates)
		}
	}
}

// TestBuildBootTargetCandidates_DellHasNoVendorChain verifies that for Dell
// (no vendor BootMediaType) the candidate list is the unmodified DMTF list.
func TestBuildBootTargetCandidates_DellHasNoVendorChain(t *testing.T) {
	q := quirks.Resolve("Dell Inc.", "PowerEdge R640")
	candidates := buildBootTargetCandidates(BootDeviceCDROM, q)
	want := []string{"UefiCd", "Cd"}

	if len(candidates) != len(want) {
		t.Fatalf("Dell candidates = %v, want %v", candidates, want)
	}
	for i, v := range want {
		if candidates[i] != v {
			t.Errorf("candidates[%d] = %q, want %q", i, candidates[i], v)
		}
	}
}

// TestBuildBootTargetCandidates_DefaultQuirkHasNoVendorChain verifies that the
// Default quirk produces only the DMTF preference list — no vendor aliases.
func TestBuildBootTargetCandidates_DefaultQuirkHasNoVendorChain(t *testing.T) {
	candidates := buildBootTargetCandidates(BootDeviceCDROM, quirks.Default())

	for _, v := range candidates {
		if v == "CD/DVD" || v == "UefiUsbCd" || v == "UsbCd" {
			t.Errorf("Default quirk produced vendor alias %q in %v", v, candidates)
		}
	}
}

// ---------------------------------------------------------------------------
// redfishClient cached identifiers + resolveQuirk
// ---------------------------------------------------------------------------

// TestRedfishClient_CachedManufacturerModelEmpty verifies the getter behaviour
// before discovery runs: empty strings without panic.
func TestRedfishClient_CachedManufacturerModelEmpty(t *testing.T) {
	c := &redfishClient{}
	if got := c.getManufacturer(); got != "" {
		t.Errorf("pre-discovery manufacturer = %q, want empty", got)
	}
	if got := c.getModel(); got != "" {
		t.Errorf("pre-discovery model = %q, want empty", got)
	}
	q := c.resolveQuirk()
	want := quirks.Default()
	if q.SOLPort != want.SOLPort {
		t.Errorf("resolveQuirk SOLPort = %q, want %q", q.SOLPort, want.SOLPort)
	}
}

// TestRedfishClient_CachedManufacturerModelStored verifies the cached values
// drive resolveQuirk to the matching registry entry once stored.
func TestRedfishClient_CachedManufacturerModelStored(t *testing.T) {
	c := &redfishClient{}
	c.manufacturer.Store("Supermicro")
	c.model.Store("X10SDV-TP8F")

	if got := c.getManufacturer(); got != "Supermicro" {
		t.Errorf("getManufacturer() = %q, want %q", got, "Supermicro")
	}
	if got := c.getModel(); got != "X10SDV-TP8F" {
		t.Errorf("getModel() = %q, want %q", got, "X10SDV-TP8F")
	}
	q := c.resolveQuirk()
	if !q.VmediaRedfishOEMFallback {
		t.Errorf("resolveQuirk for X10SDV-TP8F should signal OEM fallback")
	}
	if q.BootMediaType.CDDVDAlias != "CD/DVD" {
		t.Errorf("resolveQuirk for X10SDV-TP8F BootMediaType.CDDVDAlias = %q, want %q",
			q.BootMediaType.CDDVDAlias, "CD/DVD")
	}
}

// ---------------------------------------------------------------------------
// vmediaRedfishStd.maybeTranslateOEMFallback
// ---------------------------------------------------------------------------

// TestMaybeTranslateOEMFallback_NilErrorReturnsNil verifies the no-op path.
func TestMaybeTranslateOEMFallback_NilErrorReturnsNil(t *testing.T) {
	c := &redfishClient{}
	c.manufacturer.Store("Dell Inc.")
	c.model.Store("PowerEdge R640")
	b := newVmediaRedfishStd(c)

	if got := b.maybeTranslateOEMFallback(nil, "InsertMedia", "test"); got != nil {
		t.Errorf("maybeTranslateOEMFallback(nil) = %v, want nil", got)
	}
}

// TestMaybeTranslateOEMFallback_NonRedfishErrorPropagates verifies that a
// generic error not wrapping ErrRedfishRequest passes through unchanged.
func TestMaybeTranslateOEMFallback_NonRedfishErrorPropagates(t *testing.T) {
	c := &redfishClient{}
	c.manufacturer.Store("Supermicro")
	c.model.Store("X10SDV-TP8F")
	b := newVmediaRedfishStd(c)

	in := errors.New("generic transport error")
	got := b.maybeTranslateOEMFallback(in, "InsertMedia", "test")
	if got != in {
		t.Errorf("non-Redfish error must propagate; got %v, want %v", got, in)
	}
}

// TestMaybeTranslateOEMFallback_Non404RedfishErrorPropagates verifies that a
// 500 / 503 from the BMC propagates unchanged regardless of vendor.
func TestMaybeTranslateOEMFallback_Non404RedfishErrorPropagates(t *testing.T) {
	c := &redfishClient{}
	c.manufacturer.Store("Supermicro")
	c.model.Store("X10SDV-TP8F")
	b := newVmediaRedfishStd(c)

	in := ErrRedfishRequest{StatusCode: 500, Message: "internal"}
	got := b.maybeTranslateOEMFallback(in, "InsertMedia", "test")
	var rErr ErrRedfishRequest
	if !errors.As(got, &rErr) || rErr.StatusCode != 500 {
		t.Errorf("non-404 must propagate; got %v", got)
	}
}

// TestMaybeTranslateOEMFallback_X10_404TranslatedToUnsupported verifies the
// X10 path: a 404 is translated to ErrVirtualMediaUnsupported because the
// resolved Quirk advertises VmediaRedfishOEMFallback.
func TestMaybeTranslateOEMFallback_X10_404TranslatedToUnsupported(t *testing.T) {
	c := &redfishClient{}
	c.manufacturer.Store("Supermicro")
	c.model.Store("X10SDV-TP8F")
	b := newVmediaRedfishStd(c)

	in := ErrRedfishRequest{StatusCode: http.StatusNotFound, Message: "Not Found"}
	got := b.maybeTranslateOEMFallback(in, "EjectMedia", "firmware does not support eject")

	var unsup ErrVirtualMediaUnsupported
	if !errors.As(got, &unsup) {
		t.Fatalf("X10 404 must be translated; got %T %v", got, got)
	}
	if unsup.Backend != "redfish-std" {
		t.Errorf("translated Backend = %q, want %q", unsup.Backend, "redfish-std")
	}
}

// TestMaybeTranslateOEMFallback_Dell_404Propagates verifies the Dell path:
// a 404 propagates unchanged because Dell's Quirk does not request OEM
// fallback (Dell iDRAC fully supports the standard Redfish vmedia actions).
func TestMaybeTranslateOEMFallback_Dell_404Propagates(t *testing.T) {
	c := &redfishClient{}
	c.manufacturer.Store("Dell Inc.")
	c.model.Store("PowerEdge R640")
	b := newVmediaRedfishStd(c)

	in := ErrRedfishRequest{StatusCode: http.StatusNotFound, Message: "Not Found"}
	got := b.maybeTranslateOEMFallback(in, "EjectMedia", "test")

	var unsup ErrVirtualMediaUnsupported
	if errors.As(got, &unsup) {
		t.Errorf("Dell 404 must propagate as 404, not be translated; got translated %v", got)
	}
	var rErr ErrRedfishRequest
	if !errors.As(got, &rErr) || rErr.StatusCode != http.StatusNotFound {
		t.Errorf("Dell 404 must propagate unchanged; got %v", got)
	}
}

// TestMaybeTranslateOEMFallback_UnknownVendor_404Propagates verifies that an
// unidentified vendor (resolves to Default quirk) propagates 404 unchanged.
func TestMaybeTranslateOEMFallback_UnknownVendor_404Propagates(t *testing.T) {
	c := &redfishClient{}
	// Empty manufacturer/model resolves to Default — no OEM fallback.
	b := newVmediaRedfishStd(c)

	in := ErrRedfishRequest{StatusCode: http.StatusNotFound, Message: "Not Found"}
	got := b.maybeTranslateOEMFallback(in, "EjectMedia", "test")

	var unsup ErrVirtualMediaUnsupported
	if errors.As(got, &unsup) {
		t.Errorf("Default quirk 404 must propagate unchanged; got translated %v", got)
	}
}

// ---------------------------------------------------------------------------
// Vendor.ManufacturerString
// ---------------------------------------------------------------------------

// TestVendorManufacturerString verifies the Vendor → canonical manufacturer
// string mapping used by AutoCertManager to resolve the Quirk for fallback
// chain selection.
func TestVendorManufacturerString(t *testing.T) {
	tests := []struct {
		v    Vendor
		want string
	}{
		{VendorSupermicro, "Supermicro"},
		{VendorDell, "Dell Inc."},
		{VendorHPE, "HPE"},
		{VendorLenovo, "Lenovo"},
		{VendorUnknown, ""},
		{VendorGeneric, ""},
	}
	for _, tc := range tests {
		t.Run(string(tc.v), func(t *testing.T) {
			got := tc.v.ManufacturerString()
			if got != tc.want {
				t.Errorf("Vendor(%q).ManufacturerString() = %q, want %q", tc.v, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AutoCertManager.wireFallbackBackend
// ---------------------------------------------------------------------------

// withFakeCGIFactory swaps the registered CertBackendSMCCGI factory for the
// duration of the test, restoring whatever (if anything) was registered
// before. The cleanup runs as a t.Cleanup hook.
func withFakeCGIFactory(t *testing.T, factory CertManagerFactory) {
	t.Helper()
	original, had := lookupCertFactory(CertBackendSMCCGI)
	if factory == nil {
		certFactoriesMu.Lock()
		delete(certFactories, CertBackendSMCCGI)
		certFactoriesMu.Unlock()
	} else {
		RegisterCertFactory(CertBackendSMCCGI, factory)
	}
	t.Cleanup(func() {
		if had {
			RegisterCertFactory(CertBackendSMCCGI, original)
			return
		}
		certFactoriesMu.Lock()
		delete(certFactories, CertBackendSMCCGI)
		certFactoriesMu.Unlock()
	})
}

// TestWireFallbackBackend_SupermicroWithCGIAllowed verifies the Supermicro
// path: the resolved Quirk lists ["redfish", "smc-cgi"]; given the resolved
// primary is redfish and AllowCGIFallback is true, the fallback must be the
// SMC-CGI manager.
func TestWireFallbackBackend_SupermicroWithCGIAllowed(t *testing.T) {
	cfg := baseCfg("x", 443)
	cfg.AllowCGIFallback = true
	m, err := NewAutoCertManager(cfg, CertBackendAuto, nil)
	if err != nil {
		t.Fatalf("NewAutoCertManager: %v", err)
	}

	withFakeCGIFactory(t, fakeFactoryReturning(&fakeCertManager{backend: CertBackendSMCCGI}))

	fb := m.wireFallbackBackend(VendorSupermicro, CertBackendRedfish)
	if fb == nil {
		t.Fatal("wireFallbackBackend returned nil for Supermicro+CGI-allowed")
	}
	if fb.Backend() != CertBackendSMCCGI {
		t.Errorf("fallback backend = %q, want %q", fb.Backend(), CertBackendSMCCGI)
	}
}

// TestWireFallbackBackend_SupermicroWithCGIDenied verifies the gate: when
// AllowCGIFallback is false the SMC-CGI candidate is skipped, and since the
// only other entry is "redfish" (== primary), no fallback is wired.
func TestWireFallbackBackend_SupermicroWithCGIDenied(t *testing.T) {
	cfg := baseCfg("x", 443)
	cfg.AllowCGIFallback = false
	m, err := NewAutoCertManager(cfg, CertBackendAuto, nil)
	if err != nil {
		t.Fatalf("NewAutoCertManager: %v", err)
	}

	withFakeCGIFactory(t, fakeFactoryReturning(&fakeCertManager{backend: CertBackendSMCCGI}))

	fb := m.wireFallbackBackend(VendorSupermicro, CertBackendRedfish)
	if fb != nil {
		t.Errorf("CGI gated but wireFallbackBackend returned %v", fb)
	}
}

// TestWireFallbackBackend_DellNoFallback verifies Dell has no fallback chain
// in its Quirk so wireFallbackBackend returns nil.
func TestWireFallbackBackend_DellNoFallback(t *testing.T) {
	cfg := baseCfg("x", 443)
	cfg.AllowCGIFallback = true
	m, err := NewAutoCertManager(cfg, CertBackendAuto, nil)
	if err != nil {
		t.Fatalf("NewAutoCertManager: %v", err)
	}

	fb := m.wireFallbackBackend(VendorDell, CertBackendRedfish)
	if fb != nil {
		t.Errorf("Dell fallback = %v, want nil", fb)
	}
}

// TestWireFallbackBackend_UnknownVendorNoFallback verifies an unrecognised
// vendor resolves to Default (no fallback chain) so the function returns nil.
func TestWireFallbackBackend_UnknownVendorNoFallback(t *testing.T) {
	cfg := baseCfg("x", 443)
	cfg.AllowCGIFallback = true
	m, err := NewAutoCertManager(cfg, CertBackendAuto, nil)
	if err != nil {
		t.Fatalf("NewAutoCertManager: %v", err)
	}
	fb := m.wireFallbackBackend(VendorUnknown, CertBackendRedfish)
	if fb != nil {
		t.Errorf("Unknown vendor fallback = %v, want nil", fb)
	}
}

// TestWireFallbackBackend_FactoryUnavailableSkipped verifies that when a
// fallback chain entry has no registered factory, that entry is skipped and
// the function continues to the next candidate (or returns nil).
func TestWireFallbackBackend_FactoryUnavailableSkipped(t *testing.T) {
	cfg := baseCfg("x", 443)
	cfg.AllowCGIFallback = true
	m, err := NewAutoCertManager(cfg, CertBackendAuto, nil)
	if err != nil {
		t.Fatalf("NewAutoCertManager: %v", err)
	}

	// Unregister the SMC-CGI factory for this test.
	withFakeCGIFactory(t, nil)

	fb := m.wireFallbackBackend(VendorSupermicro, CertBackendRedfish)
	if fb != nil {
		t.Errorf("expected nil when fallback factory not registered; got %v", fb)
	}
}

// TestWireFallbackBackend_FactoryConstructionErrorSkipped verifies that when
// the candidate factory returns an error, that candidate is skipped.
func TestWireFallbackBackend_FactoryConstructionErrorSkipped(t *testing.T) {
	cfg := baseCfg("x", 443)
	cfg.AllowCGIFallback = true
	m, err := NewAutoCertManager(cfg, CertBackendAuto, nil)
	if err != nil {
		t.Fatalf("NewAutoCertManager: %v", err)
	}

	withFakeCGIFactory(t, fakeFactoryError(errors.New("boom")))

	fb := m.wireFallbackBackend(VendorSupermicro, CertBackendRedfish)
	if fb != nil {
		t.Errorf("expected nil when factory errors; got %v", fb)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// fakeFactoryReturning returns a factory that always yields fb (and nil error).
func fakeFactoryReturning(fb ManagedCertificateManager) CertManagerFactory {
	return func(_ *Config, _ *slog.Logger) (ManagedCertificateManager, error) {
		return fb, nil
	}
}

// fakeFactoryError returns a factory that always errors.
func fakeFactoryError(err error) CertManagerFactory {
	return func(_ *Config, _ *slog.Logger) (ManagedCertificateManager, error) {
		return nil, err
	}
}
