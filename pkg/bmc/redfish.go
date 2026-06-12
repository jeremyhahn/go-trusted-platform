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
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-trusted-platform/pkg/quirks"
)

// redfishBootDeviceMap maps BMC BootDevice values to Redfish BootSourceOverrideTarget values.
// This is the DMTF-standard value per ComputerSystem.v1_x_y.Boot schema; used as
// the final fallback when no vendor-specific match is found in AllowableValues.
var redfishBootDeviceMap = map[BootDevice]string{
	BootDevicePXE:          "Pxe",
	BootDeviceDisk:         "Hdd",
	BootDeviceCDROM:        "Cd",
	BootDeviceVirtualMedia: "Cd",
	BootDeviceNone:         "None",
}

// redfishBootDevicePreferences lists the DMTF-standard BootSourceOverrideTarget
// candidates per BMC BootDevice, in priority order. UEFI variants are listed
// first so they win when both forms are advertised — platform builds boot via
// UKI + Secure Boot.
//
// Vendor-specific deviations (e.g. Supermicro X10's "CD/DVD" with a slash, or
// the ATEN-emulated "UefiUsbCd" / "UsbCd") are NOT listed here. They are
// woven in dynamically by pickBootSourceOverrideTarget from the resolved
// quirks.Quirk.BootMediaType for the host's manufacturer/model. This keeps
// pkg/bmc free of manufacturer string comparisons.
var redfishBootDevicePreferences = map[BootDevice][]string{
	BootDevicePXE:          {"UefiPxe", "Pxe"},
	BootDeviceDisk:         {"UefiHdd", "Hdd"},
	BootDeviceCDROM:        {"UefiCd", "Cd"},
	BootDeviceVirtualMedia: {"UefiCd", "Cd"},
	BootDeviceNone:         {"None"},
}

// vendorUSBCDFallbacks lists USB-CD aliases that some BMCs advertise
// alongside the standard CD/DVD targets. They are tried only as a
// last-resort fallback because most hardware that exposes them does NOT
// actually route virtual-media to those slots — on Supermicro X10
// specifically, the virtual CD is exposed as a real CD/DVD device,
// not a USB CDROM, so picking UefiUsbCd here would silently fail at
// boot. The previous design preferred these aliases first; that broke
// X10 vmedia boot by sending the BIOS to a slot with no media.
var vendorUSBCDFallbacks = []string{"UefiUsbCd", "UsbCd"}

// redfishBootDeviceReverse maps Redfish BootSourceOverrideTarget values back to
// BMC BootDevice. Includes vendor-specific values so VerifyBootDevice() can
// reconcile state on any BMC regardless of the target string it advertises.
var redfishBootDeviceReverse = map[string]BootDevice{
	"Pxe":       BootDevicePXE,
	"UefiPxe":   BootDevicePXE,
	"Hdd":       BootDeviceDisk,
	"UefiHdd":   BootDeviceDisk,
	"Cd":        BootDeviceCDROM,
	"UefiCd":    BootDeviceCDROM,
	"CD/DVD":    BootDeviceCDROM,
	"UsbCd":     BootDeviceCDROM,
	"UefiUsbCd": BootDeviceCDROM,
	"None":      BootDeviceNone,
}

// pickBootSourceOverrideTarget selects the best BootSourceOverrideTarget
// string for device against the BMC's advertised allowable values, using
// the resolved hardware Quirk to weave in vendor-specific CD/DVD aliases.
//
// The candidate list is constructed by:
//  1. The quirk's vendor UEFI CD alias first (e.g. Supermicro X10
//     "UefiCd"). When the BIOS is UEFI-mode this is the slot the BMC
//     actually routes virtual media to.
//  2. The quirk's vendor BIOS-mode CD alias (e.g. Supermicro X10
//     "CD/DVD" with the slash). Used when the BIOS is in Legacy mode.
//  3. DMTF-standard preferences from redfishBootDevicePreferences[device]
//     (UefiCd, then Cd).
//  4. USB-CD fallbacks (UefiUsbCd, UsbCd) — only as a last resort. Some
//     BMCs advertise these but do NOT actually route virtual media to
//     them. Preferring them early (the previous behavior) broke X10
//     vmedia boot by sending the BIOS to an empty USB CD slot.
//
// When allowable is empty (older BMCs that don't advertise AllowableValues),
// the DMTF-standard value from redfishBootDeviceMap is returned as a best-
// effort fallback.
func pickBootSourceOverrideTarget(device BootDevice, allowable []string, quirk quirks.Quirk) string {
	if len(allowable) == 0 {
		if v, ok := redfishBootDeviceMap[device]; ok {
			return v
		}
		return ""
	}
	allowed := make(map[string]struct{}, len(allowable))
	for _, v := range allowable {
		allowed[v] = struct{}{}
	}

	candidates := buildBootTargetCandidates(device, quirk)
	for _, candidate := range candidates {
		if _, ok := allowed[candidate]; ok {
			return candidate
		}
	}
	// Nothing in the preference list matches — fall through to the DMTF
	// value if the BMC happens to accept it.
	if v, ok := redfishBootDeviceMap[device]; ok {
		if _, advertised := allowed[v]; advertised {
			return v
		}
	}
	return ""
}

// buildBootTargetCandidates returns the ordered list of BootSourceOverrideTarget
// strings to try for device, weaving in vendor-specific CD aliases from quirk
// before the DMTF-standard preferences. Duplicate entries are suppressed so
// the function output is a clean priority chain.
func buildBootTargetCandidates(device BootDevice, quirk quirks.Quirk) []string {
	defaults := redfishBootDevicePreferences[device]
	// Vendor aliases only apply to CD/virtual-media boot targets.
	isCDTarget := device == BootDeviceCDROM || device == BootDeviceVirtualMedia
	if !isCDTarget {
		out := make([]string, len(defaults))
		copy(out, defaults)
		return out
	}

	media := quirk.BootMediaType
	hasVendorAliases := media.UEFICDAlias != "" || media.CDDVDAlias != ""

	// Pre-size: defaults + 2 vendor aliases + 2 USB aliases.
	out := make([]string, 0, len(defaults)+4)
	seen := make(map[string]struct{}, len(defaults)+4)
	add := func(s string) {
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	// Vendor UEFI CD alias FIRST — this is the slot the BMC routes
	// virtual media to on UEFI-mode hosts. On Supermicro X10 this is
	// "UefiCd"; on other vendors it may differ.
	add(media.UEFICDAlias)
	// Vendor BIOS-mode alias next (e.g. "CD/DVD" with slash on
	// Supermicro X10) for hosts in Legacy mode.
	add(media.CDDVDAlias)
	// DMTF-standard preferences (UefiCd, Cd) — universal fallback.
	for _, v := range defaults {
		add(v)
	}
	// USB-CD aliases LAST — some BMCs advertise them but do not route
	// virtual media there. Picking them early would silently break
	// vmedia boot on X10 (we did exactly that before this fix).
	if hasVendorAliases {
		for _, v := range vendorUSBCDFallbacks {
			add(v)
		}
	}
	return out
}

// redfishPowerStateMap maps Redfish PowerState strings to BMC PowerState values.
var redfishPowerStateMap = map[string]PowerState{
	"On":               PowerStateOn,
	"Off":              PowerStateOff,
	"PoweringOn":       PowerStateOn,
	"PoweringOff":      PowerStateOff,
	"Paused":           PowerStateOn,
	"GracefulShutdown": PowerStateOff,
}

// redfishClient implements the Client interface using the Redfish REST API.
type redfishClient struct {
	logger *slog.Logger
	closed atomic.Bool

	// config is the original Config the client was constructed
	// with. Kept so vendor-specific boot-override backends that
	// need to open their own out-of-band channel (e.g. an OEM
	// IPMI raw command session for the smc-oem-ipmi backend) can
	// reach back to the BMC credentials and address without
	// reconstructing a Config from the transport's fragments.
	config *Config

	// transport carries the shared HTTP + auth + error-parsing
	// plumbing. doGET/doPOST/doPATCH delegate to transport methods
	// so the wire logic lives in one place.
	transport *redfishTransport

	// Discovery state protected by sync.Once for lock-free subsequent reads.
	discoverOnce sync.Once
	discoverErr  error

	// Cached Redfish paths discovered from service root.
	systemPath       atomic.Value // string
	chassisPath      atomic.Value // string
	managerPath      atomic.Value // string
	virtualMediaPath atomic.Value // string
	resetActionPath  atomic.Value // string

	// Cached hardware identifiers from the system resource fetched at
	// discovery time. Used by code paths that need to resolve the
	// hardware Quirk without re-fetching the system resource (e.g. the
	// Redfish virtual-media backend's OEM-fallback gate). atomic.Value
	// gives lock-free read access for the common case.
	manufacturer atomic.Value // string
	model        atomic.Value // string
}

// Compile-time interface check.
var _ Client = (*redfishClient)(nil)

// newRedfishClient creates a new redfishClient with the given configuration.
func newRedfishClient(config *Config, logger *slog.Logger) (*redfishClient, error) {
	t, err := newRedfishTransport(context.Background(), config, logger)
	if err != nil {
		return nil, ErrRedfishTransportInit{Cause: err}
	}
	return &redfishClient{
		config:    config,
		logger:    logger,
		transport: t,
	}, nil
}

// discover performs Redfish service root discovery and caches resource paths.
// It is called via sync.Once to ensure discovery runs exactly once.
func (c *redfishClient) discover(ctx context.Context) error {
	c.discoverOnce.Do(func() {
		c.discoverErr = c.performDiscovery(ctx)
	})
	return c.discoverErr
}

// performDiscovery fetches the Redfish service root and resolves the first
// system, chassis, and manager resource paths from their respective collections.
func (c *redfishClient) performDiscovery(ctx context.Context) error {
	// Fetch service root.
	var root redfishServiceRoot
	if err := c.doGET(ctx, "/redfish/v1/", &root); err != nil {
		return ErrRedfishDiscovery{Resource: "service root", Cause: err}
	}

	// Discover first system.
	systemPath, err := c.discoverFirstMember(ctx, root.Systems.ODataID, "Systems")
	if err != nil {
		return err
	}
	c.systemPath.Store(systemPath)

	// Discover first chassis.
	//
	// Chassis discovery is non-fatal: the resource is only required by
	// GetSensors (Thermal + Power readings under Chassis/{id}/Thermal +
	// /Power). All other operations — power control, boot device,
	// virtual media — work off the System resource. The Supermicro X10
	// ATEN BMC firmware intermittently returns 503 for /redfish/v1/Chassis
	// even when the rest of the service is healthy; failing discovery
	// fast there would break unrelated operators. We log + continue;
	// GetSensors already degrades cleanly when chassisPath is empty.
	chassisPath, err := c.discoverFirstMember(ctx, root.Chassis.ODataID, "Chassis")
	if err != nil {
		c.logger.Warn("bmc: redfish chassis discovery failed; sensors will be unavailable",
			slog.String("error", err.Error()))
	} else {
		c.chassisPath.Store(chassisPath)
	}

	// Discover first manager.
	managerPath, err := c.discoverFirstMember(ctx, root.Managers.ODataID, "Managers")
	if err != nil {
		return err
	}
	c.managerPath.Store(managerPath)

	// Discover virtual media collection from the manager.
	virtualMediaPath, err := c.discoverVirtualMedia(ctx, managerPath)
	if err != nil {
		// Virtual media may not be available on all BMCs — log but don't fail.
		c.logger.Warn("bmc: redfish virtual media discovery failed",
			slog.String("error", err.Error()))
	} else {
		c.virtualMediaPath.Store(virtualMediaPath)
	}

	// Discover reset action target from the system, and cache the
	// hardware identifiers (manufacturer + model) for downstream Quirk
	// resolution without re-fetching the system resource.
	var sys redfishSystem
	if err := c.doGET(ctx, systemPath, &sys); err != nil {
		return ErrRedfishDiscovery{Resource: "system", Cause: err}
	}
	if sys.Actions.ComputerSystemReset.Target != "" {
		c.resetActionPath.Store(sys.Actions.ComputerSystemReset.Target)
	} else {
		// Fall back to standard path.
		c.resetActionPath.Store(systemPath + "/Actions/ComputerSystem.Reset")
	}
	c.manufacturer.Store(sys.Manufacturer)
	c.model.Store(sys.Model)

	return nil
}

// discoverFirstMember fetches a Redfish collection and returns the @odata.id
// of the first member.
func (c *redfishClient) discoverFirstMember(ctx context.Context, collectionPath string, resource string) (string, error) {
	if collectionPath == "" {
		return "", ErrRedfishDiscovery{Resource: resource, Cause: ErrRedfishEmptyCollection{Resource: resource}}
	}
	var collection redfishCollection
	if err := c.doGET(ctx, collectionPath, &collection); err != nil {
		return "", ErrRedfishDiscovery{Resource: resource, Cause: err}
	}
	if len(collection.Members) == 0 {
		return "", ErrRedfishDiscovery{Resource: resource, Cause: ErrRedfishEmptyCollection{Resource: resource}}
	}
	return collection.Members[0].ODataID, nil
}

// discoverVirtualMedia discovers the virtual media collection path from a manager resource.
func (c *redfishClient) discoverVirtualMedia(ctx context.Context, managerPath string) (string, error) {
	// The manager resource typically has a VirtualMedia link. We fetch the manager
	// and look for that link. Since our redfishSystem struct doesn't include manager
	// fields, we use a lightweight struct here.
	type managerResource struct {
		VirtualMedia redfishRef `json:"VirtualMedia"`
	}
	var mgr managerResource
	if err := c.doGET(ctx, managerPath, &mgr); err != nil {
		return "", ErrRedfishDiscovery{Resource: "VirtualMedia", Cause: err}
	}
	if mgr.VirtualMedia.ODataID == "" {
		return "", ErrRedfishDiscovery{Resource: "VirtualMedia",
			Cause: ErrRedfishEmptyCollection{Resource: "VirtualMedia"}}
	}
	return mgr.VirtualMedia.ODataID, nil
}

// ensureDiscovered ensures Redfish discovery has been performed.
func (c *redfishClient) ensureDiscovered(ctx context.Context) error {
	if c.closed.Load() {
		return ErrClientClosed{}
	}
	return c.discover(ctx)
}

// getSystemPath returns the cached system path.
func (c *redfishClient) getSystemPath() string {
	v := c.systemPath.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

// getChassisPath returns the cached chassis path.
func (c *redfishClient) getChassisPath() string {
	v := c.chassisPath.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

// getVirtualMediaPath returns the cached virtual media collection path.
func (c *redfishClient) getVirtualMediaPath() string {
	v := c.virtualMediaPath.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

// getResetActionPath returns the cached reset action target path.
func (c *redfishClient) getResetActionPath() string {
	v := c.resetActionPath.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

// getManufacturer returns the cached hardware manufacturer string captured
// during discovery. Returns "" if discovery has not run.
func (c *redfishClient) getManufacturer() string {
	v := c.manufacturer.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

// getModel returns the cached hardware model string captured during discovery.
// Returns "" if discovery has not run.
func (c *redfishClient) getModel() string {
	v := c.model.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

// resolveQuirk returns the platform Quirk for this BMC, derived from the
// cached hardware identifiers captured at discovery time.
func (c *redfishClient) resolveQuirk() quirks.Quirk {
	return quirks.Resolve(c.getManufacturer(), c.getModel())
}

// PowerStatus returns the current power state from the Redfish system resource.
func (c *redfishClient) PowerStatus(ctx context.Context) (PowerState, error) {
	if err := c.ensureDiscovered(ctx); err != nil {
		return PowerStateUnknown, err
	}
	var sys redfishSystem
	if err := c.doGET(ctx, c.getSystemPath(), &sys); err != nil {
		return PowerStateUnknown, ErrPowerOperation{Operation: "status", Cause: err}
	}
	if state, ok := redfishPowerStateMap[sys.PowerState]; ok {
		return state, nil
	}
	return PowerStateUnknown, nil
}

// PowerOn powers on the system via the Redfish ComputerSystem.Reset action.
func (c *redfishClient) PowerOn(ctx context.Context) error {
	return c.doResetAction(ctx, "On", "on")
}

// PowerOff powers off the system via the Redfish ComputerSystem.Reset action.
func (c *redfishClient) PowerOff(ctx context.Context) error {
	return c.doResetAction(ctx, "ForceOff", "off")
}

// PowerReset performs a hard reset via the Redfish ComputerSystem.Reset action.
func (c *redfishClient) PowerReset(ctx context.Context) error {
	return c.doResetAction(ctx, "ForceRestart", "reset")
}

// PowerCycle power cycles the system via the Redfish ComputerSystem.Reset action.
func (c *redfishClient) PowerCycle(ctx context.Context) error {
	return c.doResetAction(ctx, "PowerCycle", "cycle")
}

// doResetAction performs a ComputerSystem.Reset action with the given reset type.
func (c *redfishClient) doResetAction(ctx context.Context, resetType string, operation string) error {
	if err := c.ensureDiscovered(ctx); err != nil {
		return ErrPowerOperation{Operation: operation, Cause: err}
	}
	body := redfishResetBody{ResetType: resetType}
	if err := c.doPOST(ctx, c.getResetActionPath(), body, nil); err != nil {
		return ErrPowerOperation{Operation: operation, Cause: err}
	}
	return nil
}

// GetBootDevice returns the current boot device override from the Redfish system resource.
func (c *redfishClient) GetBootDevice(ctx context.Context) (BootDevice, error) {
	if err := c.ensureDiscovered(ctx); err != nil {
		return BootDeviceNone, err
	}
	var sys redfishSystem
	if err := c.doGET(ctx, c.getSystemPath(), &sys); err != nil {
		return BootDeviceNone, ErrBootDevice{Cause: err}
	}
	if dev, ok := redfishBootDeviceReverse[sys.Boot.BootSourceOverrideTarget]; ok {
		return dev, nil
	}
	return BootDeviceNone, nil
}

// SetBootDevice sets the boot device override via PATCH on the Redfish system resource.
//
// Vendor handling: different BMCs advertise different BootSourceOverrideTarget
// enum values. Dell/HPE follow the DMTF standard ("Cd", "Pxe", "Hdd"); Supermicro
// X10 uses "CD/DVD" with a slash + "UefiCd" for UEFI-mode boot. SetBootDevice
// resolves the platform Quirk from the system resource's Manufacturer/Model
// fields and passes its BootMediaType into pickBootSourceOverrideTarget so the
// vendor aliases are matched against the BMC's advertised
// BootSourceOverrideTarget@Redfish.AllowableValues. UEFI variants are preferred
// because platform builds boot via UKI + Secure Boot.
func (c *redfishClient) SetBootDevice(ctx context.Context, device BootDevice, persistent bool) error {
	if !device.IsValid() {
		return ErrInvalidBootDevice{Device: string(device)}
	}
	if err := c.ensureDiscovered(ctx); err != nil {
		return ErrBootDevice{Device: string(device), Cause: err}
	}

	// GET the system resource to discover the BMC's BootSourceOverrideTarget
	// AllowableValues and confirm the host's manufacturer/model. On X10
	// Supermicro this returns ["None","Pxe","Hdd","Diags","CD/DVD","BiosSetup",
	// ...,"UefiCd","UefiHdd",...].
	var sys redfishSystem
	if err := c.doGET(ctx, c.getSystemPath(), &sys); err != nil {
		return ErrBootDevice{Device: string(device), Cause: err}
	}

	quirk := quirks.Resolve(sys.Manufacturer, sys.Model)
	target := pickBootSourceOverrideTarget(device, sys.Boot.BootSourceOverrideTargetAllowableValues, quirk)
	if target == "" {
		return ErrInvalidBootDevice{Device: string(device)}
	}

	enabled := "Once"
	if persistent {
		enabled = "Continuous"
	}
	// Vendor quirk override: some BMCs (Supermicro X10 ATEN) silently
	// erase "Once" overrides before BIOS POST sees them, falling
	// through to the on-disk UEFI NVRAM entry. Force Continuous so the
	// override survives the X10 reset dance. The orchestrator is
	// expected to clear the override (BootDeviceNone, false) once the
	// install completes so the node boots from disk on the next cycle.
	if quirk.BootOverrideContinuous && enabled == "Once" {
		c.logger.Debug("bmc: quirk forcing BootSourceOverrideEnabled=Continuous",
			"manufacturer", sys.Manufacturer,
			"model", sys.Model)
		enabled = "Continuous"
	}

	// Vendor strategy: try the named fallback backend first when set.
	// Soft-fail (ErrBootOverrideUnsupported) routes to the standard
	// Redfish PATCH path; any other error propagates immediately.
	// Today the only registered strategy is "smc-cgi" for X10 boards;
	// it is a documented stub returning ErrBootOverrideUnsupported, so
	// the dispatch layer always falls through to PATCH until the wire
	// protocol is captured (see vboot_smc_cgi.go).
	if backend := c.bootOverrideBackend(quirk.BootOverrideStrategy); backend != nil {
		err := backend.SetBootDevice(ctx, device, persistent)
		if err == nil {
			c.logger.Info("bmc: boot device set via vendor strategy",
				"backend", quirk.BootOverrideStrategy,
				"device", string(device),
				"persistent", persistent)
			return nil
		}
		var unsupported ErrBootOverrideUnsupported
		if !errors.As(err, &unsupported) {
			return ErrBootDevice{Device: string(device), Cause: err}
		}
		c.logger.Debug("bmc: vendor boot strategy unsupported, falling through to Redfish PATCH",
			"backend", quirk.BootOverrideStrategy,
			"reason", unsupported.Reason)
	}

	patch := redfishBootPatch{
		Boot: redfishBootPatchInner{
			BootSourceOverrideTarget:  target,
			BootSourceOverrideEnabled: enabled,
		},
	}

	if err := c.doPATCH(ctx, c.getSystemPath(), patch); err != nil {
		return ErrBootDevice{Device: string(device), Cause: err}
	}
	return nil
}

// bootOverrideBackend returns the registered boot-override backend for
// the given strategy name, or nil if the strategy is empty or unknown.
// New strategies are registered by adding a case here.
func (c *redfishClient) bootOverrideBackend(strategy string) bootOverrideBackend {
	switch strategy {
	case "smc-cgi":
		return newVbootSmcCGI(c)
	case "smc-oem-ipmi":
		// Supermicro OEM IPMI 0x30/0x70/0x0c "Set Boot Option
		// Override". Honored by X10 ATEN firmware even when the
		// disk has a competing UEFI NVRAM boot entry, where
		// standard Redfish PATCH is silently ignored. See
		// pkg/bmc/vboot_smc_oem_ipmi.go for firmware-specific
		// device-code limitations.
		return newVbootSmcOEMIPMI(c)
	default:
		return nil
	}
}

// bootOverrideBackend is the per-vendor boot-override interface. The
// Redfish client tries the registered backend first when a quirk asks
// for one; soft failures fall through to the standard DMTF PATCH.
type bootOverrideBackend interface {
	Name() string
	SetBootDevice(ctx context.Context, device BootDevice, persistent bool) error
}

// ClearUEFIBootEntries asks the BMC to reset the host's UEFI NVRAM
// boot entries via the Redfish Bios.ResetBios action. The action is
// idempotent and takes effect on the next host reset.
//
// Discovery walks System.Bios → Bios.Actions["#Bios.ResetBios"].target.
// When the BMC does not expose the action (older Supermicro X10
// firmware is the canonical case) we return ErrUEFIBootClearUnsupported
// so callers can route to a vendor CGI fallback.
func (c *redfishClient) ClearUEFIBootEntries(ctx context.Context) error {
	if err := c.ensureDiscovered(ctx); err != nil {
		return ErrUEFIBootClearUnsupported{Cause: err}
	}

	// GET the System resource to locate the Bios link. The discovery
	// pass cached Manufacturer/Model already, but Bios is fetched fresh
	// here because BMC firmware updates can move/add the link.
	var sys redfishSystem
	if err := c.doGET(ctx, c.getSystemPath(), &sys); err != nil {
		return ErrUEFIBootClearUnsupported{
			Manufacturer: c.getManufacturer(),
			Model:        c.getModel(),
			Cause:        err,
		}
	}
	if sys.Bios.ODataID == "" {
		return ErrUEFIBootClearUnsupported{
			Manufacturer: sys.Manufacturer,
			Model:        sys.Model,
		}
	}

	var bios redfishBios
	if err := c.doGET(ctx, sys.Bios.ODataID, &bios); err != nil {
		return ErrUEFIBootClearUnsupported{
			Manufacturer: sys.Manufacturer,
			Model:        sys.Model,
			Cause:        err,
		}
	}
	if bios.Actions.ResetBios.Target == "" {
		return ErrUEFIBootClearUnsupported{
			Manufacturer: sys.Manufacturer,
			Model:        sys.Model,
		}
	}

	// Bios.ResetBios accepts an empty body per the DMTF schema. Some
	// BMCs require ResetType ("ResetAll" / "ResetAllWithRoot"); if the
	// empty body fails we re-attempt with ResetAll.
	if err := c.doPOST(ctx, bios.Actions.ResetBios.Target, struct{}{}, nil); err != nil {
		retryErr := c.doPOST(ctx, bios.Actions.ResetBios.Target, struct {
			ResetType string `json:"ResetType"`
		}{ResetType: "ResetAll"}, nil)
		if retryErr != nil {
			return ErrUEFIBootClearUnsupported{
				Manufacturer: sys.Manufacturer,
				Model:        sys.Model,
				Cause:        retryErr,
			}
		}
	}

	c.logger.Info("bmc: UEFI NVRAM boot entries cleared via Bios.ResetBios",
		"manufacturer", sys.Manufacturer,
		"model", sys.Model,
		"action_target", bios.Actions.ResetBios.Target)
	return nil
}

// GetSystemInfo returns system identification information from the Redfish system resource.
func (c *redfishClient) GetSystemInfo(ctx context.Context) (*SystemInfo, error) {
	if err := c.ensureDiscovered(ctx); err != nil {
		return nil, ErrInventory{Cause: err}
	}
	var sys redfishSystem
	if err := c.doGET(ctx, c.getSystemPath(), &sys); err != nil {
		return nil, ErrInventory{Cause: err}
	}

	powerState := PowerStateUnknown
	if state, ok := redfishPowerStateMap[sys.PowerState]; ok {
		powerState = state
	}

	return &SystemInfo{
		Manufacturer:    sys.Manufacturer,
		Product:         sys.Model,
		SerialNumber:    sys.SerialNumber,
		FirmwareVersion: fmt.Sprintf("CPU: %s (%d cores), RAM: %.0f GiB", sys.ProcessorSummary.Model, sys.ProcessorSummary.Count, sys.MemorySummary.TotalSystemMemoryGiB),
		BIOSVersion:     sys.BiosVersion,
		PowerState:      powerState,
	}, nil
}

// GetSensors returns sensor readings from the Redfish Thermal and Power resources.
func (c *redfishClient) GetSensors(ctx context.Context) ([]SensorReading, error) {
	if err := c.ensureDiscovered(ctx); err != nil {
		return nil, ErrSensorRead{Cause: err}
	}

	chassisPath := c.getChassisPath()
	sensors := make([]SensorReading, 0, 16)
	if chassisPath == "" {
		// Chassis was unreachable at discovery time (e.g., X10 ATEN
		// firmware returning 503). Without it, /Thermal and /Power
		// can't be addressed — return an empty reading set rather
		// than emitting bogus URLs.
		return sensors, nil
	}

	// Fetch thermal data.
	var thermal redfishThermal
	thermalErr := c.doGET(ctx, chassisPath+"/Thermal", &thermal)
	if thermalErr == nil {
		for i := range thermal.Temperatures {
			t := &thermal.Temperatures[i]
			sensors = append(sensors, SensorReading{
				Name:   t.Name,
				Value:  t.ReadingCelsius,
				Units:  "degrees C",
				Status: normalizeRedfishHealth(t.Status.Health),
			})
		}
		for i := range thermal.Fans {
			f := &thermal.Fans[i]
			units := "RPM"
			if f.ReadingUnits != "" {
				units = f.ReadingUnits
			}
			sensors = append(sensors, SensorReading{
				Name:   f.Name,
				Value:  f.Reading,
				Units:  units,
				Status: normalizeRedfishHealth(f.Status.Health),
			})
		}
	} else {
		c.logger.Debug("bmc: redfish thermal read failed",
			slog.String("error", thermalErr.Error()))
	}

	// Fetch power data.
	var power redfishPower
	powerErr := c.doGET(ctx, chassisPath+"/Power", &power)
	if powerErr == nil {
		for i := range power.PowerControl {
			pc := &power.PowerControl[i]
			sensors = append(sensors, SensorReading{
				Name:   pc.Name,
				Value:  pc.PowerConsumedWatts,
				Units:  "Watts",
				Status: "ok",
			})
		}
		for i := range power.PowerSupplies {
			ps := &power.PowerSupplies[i]
			sensors = append(sensors, SensorReading{
				Name:   ps.Name,
				Value:  ps.LastPowerOutputWatts,
				Units:  "Watts",
				Status: normalizeRedfishHealth(ps.Status.Health),
			})
		}
	} else {
		c.logger.Debug("bmc: redfish power read failed",
			slog.String("error", powerErr.Error()))
	}

	if thermalErr != nil && powerErr != nil {
		return nil, ErrSensorRead{Cause: thermalErr}
	}

	return sensors, nil
}

// MountISO is a thin wrapper around MountVirtualMedia that builds a
// MediaSpec from a bare ISO URL. The Protocol is inferred from the URL
// scheme and the media is mounted write-protected.
func (c *redfishClient) MountISO(ctx context.Context, isoURL string) error {
	spec := &MediaSpec{URL: isoURL, WriteProtected: true}
	if err := spec.inferProtocol(); err != nil {
		return ErrVirtualMedia{Operation: "mount", Cause: err}
	}
	if err := c.MountVirtualMedia(ctx, spec); err != nil {
		return ErrVirtualMedia{Operation: "mount", Cause: err}
	}
	return nil
}

// UnmountISO is a thin wrapper around UnmountVirtualMedia.
func (c *redfishClient) UnmountISO(ctx context.Context) error {
	if err := c.UnmountVirtualMedia(ctx); err != nil {
		return ErrVirtualMedia{Operation: "unmount", Cause: err}
	}
	return nil
}

// VirtualMediaStatus dispatches to the configured virtual media backends
// and returns the first successful status response.
func (c *redfishClient) VirtualMediaStatus(ctx context.Context) (*VirtualMediaInfo, error) {
	info, err := c.virtualMediaStatusDispatch(ctx)
	if err != nil {
		return nil, ErrVirtualMedia{Operation: "status", Cause: err}
	}
	return info, nil
}

// Console returns an unsupported operation error because Redfish does not support SOL.
func (c *redfishClient) Console(_ context.Context) (*SOLSession, error) {
	return nil, ErrUnsupportedOperation{Operation: "console"}
}

// Close releases resources held by the Redfish client.
func (c *redfishClient) Close() error {
	if c.closed.Swap(true) {
		return nil // already closed
	}
	c.transport.HTTPClient().CloseIdleConnections()
	return nil
}

// discoverVirtualMediaCD finds the CD/DVD virtual media member from the collection.
// It iterates collection members looking for one that supports CD/DVD media types.
func (c *redfishClient) discoverVirtualMediaCD(ctx context.Context, vmCollectionPath string) (string, error) {
	var collection redfishCollection
	if err := c.doGET(ctx, vmCollectionPath, &collection); err != nil {
		return "", ErrRedfishDiscovery{Resource: "VirtualMedia members", Cause: err}
	}
	if len(collection.Members) == 0 {
		return "", ErrRedfishEmptyCollection{Resource: "VirtualMedia"}
	}

	// Try to find a CD/DVD member by checking media types.
	for i := range collection.Members {
		memberPath := collection.Members[i].ODataID
		var vm redfishVirtualMedia
		if err := c.doGET(ctx, memberPath, &vm); err != nil {
			continue
		}
		for _, mt := range vm.MediaTypes {
			lower := strings.ToLower(mt)
			if lower == "cd" || lower == "dvd" || strings.Contains(lower, "cd") || strings.Contains(lower, "dvd") {
				return memberPath, nil
			}
		}
	}

	// If no CD/DVD member found, return the first member as a fallback.
	return collection.Members[0].ODataID, nil
}

// doGET performs an authenticated GET request and decodes the JSON response.
func (c *redfishClient) doGET(ctx context.Context, path string, result any) error {
	_, err := c.transport.doJSON(ctx, http.MethodGet, path, nil, result)
	return err
}

// doPOST performs an authenticated POST request with a JSON body.
func (c *redfishClient) doPOST(ctx context.Context, path string, body any, result any) error {
	_, err := c.transport.doJSON(ctx, http.MethodPost, path, body, result)
	return err
}

// doPATCH performs an authenticated PATCH request with a JSON body.
func (c *redfishClient) doPATCH(ctx context.Context, path string, body any) error {
	_, err := c.transport.doJSON(ctx, http.MethodPatch, path, body, nil)
	return err
}

// normalizeRedfishHealth converts Redfish health status strings to BMC sensor status.
func normalizeRedfishHealth(health string) string {
	healthMap := map[string]string{
		"OK":       "ok",
		"Warning":  "warning",
		"Critical": "critical",
	}
	if status, ok := healthMap[health]; ok {
		return status
	}
	if health == "" {
		return "ok"
	}
	return strings.ToLower(health)
}
