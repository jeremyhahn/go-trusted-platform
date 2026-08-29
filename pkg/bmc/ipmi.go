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
	"encoding/binary"
	"fmt"
	"log/slog"
	"math"
	"sync/atomic"

	"github.com/jeremyhahn/go-trusted-platform/pkg/quirks"
)

// SDR record types per IPMI spec.
const (
	sdrRecordTypeFull    = 0x01
	sdrRecordTypeCompact = 0x02
)

// Maximum bytes per FRU read request. Most BMCs support 16-32 bytes per read.
const fruReadChunkSize = 16

// ianaSupermicro is the IANA Private Enterprise Number Supermicro reports
// in the IPMI Get Device ID manufacturer field. It is the only IPMI-only
// (no-Redfish) vendor that currently needs quirk routing on the IPMI path.
const ianaSupermicro = 10876

// vendorKeySupermicro is the lowercase quirks-registry vendor string for
// Supermicro-family BMCs. It is the value ianaToVendor resolves for
// ianaSupermicro and the gate HostMACAddress checks before issuing the
// OEM 0x30/0x21 host-MAC command. Rebadged Supermicro boards (VeloCloud
// EDGE840) report the same IANA over IPMI and therefore resolve to this
// key regardless of their SMBIOS model string.
const vendorKeySupermicro = "supermicro"

// ianaToVendor maps IPMI Get-Device-ID manufacturer IANA enterprise
// numbers to the lowercase vendor strings used as quirks-registry keys.
// It exists so the IPMI client can resolve a platform Quirk without any
// Redfish/TLS discovery (which is exactly the path that fails in the
// field on already-provisioned X10 nodes). Extend this map as more
// IPMI-only vendors are validated; an unknown IANA resolves to "" which
// quirks.Resolve treats as the generic default.
var ianaToVendor = map[uint32]string{
	ianaSupermicro: vendorKeySupermicro,
}

// bootDeviceBitsMap maps bmc BootDevice values to IPMI boot device selector bits.
var bootDeviceBitsMap = map[BootDevice]byte{
	BootDevicePXE:          bootDevicePXEBits,
	BootDeviceDisk:         bootDeviceDiskBits,
	BootDeviceCDROM:        bootDeviceCDROMBits,
	BootDeviceVirtualMedia: bootDeviceCDROMBits,
	BootDeviceNone:         bootDeviceNoneBits,
}

// ipmiBootDeviceFromBits maps IPMI boot device selector bits back to BootDevice values.
var ipmiBootDeviceFromBits = map[byte]BootDevice{
	bootDeviceNoneBits:  BootDeviceNone,
	bootDevicePXEBits:   BootDevicePXE,
	bootDeviceDiskBits:  BootDeviceDisk,
	bootDeviceCDROMBits: BootDeviceCDROM,
}

// ipmiSession is the subset of *rmcpSession the ipmiClient depends on.
// Declaring it as an interface keeps the client unit-testable — a fake
// session can be injected — while *rmcpSession remains the only
// production implementation. The session is always opened (concretely)
// before being assigned to the interface field, so Open is intentionally
// not part of this contract.
type ipmiSession interface {
	ipmiRawSender
	ActivateSOL(ctx context.Context, payloadInstance byte) (*SOLSession, error)
	Close() error
}

// ipmiClient implements the Client interface using IPMI 2.0 RMCP+ transport.
// Virtual media operations are delegated to a Redfish client since IPMI does
// not support virtual media natively.
type ipmiClient struct {
	config        *Config
	logger        *slog.Logger
	session       ipmiSession
	redfishClient Client // Lazy Redfish fallback for virtual media

	// manufacturer caches the lowercase quirks-registry vendor string
	// resolved from the IPMI Get-Device-ID IANA enterprise number. A nil
	// pointer means "not yet resolved"; a non-nil pointer (which may
	// point to "") means "resolved once" so repeated boot-override
	// dispatch never re-issues the Get Device ID round-trip.
	manufacturer atomic.Pointer[string]

	closed atomic.Bool
}

// Compile-time interface check.
var _ Client = (*ipmiClient)(nil)

// newIPMIClient creates a new ipmiClient with the given configuration.
func newIPMIClient(config *Config, logger *slog.Logger) *ipmiClient {
	return &ipmiClient{
		config: config,
		logger: logger,
	}
}

// ensureOpen lazily opens the IPMI 2.0 RMCP+ session on first use.
func (c *ipmiClient) ensureOpen() error {
	if c.closed.Load() {
		return ErrClientClosed{}
	}
	if c.session != nil {
		return nil
	}
	session := newRMCPSession(c.config, c.logger)
	if err := session.Open(context.Background()); err != nil {
		return ErrConnectionFailed{Address: c.config.Endpoint(), Cause: err}
	}
	c.session = session
	return nil
}

// PowerOn powers on the system via IPMI chassis control.
func (c *ipmiClient) PowerOn(_ context.Context) error {
	if err := c.ensureOpen(); err != nil {
		return err
	}
	_, err := c.session.Send(netFnChassis, cmdChassisControl, []byte{chassisControlPowerUp})
	if err != nil {
		return ErrPowerOperation{Operation: "on", Cause: err}
	}
	return nil
}

// PowerOff powers off the system via IPMI chassis control.
func (c *ipmiClient) PowerOff(_ context.Context) error {
	if err := c.ensureOpen(); err != nil {
		return err
	}
	_, err := c.session.Send(netFnChassis, cmdChassisControl, []byte{chassisControlPowerDown})
	if err != nil {
		return ErrPowerOperation{Operation: "off", Cause: err}
	}
	return nil
}

// PowerReset performs a hard reset via IPMI chassis control.
func (c *ipmiClient) PowerReset(_ context.Context) error {
	if err := c.ensureOpen(); err != nil {
		return err
	}
	_, err := c.session.Send(netFnChassis, cmdChassisControl, []byte{chassisControlHardReset})
	if err != nil {
		return ErrPowerOperation{Operation: "reset", Cause: err}
	}
	return nil
}

// PowerCycle power cycles the system via IPMI chassis control.
func (c *ipmiClient) PowerCycle(_ context.Context) error {
	if err := c.ensureOpen(); err != nil {
		return err
	}
	_, err := c.session.Send(netFnChassis, cmdChassisControl, []byte{chassisControlPowerCycle})
	if err != nil {
		return ErrPowerOperation{Operation: "cycle", Cause: err}
	}
	return nil
}

// PowerStatus returns the current power state by querying IPMI chassis status.
func (c *ipmiClient) PowerStatus(_ context.Context) (PowerState, error) {
	if err := c.ensureOpen(); err != nil {
		return PowerStateUnknown, err
	}
	resp, err := c.session.Send(netFnChassis, cmdChassisStatus, nil)
	if err != nil {
		return PowerStateUnknown, ErrPowerOperation{Operation: "status", Cause: err}
	}
	if len(resp) < 1 {
		return PowerStateUnknown, ErrPowerOperation{
			Operation: "status",
			Cause:     ErrPacketTooShort{Expected: 1, Actual: 0},
		}
	}
	// Bit 0 of the first response byte indicates system power on.
	if resp[0]&0x01 != 0 {
		return PowerStateOn, nil
	}
	return PowerStateOff, nil
}

// SetBootDevice sets the next boot device via IPMI Set System Boot Options.
//
// Dispatch order:
//  1. Standard IPMI 0x08 boot flags (parameter 5). Harmless and correct
//     for vendors whose BIOS honours it.
//  2. Vendor OEM override over the SAME live session when the IPMI-derived
//     quirk asks for "smc-oem-ipmi" and the device is OEM-routable. This is
//     authoritative on Supermicro X10 ATEN firmware (which silently ignores
//     the 0x08 flags above when the disk has a UEFI Linux NVRAM entry), so
//     on success we return immediately and skip the Redfish reinforcement.
//  3. Best-effort Redfish reinforcement for every other case (non-Supermicro,
//     or a non-OEM-routable device on Supermicro).
func (c *ipmiClient) SetBootDevice(ctx context.Context, device BootDevice, persistent bool) error {
	if !device.IsValid() {
		return ErrInvalidBootDevice{Device: string(device)}
	}
	if err := c.ensureOpen(); err != nil {
		return err
	}
	devBits, ok := bootDeviceBitsMap[device]
	if !ok {
		return ErrInvalidBootDevice{Device: string(device)}
	}

	// Set System Boot Options, parameter selector 5 (Boot Flags). Per
	// IPMI 2.0 spec Table 28-14 the Boot Flags parameter is exactly 5
	// data bytes; together with the parameter selector that's 6 bytes
	// total. Older versions of this code allocated only 5 bytes which
	// causes Supermicro BMCs (and others) to reject the command with
	// completion code 0xc6 ("Cannot return number of requested data
	// bytes" / request length mismatch).
	//
	// Byte layout (after the param selector at index 0):
	//   data 1: bit 7=valid, bit 6=persistent, bit 5=BIOS boot type (1=EFI)
	//   data 2: bit 7=CMOS clear, bit 6=lock kbd, bits 5:2=boot device
	//   data 3: BIOS verbosity / console redirect / etc — leave 0
	//   data 4: device instance + console redirect — leave 0
	//   data 5: device instance selector — leave 0
	bootFlags := make([]byte, 6)
	bootFlags[0] = 0x05 // Parameter selector: boot flags

	// data 1
	bootFlags[1] = 0x80 // Valid
	if persistent {
		bootFlags[1] |= 0x40
	}
	// EFI boot type. Most modern UEFI systems require this bit set or
	// the BIOS silently falls back to legacy and ignores the override.
	bootFlags[1] |= 0x20

	// data 2: boot device selector
	bootFlags[2] = devBits

	// Set boot info acknowledge (parameter 4) first to clear any stale state.
	ackData := []byte{0x04, 0x01, 0x00, 0x00, 0x00}
	_, err := c.session.Send(netFnChassis, cmdSetSystemBootOptions, ackData)
	if err != nil {
		// Non-fatal: some BMCs don't require this.
		c.logger.Debug("bmc: set boot info acknowledge failed",
			slog.String("error", err.Error()))
	}

	// Set boot flags (parameter 5).
	_, err = c.session.Send(netFnChassis, cmdSetSystemBootOptions, bootFlags)
	if err != nil {
		return ErrBootDevice{Device: string(device), Cause: err}
	}

	// Vendor OEM boot override (IPMI path). Supermicro X10 ATEN firmware
	// silently ignores the standard 0x08 boot flags above when the disk
	// already holds a UEFI Linux NVRAM entry; the OEM 0x30/0x70/0x0c "Set
	// Boot Option Override" lives beneath the UEFI BootOrder logic and is
	// the only software path that forces PXE on an already-provisioned
	// X10. We reuse the SAME live session here — no second RMCP+ handshake
	// and, critically, no TLS/Redfish discovery (the path that fails in
	// the field). The quirk is resolved from the IPMI-derived vendor, so
	// this never needs Redfish. The OEM override is authoritative on X10,
	// so on success we return and skip the Redfish reinforcement entirely.
	q := quirks.Resolve(c.manufacturerName(ctx), "")
	if q.BootOverrideStrategy == smcOEMBackendName {
		if _, routable := smcOEMBootDeviceCode(device); routable {
			if oemErr := sendSmcOEMBootOverride(c.session, c.logger, device, persistent); oemErr != nil {
				return ErrBootDevice{Device: string(device), Cause: oemErr}
			}
			c.logger.Info("bmc: boot device set via smc-oem-ipmi (ipmi path)",
				slog.String("device", string(device)),
				slog.Bool("persistent", persistent))
			return nil
		}
		// Non-OEM-routable device (e.g. Disk/CDROM) on a Supermicro board:
		// fall through to the Redfish reinforcement below, which handles
		// those targets on greenfield nodes.
	}

	// Best-effort Redfish reinforcement. Supermicro X10 BMCs silently
	// ignore IPMI boot flags but honor the Redfish BootSourceOverrideTarget.
	// Setting the boot device via both protocols ensures the override takes
	// effect regardless of BMC firmware behavior.
	if rfErr := c.ensureRedfishClient(); rfErr != nil {
		c.logger.Warn("bmc: redfish fallback unavailable for boot device reinforcement",
			slog.String("device", string(device)),
			slog.String("error", rfErr.Error()))
		return nil
	}
	if rfErr := c.redfishClient.SetBootDevice(ctx, device, persistent); rfErr != nil {
		c.logger.Warn("bmc: redfish boot device fallback failed, IPMI-only boot override in effect",
			slog.String("device", string(device)),
			slog.Bool("persistent", persistent),
			slog.String("error", rfErr.Error()))
	}

	return nil
}

// GetBootDevice returns the current boot device override via IPMI Get System Boot Options.
func (c *ipmiClient) GetBootDevice(_ context.Context) (BootDevice, error) {
	if err := c.ensureOpen(); err != nil {
		return BootDeviceNone, err
	}

	// Get System Boot Options, parameter selector 5 (Boot Flags).
	// Request format: parameter selector (1) + set selector (1) + block selector (1)
	reqData := []byte{0x05, 0x00, 0x00}
	resp, err := c.session.Send(netFnChassis, cmdGetSystemBootOptions, reqData)
	if err != nil {
		return BootDeviceNone, ErrBootDevice{Cause: err}
	}

	// Response: parameter version (1) + parameter selector (1) + boot flags (5)
	// The boot device selector is in byte 3 (boot flags byte 2), bits 5:2.
	if len(resp) < 5 {
		return BootDeviceNone, nil
	}

	// Check valid bit.
	if resp[2]&0x80 == 0 {
		return BootDeviceNone, nil
	}

	selector := resp[3] & 0x3C // Mask bits 5:2
	if bd, ok := ipmiBootDeviceFromBits[selector]; ok {
		return bd, nil
	}
	return BootDeviceNone, nil
}

// parseDeviceIDManufacturer extracts the 3-byte manufacturer IANA
// enterprise number from a Get Device ID response (IPMI 2.0 §20.1).
// The id occupies bytes 6..8, little-endian. Returns ok=false when the
// response is too short to contain it.
func parseDeviceIDManufacturer(devResp []byte) (uint32, bool) {
	if len(devResp) < 9 {
		return 0, false
	}
	return uint32(devResp[6]) | uint32(devResp[7])<<8 | uint32(devResp[8])<<16, true
}

// manufacturerName resolves the BMC's hardware vendor from the IPMI
// Get-Device-ID manufacturer IANA enterprise number, mapped to the
// lowercase quirks-registry vendor string via ianaToVendor. The result
// — including the "" answer for an unknown vendor — is cached on first
// resolution so repeated boot-override dispatch never re-issues the
// round-trip. Returns "" when the session can't be opened, the response
// is malformed, or the IANA id is not in the known-vendor map.
func (c *ipmiClient) manufacturerName(ctx context.Context) string {
	if v := c.manufacturer.Load(); v != nil {
		return *v
	}
	name := c.resolveManufacturerName(ctx)
	c.manufacturer.Store(&name)
	// IPMI Get Device ID names only the vendor, so the IPMI path can
	// reach no further than the manufacturer-wide entry; log which one
	// won, once, alongside the Redfish client's own resolution.
	c.logger.Info("bmc: resolved vendor quirk (ipmi path)",
		slog.String("quirk", quirks.Resolve(name, "").Key),
		slog.String("manufacturer", name))
	return name
}

// resolveManufacturerName performs the uncached Get Device ID round-trip
// and IANA→vendor lookup. See manufacturerName for caching semantics.
func (c *ipmiClient) resolveManufacturerName(_ context.Context) string {
	if err := c.ensureOpen(); err != nil {
		c.logger.Debug("bmc: manufacturer detection skipped (session unavailable)",
			slog.String("error", err.Error()))
		return ""
	}
	devResp, err := c.session.Send(netFnApp, cmdGetDeviceID, nil)
	if err != nil {
		c.logger.Debug("bmc: get device id failed during manufacturer detection",
			slog.String("error", err.Error()))
		return ""
	}
	iana, ok := parseDeviceIDManufacturer(devResp)
	if !ok {
		return ""
	}
	return ianaToVendor[iana]
}

// ensureRedfishClient lazily creates a Redfish client for virtual media operations.
// Uses the same BMC address and credentials but connects via HTTPS (port 443).
// The TLSProvider from the parent IPMI config is carried over so all Redfish
// connections use the same class-BMC trust resolver as the IPMI client itself.
// When no provider is set, BuildTLSConfig falls back to system roots (TLS 1.2+)
// which is the secure default.
func (c *ipmiClient) ensureRedfishClient() error {
	if c.redfishClient != nil {
		return nil
	}
	redfishConfig := &Config{
		Address:  c.config.Address,
		Port:     443,
		Username: c.config.Username,
		Password: c.config.Password,
		Protocol: ProtocolRedfish,
		TLS:      c.config.TLS,
	}
	rc, err := newRedfishClient(redfishConfig, c.logger)
	if err != nil {
		return err
	}
	c.redfishClient = rc
	c.logger.Info("bmc: created Redfish fallback client for virtual media",
		"address", c.config.Address)
	return nil
}

// MountISO mounts an ISO image via Redfish virtual media.
// IPMI does not support virtual media natively, so this delegates to a
// Redfish client using the same BMC address and credentials.
func (c *ipmiClient) MountISO(ctx context.Context, isoURL string) error {
	if c.closed.Load() {
		return ErrClientClosed{}
	}
	if isoURL == "" {
		return ErrVirtualMedia{Operation: "mount"}
	}
	if err := c.ensureRedfishClient(); err != nil {
		return err
	}
	return c.redfishClient.MountISO(ctx, isoURL)
}

// UnmountISO unmounts virtual media via Redfish.
func (c *ipmiClient) UnmountISO(ctx context.Context) error {
	if c.closed.Load() {
		return ErrClientClosed{}
	}
	if err := c.ensureRedfishClient(); err != nil {
		return err
	}
	return c.redfishClient.UnmountISO(ctx)
}

// MountVirtualMedia delegates to the embedded Redfish client's
// MountVirtualMedia, since IPMI has no native virtual media facility.
func (c *ipmiClient) MountVirtualMedia(ctx context.Context, spec *MediaSpec) error {
	if c.closed.Load() {
		return ErrClientClosed{}
	}
	if err := c.ensureRedfishClient(); err != nil {
		return err
	}
	return c.redfishClient.MountVirtualMedia(ctx, spec)
}

// UnmountVirtualMedia delegates to the embedded Redfish client's UnmountVirtualMedia.
func (c *ipmiClient) UnmountVirtualMedia(ctx context.Context) error {
	if c.closed.Load() {
		return ErrClientClosed{}
	}
	if err := c.ensureRedfishClient(); err != nil {
		return err
	}
	return c.redfishClient.UnmountVirtualMedia(ctx)
}

// VirtualMediaStatus returns virtual media status via Redfish.
// Falls back to a default "not mounted" status if Redfish is unavailable.
func (c *ipmiClient) VirtualMediaStatus(ctx context.Context) (*VirtualMediaInfo, error) {
	if c.closed.Load() {
		return nil, ErrClientClosed{}
	}
	if err := c.ensureRedfishClient(); err != nil {
		return &VirtualMediaInfo{Mounted: false}, nil
	}
	info, err := c.redfishClient.VirtualMediaStatus(ctx)
	if err != nil {
		c.logger.Debug("bmc: redfish virtual media status failed, returning default", "error", err)
		return &VirtualMediaInfo{Mounted: false}, nil
	}
	return info, nil
}

// GetSensors reads sensor data from the BMC via the SDR repository and
// individual sensor reading commands.
func (c *ipmiClient) GetSensors(_ context.Context) ([]SensorReading, error) {
	if err := c.ensureOpen(); err != nil {
		return nil, err
	}
	records, err := c.readSDRRepository()
	if err != nil {
		return nil, ErrSensorRead{Cause: err}
	}
	sensors := make([]SensorReading, 0, len(records))
	for i := range records {
		rec := &records[i]
		reading, err := c.readSensor(rec.SensorNumber)
		if err != nil {
			c.logger.Debug("bmc: sensor read failed",
				slog.String("sensor", rec.Name),
				slog.Uint64("number", uint64(rec.SensorNumber)),
				slog.String("error", err.Error()))
			continue
		}
		value := convertSensorReading(reading.RawReading, rec)
		status := sensorStatus(reading)
		sensors = append(sensors, SensorReading{
			Name:   rec.Name,
			Value:  value,
			Units:  sensorUnitString(rec.BaseUnit),
			Status: status,
		})
	}
	return sensors, nil
}

// GetSystemInfo returns system identification from IPMI Device ID and FRU data.
func (c *ipmiClient) GetSystemInfo(_ context.Context) (*SystemInfo, error) {
	if err := c.ensureOpen(); err != nil {
		return nil, err
	}

	info := &SystemInfo{}

	// Get Device ID for manufacturer and firmware version.
	devResp, err := c.session.Send(netFnApp, cmdGetDeviceID, nil)
	if err != nil {
		return nil, ErrInventory{Cause: err}
	}
	if len(devResp) >= 12 {
		fwMajor := devResp[2] & 0x3F
		fwMinor := devResp[3]
		info.FirmwareVersion = fmt.Sprintf("%d.%02d", fwMajor, fwMinor)
		if iana, ok := parseDeviceIDManufacturer(devResp); ok {
			info.Manufacturer = fmt.Sprintf("%d", iana)
		}
	}

	// Attempt FRU read for product name and serial number.
	fru, fruErr := c.readFRU(0) // FRU device 0 is the system board
	if fruErr == nil {
		if fru.ProductName != "" {
			info.Product = fru.ProductName
		}
		if fru.ProductSerial != "" {
			info.SerialNumber = fru.ProductSerial
		}
		if fru.ProductManufacturer != "" {
			info.Manufacturer = fru.ProductManufacturer
		}
		if fru.BoardProduct != "" && info.Product == "" {
			info.Product = fru.BoardProduct
		}
		if fru.BoardSerial != "" && info.SerialNumber == "" {
			info.SerialNumber = fru.BoardSerial
		}
	} else {
		c.logger.Debug("bmc: FRU read failed, using device ID only",
			slog.String("error", fruErr.Error()))
	}

	// Get power state.
	resp, err := c.session.Send(netFnChassis, cmdChassisStatus, nil)
	if err == nil && len(resp) >= 1 {
		if resp[0]&0x01 != 0 {
			info.PowerState = PowerStateOn
		} else {
			info.PowerState = PowerStateOff
		}
	} else {
		info.PowerState = PowerStateUnknown
	}

	return info, nil
}

// Console opens an interactive SOL console session over the IPMI RMCP+ session.
//
// IPMI 2.0 lets each board route serial-console bytes to a different SOL
// payload instance (Table 24-2). Most BMCs use 0x01; a few — notably
// Supermicro X10SDV-TP8F — route to 0x02 because their SOL UART is wired
// to COM2 instead of COM1. Activating the wrong instance yields a
// successful Activate Payload response from the BMC followed by silence on
// the receive loop (the operator sees a zero-byte SOL log).
//
// To pick the right instance, Console resolves the platform Quirk via the
// lazy Redfish client (which fetches Manufacturer/Model from the System
// resource). If the BMC does not expose Redfish or System discovery fails,
// Console falls back to the IPMI default (0x01) — preserving prior
// behaviour for vendors where the default works.
//
// SOLPayloadInstanceOverride on the Config wins over the resolved quirk so
// operators can diagnose new hardware without a code change.
func (c *ipmiClient) Console(ctx context.Context) (*SOLSession, error) {
	if err := c.ensureOpen(); err != nil {
		return nil, err
	}
	instance := c.resolveSOLPayloadInstance(ctx)
	sol, err := c.session.ActivateSOL(ctx, instance)
	if err != nil {
		return nil, err
	}
	return sol, nil
}

// resolveSOLPayloadInstance picks the IPMI 2.0 SOL payload instance for
// this BMC: explicit Config override wins, then quirks.Resolve from the
// Redfish-discovered Manufacturer/Model, then the IPMI default (0x01).
//
// Returns 0x01 on any error path so a transient discovery failure never
// silently breaks SOL — at worst the operator gets prior behaviour.
func (c *ipmiClient) resolveSOLPayloadInstance(ctx context.Context) byte {
	if c.config != nil && c.config.SOLPayloadInstance != 0 {
		c.logger.Debug("bmc: SOL payload instance from explicit config",
			"instance", c.config.SOLPayloadInstance)
		return c.config.SOLPayloadInstance
	}
	if err := c.ensureRedfishClient(); err != nil {
		c.logger.Debug("bmc: SOL payload instance defaulting (no Redfish)",
			"error", err.Error())
		return 0x01
	}
	rc, ok := c.redfishClient.(*redfishClient)
	if !ok {
		return 0x01
	}
	if err := rc.ensureDiscovered(ctx); err != nil {
		c.logger.Debug("bmc: SOL payload instance defaulting (Redfish discovery failed)",
			"error", err.Error())
		return 0x01
	}
	q := rc.resolveQuirk()
	if q.SOLPayloadInstance != 0 {
		c.logger.Info("bmc: SOL payload instance from quirk",
			"manufacturer", q.Manufacturer,
			"model", q.Model,
			"instance", q.SOLPayloadInstance)
		return q.SOLPayloadInstance
	}
	return 0x01
}

// ClearUEFIBootEntries delegates to the lazy Redfish fallback because
// IPMI 2.0 does not provide a standard command for clearing UEFI NVRAM
// boot entries. When the BMC speaks Redfish, the fallback tries
// Bios.ResetBios; otherwise we propagate ErrUEFIBootClearUnsupported.
func (c *ipmiClient) ClearUEFIBootEntries(ctx context.Context) error {
	if err := c.ensureRedfishClient(); err != nil {
		return ErrUEFIBootClearUnsupported{Cause: err}
	}
	return c.redfishClient.ClearUEFIBootEntries(ctx)
}

// Close releases the IPMI session and underlying transport.
func (c *ipmiClient) Close() error {
	if c.closed.Swap(true) {
		return nil // already closed
	}
	if c.redfishClient != nil {
		c.redfishClient.Close()
		c.redfishClient = nil
	}
	if c.session != nil {
		err := c.session.Close()
		c.session = nil
		if err != nil {
			return ErrConnectionFailed{Address: c.config.Endpoint(), Cause: err}
		}
	}
	return nil
}

// readSDRRepository reads all Full Sensor Records (type 0x01) from the SDR repository.
func (c *ipmiClient) readSDRRepository() ([]sdrFullSensorRecord, error) {
	// Get SDR Repository Info to learn record count.
	infoResp, err := c.session.Send(netFnStorage, cmdGetSDRRepositoryInfo, nil)
	if err != nil {
		return nil, ErrGetSDRRepoInfo{Cause: err}
	}
	if len(infoResp) < 6 {
		return nil, ErrSDRResponseTooShort{Operation: "SDR repository info", Length: len(infoResp), Expected: 6}
	}
	recordCount := binary.LittleEndian.Uint16(infoResp[1:3])
	if recordCount == 0 {
		return nil, nil
	}

	// Reserve SDR Repository for partial reads.
	reserveResp, err := c.session.Send(netFnStorage, cmdReserveSDRRepository, nil)
	if err != nil {
		return nil, ErrReserveSDR{Cause: err}
	}
	if len(reserveResp) < 2 {
		return nil, ErrSDRResponseTooShort{Operation: "reserve SDR", Length: len(reserveResp), Expected: 2}
	}
	reservationID := binary.LittleEndian.Uint16(reserveResp[0:2])

	records := make([]sdrFullSensorRecord, 0, recordCount)
	nextRecordID := uint16(0x0000)

	for nextRecordID != 0xFFFF {
		// Read entire SDR record. Requesting 0xFF bytes gets the full record.
		getReq := make([]byte, 6)
		binary.LittleEndian.PutUint16(getReq[0:2], reservationID)
		binary.LittleEndian.PutUint16(getReq[2:4], nextRecordID)
		getReq[4] = 0    // Offset
		getReq[5] = 0xFF // Read all bytes

		getResp, err := c.session.Send(netFnStorage, cmdGetSDR, getReq)
		if err != nil {
			// Some BMCs reject 0xFF reads. Stop iteration on error.
			c.logger.Debug("bmc: get SDR failed, stopping iteration",
				slog.Uint64("record_id", uint64(nextRecordID)),
				slog.String("error", err.Error()))
			break
		}

		if len(getResp) < 2 {
			break
		}
		nextRecordID = binary.LittleEndian.Uint16(getResp[0:2])

		sdrData := getResp[2:]
		if len(sdrData) < 5 {
			continue
		}
		recordType := sdrData[3]
		if recordType == sdrRecordTypeFull {
			rec, err := parseFullSensorRecord(sdrData)
			if err != nil {
				c.logger.Debug("bmc: parse SDR record failed",
					slog.String("error", err.Error()))
				continue
			}
			records = append(records, rec)
		}
	}

	return records, nil
}

// readSensor reads the current value of a single sensor by its sensor number.
func (c *ipmiClient) readSensor(sensorNumber uint8) (*sensorReadingResponse, error) {
	resp, err := c.session.Send(netFnSensorEvent, cmdGetSensorReading, []byte{sensorNumber})
	if err != nil {
		return nil, err
	}
	reading := &sensorReadingResponse{}
	if len(resp) >= 1 {
		reading.RawReading = resp[0]
	}
	if len(resp) >= 2 {
		reading.EventStatus = resp[1]
	}
	if len(resp) >= 3 {
		reading.ThresholdLow = resp[2]
	}
	if len(resp) >= 4 {
		reading.ThresholdHigh = resp[3]
	}
	return reading, nil
}

// readFRU reads and parses FRU data from the specified FRU device.
func (c *ipmiClient) readFRU(deviceID uint8) (*fruData, error) {
	// Get FRU Inventory Area Info to determine total size.
	infoResp, err := c.session.Send(netFnStorage, cmdGetFRUInventoryArea, []byte{deviceID})
	if err != nil {
		return nil, ErrGetFRUInfo{Cause: err}
	}
	if len(infoResp) < 3 {
		return nil, ErrFRURead{Reason: "FRU inventory area info response too short"}
	}
	areaSize := binary.LittleEndian.Uint16(infoResp[0:2])
	if areaSize == 0 {
		return nil, ErrFRURead{Reason: "FRU area size is zero"}
	}

	// Read the entire FRU data in chunks.
	fruBytes, err := c.readFRUBytes(deviceID, areaSize)
	if err != nil {
		return nil, err
	}

	return parseFRU(fruBytes)
}

// readFRUBytes reads the complete FRU data area from the BMC in chunks.
func (c *ipmiClient) readFRUBytes(deviceID uint8, size uint16) ([]byte, error) {
	data := make([]byte, 0, size)
	offset := uint16(0)
	for offset < size {
		remaining := size - offset
		chunkSize := uint8(fruReadChunkSize)
		if uint16(chunkSize) > remaining {
			chunkSize = uint8(remaining)
		}

		readReq := make([]byte, 4)
		readReq[0] = deviceID
		binary.LittleEndian.PutUint16(readReq[1:3], offset)
		readReq[3] = chunkSize

		resp, err := c.session.Send(netFnStorage, cmdReadFRUData, readReq)
		if err != nil {
			return nil, ErrReadFRU{Offset: int(offset), Cause: err}
		}
		if len(resp) < 1 {
			break
		}
		count := resp[0]
		if count == 0 {
			break
		}
		if len(resp) < 1+int(count) {
			break
		}
		data = append(data, resp[1:1+count]...)
		offset += uint16(count)
	}
	return data, nil
}

// convertSensorReading converts a raw sensor reading to a human-readable
// floating-point value using the SDR linearization factors.
// Formula: reading = ((M * raw) + (B * 10^Bexp)) * 10^Rexp
func convertSensorReading(raw uint8, rec *sdrFullSensorRecord) float64 {
	m := float64(rec.M)
	b := float64(rec.B)
	bExp := float64(rec.BExp)
	rExp := float64(rec.RExp)
	return (m*float64(raw) + b*math.Pow(10, bExp)) * math.Pow(10, rExp)
}

// sensorStatus maps sensor reading flags to a status string.
func sensorStatus(reading *sensorReadingResponse) string {
	if !reading.IsValid() {
		return "unknown"
	}
	// Check threshold-based status from the optional assertion bytes.
	if reading.HasThresholds() {
		events := reading.ThresholdEvents()
		// Upper critical or non-recoverable
		if events&0x30 != 0 {
			return "critical"
		}
		// Lower critical or non-recoverable
		if events&0x06 != 0 {
			return "critical"
		}
		// Upper or lower non-critical (warning)
		if events&0x09 != 0 {
			return "warning"
		}
	}
	return "ok"
}

// IPMIClientFactory creates ipmiClient instances using IPMI 2.0 RMCP+ transport.
type IPMIClientFactory struct {
	logger *slog.Logger
}

// Compile-time interface check.
var _ ClientFactory = (*IPMIClientFactory)(nil)

// NewIPMIClientFactory creates a new IPMIClientFactory.
func NewIPMIClientFactory(logger *slog.Logger) *IPMIClientFactory {
	return &IPMIClientFactory{logger: logger}
}

// NewClient creates a new BMC client from the given configuration.
func (f *IPMIClientFactory) NewClient(config *Config) (Client, error) {
	if config == nil {
		return nil, ErrNilConfig{}
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return newIPMIClient(config, f.logger), nil
}
