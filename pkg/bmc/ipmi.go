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
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
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

	// openSession opens the RMCP+ session on first use; nil means
	// newRMCPSession. Tests inject an in-process session here.
	openSession ipmiSessionOpener

	// openMu serialises lazy session establishment (ensureOpen,
	// ensureRedfishClient) against concurrent first callers and Close:
	// Service.clientFor hands one client to every caller of a profile.
	openMu sync.Mutex

	// opMu is the lifecycle lock: every operation holds it for reading
	// from acquire/acquireRedfish until it returns, and Close holds it
	// for writing while it tears the session and Redfish client down, so
	// Close waits for in-flight operations and an operation never sees a
	// resource disappear underneath it. Helpers reached from an operation
	// (readFRU, hardwareIdentity, ...) run under the caller's read lock
	// and must not acquire again — a pending Close blocks new readers.
	opMu sync.RWMutex

	// consoles tracks the SOL sessions Console has activated and not yet
	// deactivated. Each one holds an opMu read pin until it deactivates,
	// so Close deactivates them first rather than waiting on them.
	consolesMu sync.Mutex
	consoles   map[*SOLSession]struct{}

	// identity caches the hardware identity resolved over IPMI alone (see
	// hardwareIdentity). A nil pointer means "not yet resolved"; a non-nil
	// pointer means the BMC answered once, so repeated boot-override and
	// SOL dispatch never re-issue the Get Device ID / FRU round-trips.
	// Transport failures are never stored here.
	identity atomic.Pointer[quirks.Identity]

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
// Concurrent first callers serialise on openMu so exactly one session is
// opened and every caller sees it. closed is re-checked under the lock so
// a caller that raced with Close never stores a session Close will not
// see.
func (c *ipmiClient) ensureOpen() error {
	if c.closed.Load() {
		return ErrClientClosed{}
	}
	c.openMu.Lock()
	defer c.openMu.Unlock()
	if c.closed.Load() {
		return ErrClientClosed{}
	}
	if c.session != nil {
		return nil
	}
	session, err := c.newSession()
	if err != nil {
		return ErrConnectionFailed{Address: c.config.Endpoint(), Cause: err}
	}
	c.session = session
	return nil
}

// acquire pins the RMCP+ session for one operation: it opens the session
// on first use, then takes the lifecycle read lock and re-checks under it
// that the client is still open. The returned release must be deferred
// by the operation; c.session is stable until then.
func (c *ipmiClient) acquire() (release func(), err error) {
	if err := c.ensureOpen(); err != nil {
		return nil, err
	}
	c.opMu.RLock()
	if c.closed.Load() || c.session == nil {
		c.opMu.RUnlock()
		return nil, ErrClientClosed{}
	}
	return c.opMu.RUnlock, nil
}

// acquireRedfish is acquire for the lazily created Redfish fallback
// client: c.redfishClient is stable until release is called.
func (c *ipmiClient) acquireRedfish() (release func(), err error) {
	if err := c.ensureRedfishClient(); err != nil {
		return nil, err
	}
	c.opMu.RLock()
	if c.closed.Load() || c.redfishClient == nil {
		c.opMu.RUnlock()
		return nil, ErrClientClosed{}
	}
	return c.opMu.RUnlock, nil
}

// newSession opens a fresh RMCP+ session through openSession, or the
// production rmcpSession when none is injected.
func (c *ipmiClient) newSession() (ipmiSession, error) {
	if c.openSession != nil {
		return c.openSession(context.Background(), c.config, c.logger)
	}
	session := newRMCPSession(c.config, c.logger)
	if err := session.Open(context.Background()); err != nil {
		return nil, err
	}
	return session, nil
}

// PowerOn powers on the system via IPMI chassis control.
func (c *ipmiClient) PowerOn(_ context.Context) error {
	release, acqErr := c.acquire()
	if acqErr != nil {
		return acqErr
	}
	defer release()
	_, err := c.session.Send(netFnChassis, cmdChassisControl, []byte{chassisControlPowerUp})
	if err != nil {
		return ErrPowerOperation{Operation: "on", Cause: err}
	}
	return nil
}

// PowerOff powers off the system via IPMI chassis control.
func (c *ipmiClient) PowerOff(_ context.Context) error {
	release, acqErr := c.acquire()
	if acqErr != nil {
		return acqErr
	}
	defer release()
	_, err := c.session.Send(netFnChassis, cmdChassisControl, []byte{chassisControlPowerDown})
	if err != nil {
		return ErrPowerOperation{Operation: "off", Cause: err}
	}
	return nil
}

// PowerReset performs a hard reset via IPMI chassis control.
func (c *ipmiClient) PowerReset(_ context.Context) error {
	release, acqErr := c.acquire()
	if acqErr != nil {
		return acqErr
	}
	defer release()
	_, err := c.session.Send(netFnChassis, cmdChassisControl, []byte{chassisControlHardReset})
	if err != nil {
		return ErrPowerOperation{Operation: "reset", Cause: err}
	}
	return nil
}

// PowerCycle power cycles the system via IPMI chassis control.
func (c *ipmiClient) PowerCycle(_ context.Context) error {
	release, acqErr := c.acquire()
	if acqErr != nil {
		return acqErr
	}
	defer release()
	_, err := c.session.Send(netFnChassis, cmdChassisControl, []byte{chassisControlPowerCycle})
	if err != nil {
		return ErrPowerOperation{Operation: "cycle", Cause: err}
	}
	return nil
}

// PowerStatus returns the current power state by querying IPMI chassis status.
func (c *ipmiClient) PowerStatus(_ context.Context) (PowerState, error) {
	release, acqErr := c.acquire()
	if acqErr != nil {
		return PowerStateUnknown, acqErr
	}
	defer release()
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
	release, acqErr := c.acquire()
	if acqErr != nil {
		return acqErr
	}
	defer release()
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

	// Set boot flags (parameter 5). A failure aborts a boot target; a
	// clear carries on to the vendor and Redfish layers (the Redfish
	// PATCH is the step that disarms the override) and reports the
	// failure once those have been tried.
	var flagsErr error
	if _, err = c.session.Send(netFnChassis, cmdSetSystemBootOptions, bootFlags); err != nil {
		if device != BootDeviceNone {
			return ErrBootDevice{Device: string(device), Cause: err}
		}
		flagsErr = err
		c.logger.Warn("bmc: ipmi boot flags clear failed, still clearing vendor and Redfish overrides",
			slog.String("error", err.Error()))
	}

	// Vendor OEM boot override (IPMI path). Supermicro X10 ATEN firmware
	// silently ignores the standard 0x08 boot flags above when the disk
	// already holds a UEFI Linux NVRAM entry; the OEM 0x30/0x70/0x0c "Set
	// Boot Option Override" lives beneath the UEFI BootOrder logic and is
	// the only software path that forces PXE on an already-provisioned
	// X10. We reuse the SAME live session here — no second RMCP+ handshake
	// and, critically, no TLS/Redfish discovery (the path that fails in
	// the field). The quirk is resolved from the IPMI-derived vendor, so
	// this never needs Redfish. The OEM override is authoritative on X10
	// for a boot target, so on success we return and skip the Redfish
	// reinforcement — except for BootDeviceNone: measured on X10 ATEN
	// firmware (issue #103), the OEM disable leaves a Continuous
	// CD/virtual-media override armed in both the Redfish and IPMI
	// views, and only the Redfish PATCH None/Disabled clears it, so the
	// clear always continues to the reinforcement below.
	var oemErr error
	q := quirks.ResolveIdentity(c.hardwareIdentity(ctx))
	if q.BootOverrideStrategy == smcOEMBackendName {
		if _, routable := smcOEMBootDeviceCode(device); routable {
			oemErr = sendSmcOEMBootOverride(c.session, c.logger, device, persistent)
			switch {
			case oemErr != nil && device != BootDeviceNone:
				return ErrBootDevice{Device: string(device), Cause: oemErr}
			case oemErr != nil:
				// A clear still attempts the Redfish layer; the OEM
				// failure is reported once that has been tried.
				c.logger.Warn("bmc: smc-oem-ipmi disable failed, still clearing Redfish override",
					slog.String("error", oemErr.Error()))
			case device != BootDeviceNone:
				c.logger.Info("bmc: boot device set via smc-oem-ipmi (ipmi path)",
					slog.String("device", string(device)),
					slog.Bool("persistent", persistent))
				return nil
			default:
				c.logger.Debug("bmc: smc-oem-ipmi override cleared, clearing Redfish override too")
			}
		}
		// Non-OEM-routable device (e.g. Disk/CDROM) on a Supermicro board:
		// fall through to the Redfish reinforcement below, which handles
		// those targets on greenfield nodes.
	}

	// Redfish reinforcement. Supermicro X10 BMCs silently ignore IPMI
	// boot flags but honor the Redfish BootSourceOverrideTarget. Setting
	// the boot device via both protocols ensures the override takes
	// effect regardless of BMC firmware behavior. For a boot target the
	// reinforcement is best-effort (the IPMI override is in effect
	// either way); for the None clear it is mandatory, because the
	// Redfish PATCH is the only step that disarms a Continuous
	// CD/virtual-media override on X10 ATEN firmware.
	rfErr := c.ensureRedfishClient()
	if rfErr == nil {
		rfErr = c.redfishClient.SetBootDevice(ctx, device, persistent)
	}
	if device == BootDeviceNone {
		return clearBootOverrideResult(device, flagsErr, oemErr, rfErr)
	}
	if rfErr != nil {
		c.logger.Warn("bmc: redfish boot device fallback failed, IPMI-only boot override in effect",
			slog.String("device", string(device)),
			slog.Bool("persistent", persistent),
			slog.String("error", rfErr.Error()))
	}
	return nil
}

// clearBootOverrideResult folds the outcome of the layered None clear
// into the caller's error. The Redfish failure wins because that layer
// is the one measured to disarm the override, then the OEM disable,
// then the standard IPMI boot flags.
func clearBootOverrideResult(device BootDevice, flagsErr, oemErr, rfErr error) error {
	for _, err := range []error{rfErr, oemErr, flagsErr} {
		if err != nil {
			return ErrBootDevice{Device: string(device), Cause: err}
		}
	}
	return nil
}

// GetBootDevice returns the current boot device override via IPMI Get System Boot Options.
func (c *ipmiClient) GetBootDevice(_ context.Context) (BootDevice, error) {
	release, acqErr := c.acquire()
	if acqErr != nil {
		return BootDeviceNone, acqErr
	}
	defer release()

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

// manufacturerName returns the lowercase quirks-registry vendor string
// for this BMC — the Manufacturer field of hardwareIdentity — or "" for an
// unknown vendor or an unanswered BMC.
func (c *ipmiClient) manufacturerName(ctx context.Context) string {
	return c.hardwareIdentity(ctx).Manufacturer
}

// HardwareIdentity returns the quirks identity this BMC exposes over IPMI
// alone — no Redfish, no TLS, which is exactly the path that must keep
// working on an already-provisioned X10 in the field: the vendor from the
// Get Device ID IANA enterprise number (via ianaToVendor), the board from
// the FRU Board Product field and the system SKU from the FRU Product Part
// Number. Either FRU field is enough for the registry to name the board,
// so the IPMI path resolves the same entry Redfish discovery does.
//
// The identity is resolved once per client. The cache is filled with a
// compare-and-swap so concurrent first callers agree on one answer and the
// winning quirk is logged exactly once; a transport failure is never
// cached — the call returns what it could learn alongside the error and
// the next call retries.
//
// As an exported entry point it takes the lifecycle pin itself, because an
// out-of-process caller has no other way to hold one: without it a
// concurrent Close could nil c.session between the ensureOpen inside
// resolveHardwareIdentity and the FRU round-trips that follow. The
// pin-holding body lives in hardwareIdentityLocked so the internal callers,
// which already hold the read lock, do not recurse into it — a recursive
// RLock deadlocks against a waiting Close.
func (c *ipmiClient) HardwareIdentity(ctx context.Context) (quirks.Identity, error) {
	release, acqErr := c.acquire()
	if acqErr != nil {
		return quirks.Identity{}, acqErr
	}
	defer release()
	return c.hardwareIdentityLocked(ctx)
}

// hardwareIdentityLocked is the body of HardwareIdentity. Callers must
// already hold the lifecycle pin (acquire, or an active console).
func (c *ipmiClient) hardwareIdentityLocked(ctx context.Context) (quirks.Identity, error) {
	if v := c.identity.Load(); v != nil {
		return *v, nil
	}
	id, err := c.resolveHardwareIdentity(ctx)
	if err != nil {
		return id, ErrInventory{Cause: err}
	}
	if c.identity.CompareAndSwap(nil, &id) {
		c.logger.Info("bmc: resolved vendor quirk (ipmi path)",
			slog.String("quirk", quirks.ResolveIdentity(id).Key),
			slog.String("manufacturer", id.Manufacturer),
			slog.String("model", id.Model),
			slog.String("part_number", id.PartNumber))
	}
	return *c.identity.Load(), nil
}

// hardwareIdentity is the identity accessor for the internal callers that
// treat an unreadable identity as "no quirk" rather than an error: a
// transport failure yields whatever was learned before it and is logged
// once. Callers hold the lifecycle pin already, so it does not re-acquire.
func (c *ipmiClient) hardwareIdentity(ctx context.Context) quirks.Identity {
	id, err := c.hardwareIdentityLocked(ctx)
	if err != nil {
		c.logger.Debug("bmc: hardware identity not cached (ipmi transport failure)",
			slog.String("error", err.Error()))
	}
	return id
}

// resolveHardwareIdentity performs the uncached Get Device ID and FRU
// round-trips behind hardwareIdentity. A non-nil error marks a failure the
// caller must not cache; the identity returned alongside it carries
// whatever was learned before the failure. A BMC that answers — including
// with an unknown IANA number, a completion code that says the FRU does
// not exist, or FRU content that does not decode — is a definitive answer
// and yields a nil error (see definitiveIPMIError).
func (c *ipmiClient) resolveHardwareIdentity(_ context.Context) (quirks.Identity, error) {
	var id quirks.Identity
	if err := c.ensureOpen(); err != nil {
		return id, err
	}
	devResp, err := c.session.Send(netFnApp, cmdGetDeviceID, nil)
	if err != nil && !definitiveIPMIError(err) {
		return id, err
	}
	if iana, ok := parseDeviceIDManufacturer(devResp); ok {
		id.Manufacturer = ianaToVendor[iana]
	}
	fru, err := c.readFRU(0) // FRU device 0 is the system board
	if err != nil {
		if definitiveIPMIError(err) {
			c.logger.Debug("bmc: FRU unavailable, vendor-only identity",
				slog.String("error", err.Error()))
			return id, nil
		}
		return id, err
	}
	id.Model = fru.BoardProduct
	id.PartNumber = fru.ProductPartNumber
	return id, nil
}

// definitiveCompletionCodes lists the IPMI completion codes (IPMI 2.0
// §5.2, Table 5-2) that say the request itself can never succeed on this
// BMC — the command or the FRU device is absent — as opposed to codes
// such as 0xC0 (node busy), 0xC3 (timeout) or 0xD3 (destination
// unavailable) that describe the BMC's state right now and may clear.
var definitiveCompletionCodes = map[uint8]struct{}{
	0xC1: {}, // invalid command
	0xC9: {}, // parameter out of range (no such FRU device)
	0xCB: {}, // requested data not present
	0xCC: {}, // invalid data field in request
	0xD4: {}, // insufficient privilege level
}

// definitiveIPMIError reports whether err is the BMC's final answer —
// a completion code from definitiveCompletionCodes or FRU content that
// does not decode — rather than a failure that may succeed on retry.
// Only a definitive answer may be cached for the client's lifetime.
func definitiveIPMIError(err error) bool {
	var fru ErrFRURead
	if errors.As(err, &fru) {
		return true
	}
	var cc ErrCompletionCode
	if !errors.As(err, &cc) {
		return false
	}
	_, ok := definitiveCompletionCodes[cc.Code]
	return ok
}

// ensureRedfishClient lazily creates a Redfish client for virtual media operations.
// Uses the same BMC address and credentials but connects via HTTPS (port 443).
// The TLSProvider from the parent IPMI config is carried over so all Redfish
// connections use the same class-BMC trust resolver as the IPMI client itself.
// When no provider is set, BuildTLSConfig falls back to system roots (TLS 1.2+)
// which is the secure default.
func (c *ipmiClient) ensureRedfishClient() error {
	c.openMu.Lock()
	defer c.openMu.Unlock()
	if c.closed.Load() {
		return ErrClientClosed{}
	}
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
	release, acqErr := c.acquireRedfish()
	if acqErr != nil {
		return acqErr
	}
	defer release()
	return c.redfishClient.MountISO(ctx, isoURL)
}

// UnmountISO unmounts virtual media via Redfish.
func (c *ipmiClient) UnmountISO(ctx context.Context) error {
	if c.closed.Load() {
		return ErrClientClosed{}
	}
	release, acqErr := c.acquireRedfish()
	if acqErr != nil {
		return acqErr
	}
	defer release()
	return c.redfishClient.UnmountISO(ctx)
}

// MountVirtualMedia delegates to the embedded Redfish client's
// MountVirtualMedia, since IPMI has no native virtual media facility.
func (c *ipmiClient) MountVirtualMedia(ctx context.Context, spec *MediaSpec) error {
	if c.closed.Load() {
		return ErrClientClosed{}
	}
	release, acqErr := c.acquireRedfish()
	if acqErr != nil {
		return acqErr
	}
	defer release()
	return c.redfishClient.MountVirtualMedia(ctx, spec)
}

// UnmountVirtualMedia delegates to the embedded Redfish client's UnmountVirtualMedia.
func (c *ipmiClient) UnmountVirtualMedia(ctx context.Context) error {
	if c.closed.Load() {
		return ErrClientClosed{}
	}
	release, acqErr := c.acquireRedfish()
	if acqErr != nil {
		return acqErr
	}
	defer release()
	return c.redfishClient.UnmountVirtualMedia(ctx)
}

// VirtualMediaStatus returns virtual media status via Redfish.
// Falls back to a default "not mounted" status if Redfish is unavailable.
func (c *ipmiClient) VirtualMediaStatus(ctx context.Context) (*VirtualMediaInfo, error) {
	if c.closed.Load() {
		return nil, ErrClientClosed{}
	}
	release, acqErr := c.acquireRedfish()
	if acqErr != nil {
		return &VirtualMediaInfo{Mounted: false}, nil
	}
	defer release()
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
	release, acqErr := c.acquire()
	if acqErr != nil {
		return nil, acqErr
	}
	defer release()
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
	release, acqErr := c.acquire()
	if acqErr != nil {
		return nil, acqErr
	}
	defer release()

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
// payload instance (Table 24-2). Most BMCs use 0x01; a board whose BMC
// wires SOL to a second UART may route to 0x02 instead. Activating the
// wrong instance yields a
// successful Activate Payload response from the BMC followed by silence on
// the receive loop (the operator sees a zero-byte SOL log).
//
// To pick the right instance, Console resolves the platform Quirk from the
// identity the BMC exposes over IPMI itself (hardwareIdentity), falling
// back to the lazy Redfish client's System discovery only when IPMI names
// no registry entry. If neither path identifies the board, Console uses
// the IPMI default (0x01) — preserving prior behaviour for vendors where
// the default works.
//
// Config.SOLPayloadInstance wins over the resolved quirk so operators can
// diagnose new hardware without a code change.
//
// The returned session keeps using the client's RMCP+ session (its
// receive loop takes over the socket), so it holds the client's lifecycle
// pin until it is deactivated: Close deactivates any console still open
// before tearing the session down, and a console closed by its owner
// releases the pin itself.
func (c *ipmiClient) Console(ctx context.Context) (*SOLSession, error) {
	release, acqErr := c.acquire()
	if acqErr != nil {
		return nil, acqErr
	}
	instance := c.resolveSOLPayloadInstance(ctx)
	sol, err := c.session.ActivateSOL(ctx, instance)
	if err != nil {
		release()
		return nil, err
	}
	sol.release = func() {
		c.forgetConsole(sol)
		release()
	}
	if !c.rememberConsole(sol) {
		// Close ran between activation and registration and has
		// already taken its snapshot: deactivate here so the pin is
		// released and Close can finish.
		if err := sol.Deactivate(ctx); err != nil {
			return nil, err
		}
		return nil, ErrClientClosed{}
	}
	return sol, nil
}

// rememberConsole records an active console so Close can deactivate it.
// It reports false, recording nothing, when the client is already closed:
// Close flips closed before it snapshots the consoles, and registration
// is serialised with that snapshot on consolesMu, so a console is either
// in the snapshot or told to deactivate itself — never left holding the
// pin unseen.
func (c *ipmiClient) rememberConsole(sol *SOLSession) bool {
	c.consolesMu.Lock()
	defer c.consolesMu.Unlock()
	if c.closed.Load() {
		return false
	}
	if c.consoles == nil {
		c.consoles = make(map[*SOLSession]struct{})
	}
	c.consoles[sol] = struct{}{}
	return true
}

// forgetConsole drops a console that has deactivated.
func (c *ipmiClient) forgetConsole(sol *SOLSession) {
	c.consolesMu.Lock()
	defer c.consolesMu.Unlock()
	delete(c.consoles, sol)
}

// deactivateConsoles deactivates every console still active on this
// client, releasing the lifecycle pins they hold so Close can proceed.
func (c *ipmiClient) deactivateConsoles(ctx context.Context) error {
	c.consolesMu.Lock()
	active := make([]*SOLSession, 0, len(c.consoles))
	for sol := range c.consoles {
		active = append(active, sol)
	}
	c.consolesMu.Unlock()
	var firstErr error
	for _, sol := range active {
		if err := sol.Deactivate(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// resolveSOLPayloadInstance picks the IPMI 2.0 SOL payload instance for
// this BMC: explicit Config override wins, then the quirk resolved from
// the IPMI-native identity, then the quirk resolved from the
// Redfish-discovered identity, then the IPMI default (0x01).
//
// Returns 0x01 on any error path so a transient discovery failure never
// silently breaks SOL — at worst the operator gets prior behaviour.
func (c *ipmiClient) resolveSOLPayloadInstance(ctx context.Context) byte {
	if c.config != nil && c.config.SOLPayloadInstance != 0 {
		c.logger.Debug("bmc: SOL payload instance from explicit config",
			"instance", c.config.SOLPayloadInstance)
		return c.config.SOLPayloadInstance
	}
	if q := quirks.ResolveIdentity(c.hardwareIdentity(ctx)); q.Key != quirks.Default().Key {
		return c.solPayloadInstanceFromQuirk(q, "ipmi")
	}
	if err := c.ensureRedfishClient(); err != nil {
		c.logger.Debug("bmc: SOL payload instance defaulting (no Redfish)",
			"error", err.Error())
		return defaultSOLPayloadInstance
	}
	rc, ok := c.redfishClient.(*redfishClient)
	if !ok {
		return defaultSOLPayloadInstance
	}
	if err := rc.ensureDiscovered(ctx); err != nil {
		c.logger.Debug("bmc: SOL payload instance defaulting (Redfish discovery failed)",
			"error", err.Error())
		return defaultSOLPayloadInstance
	}
	return c.solPayloadInstanceFromQuirk(rc.resolveQuirk(), "redfish")
}

// defaultSOLPayloadInstance is the IPMI 2.0 SOL payload instance almost
// every BMC routes the console to (Table 24-2).
const defaultSOLPayloadInstance byte = 0x01

// solPayloadInstanceFromQuirk returns the quirk's SOL payload instance,
// logging which identity path (ipmi / redfish) supplied it, or the IPMI
// default when the quirk leaves the instance unset.
func (c *ipmiClient) solPayloadInstanceFromQuirk(q quirks.Quirk, path string) byte {
	if q.SOLPayloadInstance == 0 {
		return defaultSOLPayloadInstance
	}
	c.logger.Info("bmc: SOL payload instance from quirk",
		"path", path,
		"quirk", q.Key,
		"instance", q.SOLPayloadInstance)
	return q.SOLPayloadInstance
}

// ClearUEFIBootEntries delegates to the lazy Redfish fallback because
// IPMI 2.0 does not provide a standard command for clearing UEFI NVRAM
// boot entries. When the BMC speaks Redfish, the fallback tries
// Bios.ResetBios; otherwise we propagate ErrUEFIBootClearUnsupported.
func (c *ipmiClient) ClearUEFIBootEntries(ctx context.Context) error {
	release, acqErr := c.acquireRedfish()
	if acqErr != nil {
		return ErrUEFIBootClearUnsupported{Cause: acqErr}
	}
	defer release()
	return c.redfishClient.ClearUEFIBootEntries(ctx)
}

// Close releases the IPMI session and underlying transport.
func (c *ipmiClient) Close() error {
	if c.closed.Swap(true) {
		return nil // already closed
	}
	// An open console pins the lifecycle lock for as long as it is
	// active; deactivate it now rather than waiting for an owner that may
	// never close it. Then wait for in-flight operations (readers of
	// opMu) before tearing anything down; new operations already see
	// closed.
	consoleErr := c.deactivateConsoles(context.Background())
	c.opMu.Lock()
	defer c.opMu.Unlock()
	c.openMu.Lock()
	defer c.openMu.Unlock()
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
	return consoleErr
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
