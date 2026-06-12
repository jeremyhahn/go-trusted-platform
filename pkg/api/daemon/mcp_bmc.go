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

package daemon

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
)

// =============================================================================
// MCP BMC bridge
// =============================================================================
//
// MCPServiceProvider implements mcp.BMCProvider by delegating to the same
// BMCServicer that powers the gRPC BMCService. This keeps the MCP and
// gRPC surfaces in lockstep: AI/LLM clients calling platform_bmc_power_on
// hit the exact same code path as a gRPC PowerOn RPC.

// ErrBMCNotConfigured indicates that no BMC servicer is wired into the
// MCPServiceProvider. Callers should treat this the same way the gRPC
// BMC service treats a nil servicer (FailedPrecondition).
type ErrBMCNotConfigured struct{}

// Error returns a human-readable description of the error.
func (ErrBMCNotConfigured) Error() string {
	return "bmc service not configured"
}

// ErrBMCInvalidBootDevice indicates that the boot device string passed
// from MCP did not match a known bmc.BootDevice constant.
type ErrBMCInvalidBootDevice struct {
	Device string
}

// Error returns a human-readable description of the error.
func (e ErrBMCInvalidBootDevice) Error() string {
	return "bmc: invalid boot device: " + e.Device
}

// bmcBootDeviceFromString converts the JSON-friendly string passed by
// MCP clients into the domain bmc.BootDevice type. Map-based lookup
// keeps dispatch O(1).
var bmcBootDeviceFromString = map[string]bmc.BootDevice{
	"pxe":           bmc.BootDevicePXE,
	"disk":          bmc.BootDeviceDisk,
	"cdrom":         bmc.BootDeviceCDROM,
	"virtual_media": bmc.BootDeviceVirtualMedia,
	"none":          bmc.BootDeviceNone,
}

// SetBMCService injects the BMC service after construction. The daemon
// wires the same BMCServicer that powers the gRPC BMCServiceServer so
// the MCP and gRPC surfaces stay in lockstep.
func (p *MCPServiceProvider) SetBMCService(svc BMCServicer) {
	p.bmcService = svc
}

// SetBMCEnroller injects the BMCEnroller and DeviceProfileService after
// construction. The daemon calls this once the App and DeviceProfileService
// are available so the MCP enrollment tool can drive the ceremony.
func (p *MCPServiceProvider) SetBMCEnroller(enroller BMCEnroller, profileSvc device.DeviceProfileService) {
	p.bmcEnroller = enroller
	p.deviceProfileService = profileSvc
}

// SetBMCRestorer injects the BMCRestorer and DeviceProfileService after
// construction. The daemon calls this once the App and DeviceProfileService
// are available so the MCP restore tool can drive the ceremony.
func (p *MCPServiceProvider) SetBMCRestorer(restorer BMCRestorer, profileSvc device.DeviceProfileService) {
	p.bmcRestorer = restorer
	if p.deviceProfileService == nil {
		p.deviceProfileService = profileSvc
	}
}

// BMCEnrollBMC performs the BMC enrollment ceremony. It satisfies the
// mcp.BMCProvider extension for the platform_bmc_enroll MCP tool.
func (p *MCPServiceProvider) BMCEnrollBMC(
	ctx context.Context,
	profileID uint64,
	replaceCertificate, rotatePassword, dnsRegister, danePublish *bool,
) (interface{}, error) {
	if p.bmcEnroller == nil {
		return nil, ErrBMCEnrollerNotConfigured{}
	}
	bmcCfg, err := loadBMCConfig(ctx, p.deviceProfileService, profileID, p.bmcEnroller)
	if err != nil {
		return nil, err
	}
	opts := &app.BMCEnrollOptions{
		ReplaceCertificate: replaceCertificate,
		RotatePassword:     rotatePassword,
		DNSRegister:        dnsRegister,
		DANEPublish:        danePublish,
	}
	result, err := p.bmcEnroller.EnrollBMC(ctx, profileID, bmcCfg, opts)
	if err != nil {
		return nil, err
	}
	return bmcEnrollResultToMap(result), nil
}

// =============================================================================
// Power management
// =============================================================================

// BMCPowerOn powers on the BMC-managed system identified by profileID.
func (p *MCPServiceProvider) BMCPowerOn(ctx context.Context, profileID uint64) (interface{}, error) {
	if p.bmcService == nil {
		return nil, ErrBMCNotConfigured{}
	}
	previous, err := p.bmcService.PowerStatus(ctx, profileID)
	if err != nil {
		return nil, err
	}
	if err := p.bmcService.PowerOn(ctx, profileID); err != nil {
		return nil, err
	}
	current := bmc.PowerStateUnknown
	if cur, statusErr := p.bmcService.PowerStatus(ctx, profileID); statusErr == nil {
		current = cur
	}
	return bmcPowerResultJSON(previous, current), nil
}

// BMCPowerOff powers off the BMC-managed system identified by profileID.
func (p *MCPServiceProvider) BMCPowerOff(ctx context.Context, profileID uint64) (interface{}, error) {
	if p.bmcService == nil {
		return nil, ErrBMCNotConfigured{}
	}
	previous, err := p.bmcService.PowerStatus(ctx, profileID)
	if err != nil {
		return nil, err
	}
	if err := p.bmcService.PowerOff(ctx, profileID); err != nil {
		return nil, err
	}
	current := bmc.PowerStateUnknown
	if cur, statusErr := p.bmcService.PowerStatus(ctx, profileID); statusErr == nil {
		current = cur
	}
	return bmcPowerResultJSON(previous, current), nil
}

// BMCPowerReset hard-resets the BMC-managed system identified by profileID.
func (p *MCPServiceProvider) BMCPowerReset(ctx context.Context, profileID uint64) (interface{}, error) {
	if p.bmcService == nil {
		return nil, ErrBMCNotConfigured{}
	}
	previous, err := p.bmcService.PowerStatus(ctx, profileID)
	if err != nil {
		return nil, err
	}
	if err := p.bmcService.PowerReset(ctx, profileID); err != nil {
		return nil, err
	}
	current := bmc.PowerStateUnknown
	if cur, statusErr := p.bmcService.PowerStatus(ctx, profileID); statusErr == nil {
		current = cur
	}
	return bmcPowerResultJSON(previous, current), nil
}

// BMCPowerCycle power-cycles the BMC-managed system identified by profileID.
func (p *MCPServiceProvider) BMCPowerCycle(ctx context.Context, profileID uint64) (interface{}, error) {
	if p.bmcService == nil {
		return nil, ErrBMCNotConfigured{}
	}
	previous, err := p.bmcService.PowerStatus(ctx, profileID)
	if err != nil {
		return nil, err
	}
	if err := p.bmcService.PowerCycle(ctx, profileID); err != nil {
		return nil, err
	}
	current := bmc.PowerStateUnknown
	if cur, statusErr := p.bmcService.PowerStatus(ctx, profileID); statusErr == nil {
		current = cur
	}
	return bmcPowerResultJSON(previous, current), nil
}

// BMCPowerStatus returns the current power state for the system.
func (p *MCPServiceProvider) BMCPowerStatus(ctx context.Context, profileID uint64) (interface{}, error) {
	if p.bmcService == nil {
		return nil, ErrBMCNotConfigured{}
	}
	state, err := p.bmcService.PowerStatus(ctx, profileID)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"profile_id": profileID,
		"state":      string(state),
	}, nil
}

// =============================================================================
// Boot device control
// =============================================================================

// BMCSetBootDevice sets the next-boot device override.
func (p *MCPServiceProvider) BMCSetBootDevice(ctx context.Context, profileID uint64, device string, persistent bool) (interface{}, error) {
	if p.bmcService == nil {
		return nil, ErrBMCNotConfigured{}
	}
	dev, ok := bmcBootDeviceFromString[device]
	if !ok {
		return nil, ErrBMCInvalidBootDevice{Device: device}
	}
	if err := p.bmcService.SetBootDevice(ctx, profileID, dev, persistent); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"profile_id": profileID,
		"device":     string(dev),
		"persistent": persistent,
	}, nil
}

// BMCGetBootDevice returns the current boot device override.
func (p *MCPServiceProvider) BMCGetBootDevice(ctx context.Context, profileID uint64) (interface{}, error) {
	if p.bmcService == nil {
		return nil, ErrBMCNotConfigured{}
	}
	dev, err := p.bmcService.GetBootDevice(ctx, profileID)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"profile_id": profileID,
		"device":     string(dev),
	}, nil
}

// =============================================================================
// Virtual media
// =============================================================================

// BMCMountISO mounts an ISO image via the BMC's virtual media subsystem.
func (p *MCPServiceProvider) BMCMountISO(ctx context.Context, profileID uint64, isoURL string) (interface{}, error) {
	if p.bmcService == nil {
		return nil, ErrBMCNotConfigured{}
	}
	if isoURL == "" {
		return nil, errors.New("bmc: iso_url is required")
	}
	if err := p.bmcService.MountISO(ctx, profileID, isoURL); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"profile_id": profileID,
		"mounted":    true,
		"iso_url":    isoURL,
	}, nil
}

// BMCUnmountISO ejects whatever virtual media is currently inserted.
func (p *MCPServiceProvider) BMCUnmountISO(ctx context.Context, profileID uint64) (interface{}, error) {
	if p.bmcService == nil {
		return nil, ErrBMCNotConfigured{}
	}
	if err := p.bmcService.UnmountISO(ctx, profileID); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"profile_id": profileID,
		"mounted":    false,
	}, nil
}

// BMCVirtualMediaStatus returns the current virtual media state.
func (p *MCPServiceProvider) BMCVirtualMediaStatus(ctx context.Context, profileID uint64) (interface{}, error) {
	if p.bmcService == nil {
		return nil, ErrBMCNotConfigured{}
	}
	info, err := p.bmcService.VirtualMediaStatus(ctx, profileID)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return map[string]interface{}{
			"profile_id": profileID,
			"mounted":    false,
		}, nil
	}
	return map[string]interface{}{
		"profile_id": profileID,
		"mounted":    info.Mounted,
		"image_url":  info.ImageURL,
		"media_type": info.MediaType,
	}, nil
}

// =============================================================================
// Monitoring
// =============================================================================

// BMCGetSensors returns sensor readings (temperatures, fans, voltages...).
func (p *MCPServiceProvider) BMCGetSensors(ctx context.Context, profileID uint64) (interface{}, error) {
	if p.bmcService == nil {
		return nil, ErrBMCNotConfigured{}
	}
	sensors, err := p.bmcService.GetSensors(ctx, profileID)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]interface{}, len(sensors))
	for i, s := range sensors {
		out[i] = map[string]interface{}{
			"name":   s.Name,
			"value":  s.Value,
			"units":  s.Units,
			"status": s.Status,
		}
	}
	return map[string]interface{}{
		"profile_id": profileID,
		"sensors":    out,
	}, nil
}

// BMCGetSystemInfo returns hardware/firmware identity info.
func (p *MCPServiceProvider) BMCGetSystemInfo(ctx context.Context, profileID uint64) (interface{}, error) {
	if p.bmcService == nil {
		return nil, ErrBMCNotConfigured{}
	}
	info, err := p.bmcService.GetSystemInfo(ctx, profileID)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return map[string]interface{}{"profile_id": profileID}, nil
	}
	return map[string]interface{}{
		"profile_id":       profileID,
		"manufacturer":     info.Manufacturer,
		"product":          info.Product,
		"serial_number":    info.SerialNumber,
		"firmware_version": info.FirmwareVersion,
		"bios_version":     info.BIOSVersion,
		"power_state":      string(info.PowerState),
	}, nil
}

// =============================================================================
// Certificate management (read-only over MCP)
// =============================================================================

// BMCGetWebCertificate returns the current BMC web certificate metadata.
func (p *MCPServiceProvider) BMCGetWebCertificate(ctx context.Context, profileID uint64) (interface{}, error) {
	if p.bmcService == nil {
		return nil, ErrBMCNotConfigured{}
	}
	info, err := p.bmcService.GetWebCertificate(ctx, profileID)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return map[string]interface{}{"profile_id": profileID}, nil
	}
	return map[string]interface{}{
		"profile_id":                profileID,
		"subject":                   info.Subject,
		"issuer":                    info.Issuer,
		"serial_number":             info.SerialNumber,
		"not_before":                info.NotBefore,
		"not_after":                 info.NotAfter,
		"days_remaining":            info.DaysRemaining,
		"subject_alternative_names": info.SubjectAlternativeNames,
		"fingerprint":               info.Fingerprint,
	}, nil
}

// =============================================================================
// User management (read-only over MCP)
// =============================================================================

// BMCListUsers returns populated BMC user slots.
func (p *MCPServiceProvider) BMCListUsers(ctx context.Context, profileID uint64) (interface{}, error) {
	if p.bmcService == nil {
		return nil, ErrBMCNotConfigured{}
	}
	users, err := p.bmcService.ListUsers(ctx, profileID)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]interface{}, len(users))
	for i, u := range users {
		out[i] = map[string]interface{}{
			"slot":      u.Slot,
			"username":  u.Username,
			"enabled":   u.Enabled,
			"privilege": u.Privilege.String(),
			"channel":   u.Channel,
		}
	}
	return map[string]interface{}{
		"profile_id": profileID,
		"users":      out,
	}, nil
}

// bmcEnrollResultToMap converts an app.BMCEnrollResult into a JSON-friendly
// map[string]interface{} so MCP clients receive structured output matching
// the REST EnrollResponse and gRPC BMCEnrollResponse shapes.
func bmcEnrollResultToMap(r *app.BMCEnrollResult) map[string]interface{} {
	if r == nil {
		return map[string]interface{}{}
	}

	meta := map[string]interface{}{
		"subject":       r.FactoryCertMeta.Subject,
		"issuer":        r.FactoryCertMeta.Issuer,
		"serial_number": r.FactoryCertMeta.SerialNumber,
		"not_before":    r.FactoryCertMeta.NotBefore,
		"not_after":     r.FactoryCertMeta.NotAfter,
		"spki_sha256":   r.FactoryCertMeta.SPKISHA256,
		"sha256":        r.FactoryCertMeta.SHA256,
		"captured_at":   r.FactoryCertMeta.CapturedAt,
	}

	steps := make([]map[string]interface{}, len(r.Steps))
	for i, s := range r.Steps {
		steps[i] = map[string]interface{}{
			"name":   s.Name,
			"ok":     s.OK,
			"detail": s.Detail,
		}
	}

	out := map[string]interface{}{
		"device_id":         r.DeviceID,
		"endpoint":          r.Endpoint,
		"hostname":          r.Hostname,
		"dns_name":          r.DNSName,
		"pin_spki_sha256":   r.PinSPKISHA256,
		"factory_cert_meta": meta,
		"steps":             steps,
	}
	if len(r.FactoryCertPEM) > 0 {
		out["factory_cert_pem"] = string(r.FactoryCertPEM)
	}
	if len(r.NewCertPEM) > 0 {
		out["new_cert_pem"] = string(r.NewCertPEM)
	}
	if len(r.CACertPEM) > 0 {
		out["ca_cert_pem"] = string(r.CACertPEM)
	}
	return out
}

// =============================================================================
// Helpers
// =============================================================================

// bmcPowerResultJSON formats the (previous, current) power state pair as
// a JSON-friendly map. Mirrors the proto BMCPowerResponse shape so MCP
// clients see fields the gRPC clients already know.
func bmcPowerResultJSON(previous, current bmc.PowerState) map[string]interface{} {
	return map[string]interface{}{
		"previous_state": string(previous),
		"current_state":  string(current),
	}
}

// =============================================================================
// Factory-certificate restore (MCP)
// =============================================================================

// BMCRestoreFactoryCert performs the BMC factory-certificate restore ceremony.
// It satisfies the mcp.BMCProvider extension for the platform_bmc_cert_restore
// MCP tool.
func (p *MCPServiceProvider) BMCRestoreFactoryCert(
	ctx context.Context,
	profileID uint64,
) (interface{}, error) {
	if p.bmcRestorer == nil {
		return nil, ErrBMCRestorerNotConfigured{}
	}
	bmcCfg, err := loadBMCConfigForRestorer(ctx, p.deviceProfileService, profileID, p.bmcRestorer)
	if err != nil {
		return nil, err
	}
	result, err := p.bmcRestorer.RestoreBMC(ctx, profileID, bmcCfg)
	if err != nil {
		return nil, err
	}
	steps := make([]map[string]interface{}, len(result.Steps))
	for i, s := range result.Steps {
		steps[i] = map[string]interface{}{
			"name":   s.Name,
			"ok":     s.OK,
			"detail": s.Detail,
		}
	}
	return map[string]interface{}{
		"device_id": result.DeviceID,
		"endpoint":  result.Endpoint,
		"hostname":  result.Hostname,
		"steps":     steps,
		"new_cert_meta": map[string]interface{}{
			"subject":       result.NewCertMeta.Subject,
			"issuer":        result.NewCertMeta.Issuer,
			"serial_number": result.NewCertMeta.SerialNumber,
			"spki_sha256":   result.NewCertMeta.SPKISHA256,
			"sha256":        result.NewCertMeta.SHA256,
		},
	}, nil
}
