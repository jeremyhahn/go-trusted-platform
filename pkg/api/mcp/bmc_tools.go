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

package mcp

import (
	"context"
	"errors"
)

// =============================================================================
// BMC tool wiring
// =============================================================================
//
// These tools mirror the gRPC BMCService surface so AI/LLM clients can drive
// the same bare-metal management workflows over MCP. Tool names follow the
// project convention `platform_bmc_<verb>` and are routed through a
// map-based dispatcher (O(1) lookup per project conventions).
//
// The MCP server stays decoupled from the daemon: the underlying daemon
// service is exposed via the optional BMCProvider interface, satisfied by
// the daemon's MCPServiceProvider when a *bmc.Service is wired in. When a
// provider is not wired, every BMC tool returns ErrBMCNotConfigured so
// clients receive a clear, structured failure rather than a generic
// "unknown tool" error.

// ErrBMCNotConfigured indicates the BMC backend is not wired into the MCP
// tool registry. Clients see this when the daemon was started without a
// BMC service available (e.g., the IPMI client factory failed to load).
var ErrBMCNotConfigured = errors.New("bmc: service provider not configured")

// BMCProvider is the optional interface a ServiceProvider can satisfy to
// unlock BMC MCP tools. Implementations are expected to delegate to the
// platform bmc.Service (the same backing implementation that powers the
// gRPC BMCService) so the MCP and gRPC surfaces remain in lockstep.
//
// Method names map to MCP tools: platform_bmc_power_on, etc.
type BMCProvider interface {
	// Power management
	BMCPowerOn(ctx context.Context, profileID uint64) (interface{}, error)
	BMCPowerOff(ctx context.Context, profileID uint64) (interface{}, error)
	BMCPowerReset(ctx context.Context, profileID uint64) (interface{}, error)
	BMCPowerCycle(ctx context.Context, profileID uint64) (interface{}, error)
	BMCPowerStatus(ctx context.Context, profileID uint64) (interface{}, error)

	// Boot device control
	BMCSetBootDevice(ctx context.Context, profileID uint64, device string, persistent bool) (interface{}, error)
	BMCGetBootDevice(ctx context.Context, profileID uint64) (interface{}, error)

	// Virtual media
	BMCMountISO(ctx context.Context, profileID uint64, isoURL string) (interface{}, error)
	BMCUnmountISO(ctx context.Context, profileID uint64) (interface{}, error)
	BMCVirtualMediaStatus(ctx context.Context, profileID uint64) (interface{}, error)

	// Monitoring
	BMCGetSensors(ctx context.Context, profileID uint64) (interface{}, error)
	BMCGetSystemInfo(ctx context.Context, profileID uint64) (interface{}, error)

	// Certificate management (read-only over MCP — replace flows go through
	// the dedicated cert lifecycle pipeline; see docs/architecture/bmc-tls.md)
	BMCGetWebCertificate(ctx context.Context, profileID uint64) (interface{}, error)

	// User management (read-only over MCP — write operations require
	// privileged credentials and live on the gRPC/Unix surfaces).
	BMCListUsers(ctx context.Context, profileID uint64) (interface{}, error)
}

// bmcProvider returns the BMCProvider interface if the ServiceProvider
// implements it, else nil.
func (r *ToolRegistry) bmcProvider() BMCProvider {
	if p, ok := r.service.(BMCProvider); ok {
		return p
	}
	return nil
}

// registerBMCTools registers the platform_bmc_* MCP tools. Each tool
// definition mirrors the equivalent gRPC RPC so AI/LLM clients can issue
// the same calls they would over gRPC.
func (r *ToolRegistry) registerBMCTools() {
	// All BMC tools key off a 64-bit device profile id. Description copy
	// is borrowed from bmc.proto so MCP and gRPC docs stay aligned.
	profileSchema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"profile_id": map[string]interface{}{
				"type":        "integer",
				"description": "Device profile id identifying the BMC-managed system",
			},
		},
		"required": []string{"profile_id"},
	}

	r.addTool(ToolDefinition{
		Name:        "platform_bmc_power_on",
		Description: "Power on the BMC-managed system",
		InputSchema: profileSchema,
	})
	r.addTool(ToolDefinition{
		Name:        "platform_bmc_power_off",
		Description: "Power off the BMC-managed system",
		InputSchema: profileSchema,
	})
	r.addTool(ToolDefinition{
		Name:        "platform_bmc_power_reset",
		Description: "Hard reset the BMC-managed system",
		InputSchema: profileSchema,
	})
	r.addTool(ToolDefinition{
		Name:        "platform_bmc_power_cycle",
		Description: "Power cycle the BMC-managed system",
		InputSchema: profileSchema,
	})
	r.addTool(ToolDefinition{
		Name:        "platform_bmc_power_status",
		Description: "Query the current power state of the BMC-managed system",
		InputSchema: profileSchema,
	})

	r.addTool(ToolDefinition{
		Name:        "platform_bmc_set_boot_device",
		Description: "Set the next boot device override (pxe, disk, cdrom, virtual_media, none)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"profile_id": map[string]interface{}{"type": "integer"},
				"device": map[string]interface{}{
					"type":        "string",
					"description": "Boot device: pxe | disk | cdrom | virtual_media | none",
				},
				"persistent": map[string]interface{}{
					"type":        "boolean",
					"description": "Persist override across reboots (default false: next-boot only)",
				},
			},
			"required": []string{"profile_id", "device"},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_bmc_get_boot_device",
		Description: "Return the current boot device override",
		InputSchema: profileSchema,
	})

	r.addTool(ToolDefinition{
		Name:        "platform_bmc_mount_iso",
		Description: "Mount an ISO image via virtual media (HTTP/HTTPS URL)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"profile_id": map[string]interface{}{"type": "integer"},
				"iso_url":    map[string]interface{}{"type": "string"},
			},
			"required": []string{"profile_id", "iso_url"},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "platform_bmc_unmount_iso",
		Description: "Eject the currently mounted virtual media",
		InputSchema: profileSchema,
	})
	r.addTool(ToolDefinition{
		Name:        "platform_bmc_virtual_media_status",
		Description: "Report whether virtual media is mounted and what is loaded",
		InputSchema: profileSchema,
	})

	r.addTool(ToolDefinition{
		Name:        "platform_bmc_get_sensors",
		Description: "Read all BMC sensor values (temperatures, fans, voltages, etc.)",
		InputSchema: profileSchema,
	})
	r.addTool(ToolDefinition{
		Name:        "platform_bmc_get_system_info",
		Description: "Return manufacturer, product, serial, firmware/BIOS versions and power state",
		InputSchema: profileSchema,
	})

	r.addTool(ToolDefinition{
		Name:        "platform_bmc_get_web_certificate",
		Description: "Inspect the BMC's HTTPS certificate (subject, issuer, expiry, fingerprint)",
		InputSchema: profileSchema,
	})

	r.addTool(ToolDefinition{
		Name:        "platform_bmc_list_users",
		Description: "List populated BMC user slots (slot, username, enabled, privilege, channel)",
		InputSchema: profileSchema,
	})
}

// =============================================================================
// Map-based dispatch
// =============================================================================

// bmcToolHandler dispatches a BMC tool by name. Map-based dispatch keeps
// routing O(1) per project conventions.
type bmcToolHandler func(*ToolRegistry, context.Context, map[string]interface{}) (interface{}, error)

var bmcToolDispatch = map[string]bmcToolHandler{
	"platform_bmc_power_on":             (*ToolRegistry).executeBMCPowerOn,
	"platform_bmc_power_off":            (*ToolRegistry).executeBMCPowerOff,
	"platform_bmc_power_reset":          (*ToolRegistry).executeBMCPowerReset,
	"platform_bmc_power_cycle":          (*ToolRegistry).executeBMCPowerCycle,
	"platform_bmc_power_status":         (*ToolRegistry).executeBMCPowerStatus,
	"platform_bmc_set_boot_device":      (*ToolRegistry).executeBMCSetBootDevice,
	"platform_bmc_get_boot_device":      (*ToolRegistry).executeBMCGetBootDevice,
	"platform_bmc_mount_iso":            (*ToolRegistry).executeBMCMountISO,
	"platform_bmc_unmount_iso":          (*ToolRegistry).executeBMCUnmountISO,
	"platform_bmc_virtual_media_status": (*ToolRegistry).executeBMCVirtualMediaStatus,
	"platform_bmc_get_sensors":          (*ToolRegistry).executeBMCGetSensors,
	"platform_bmc_get_system_info":      (*ToolRegistry).executeBMCGetSystemInfo,
	"platform_bmc_get_web_certificate":  (*ToolRegistry).executeBMCGetWebCertificate,
	"platform_bmc_list_users":           (*ToolRegistry).executeBMCListUsers,
}

// dispatchBMCTool looks up a BMC tool and invokes it. Returns
// (result, handled, err) so the caller can fall through when handled is
// false (tool name doesn't belong to BMC).
func (r *ToolRegistry) dispatchBMCTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	fn, ok := bmcToolDispatch[name]
	if !ok {
		return nil, false, nil
	}
	result, err := fn(r, ctx, args)
	return result, true, err
}

// =============================================================================
// Argument helpers
// =============================================================================

// bmcProfileID extracts the required `profile_id` argument as a uint64.
// Returns ErrBMCProfileIDRequired when missing or zero.
func bmcProfileID(args map[string]interface{}) (uint64, error) {
	id := uint64(getInt64(args, "profile_id"))
	if id == 0 {
		return 0, ErrBMCProfileIDRequired
	}
	return id, nil
}

// ErrBMCProfileIDRequired indicates the profile_id argument is missing
// or zero. profile_id is the primary key for every BMC RPC.
var ErrBMCProfileIDRequired = errors.New("bmc: profile_id is required and must be non-zero")

// ErrBMCBootDeviceRequired indicates the `device` argument is missing.
var ErrBMCBootDeviceRequired = errors.New("bmc: device is required (pxe|disk|cdrom|virtual_media|none)")

// ErrBMCISOURLRequired indicates the `iso_url` argument is missing.
var ErrBMCISOURLRequired = errors.New("bmc: iso_url is required")

// =============================================================================
// Executors
// =============================================================================

func (r *ToolRegistry) executeBMCPowerOn(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.bmcProvider()
	if p == nil {
		return nil, ErrBMCNotConfigured
	}
	id, err := bmcProfileID(args)
	if err != nil {
		return nil, err
	}
	return p.BMCPowerOn(ctx, id)
}

func (r *ToolRegistry) executeBMCPowerOff(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.bmcProvider()
	if p == nil {
		return nil, ErrBMCNotConfigured
	}
	id, err := bmcProfileID(args)
	if err != nil {
		return nil, err
	}
	return p.BMCPowerOff(ctx, id)
}

func (r *ToolRegistry) executeBMCPowerReset(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.bmcProvider()
	if p == nil {
		return nil, ErrBMCNotConfigured
	}
	id, err := bmcProfileID(args)
	if err != nil {
		return nil, err
	}
	return p.BMCPowerReset(ctx, id)
}

func (r *ToolRegistry) executeBMCPowerCycle(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.bmcProvider()
	if p == nil {
		return nil, ErrBMCNotConfigured
	}
	id, err := bmcProfileID(args)
	if err != nil {
		return nil, err
	}
	return p.BMCPowerCycle(ctx, id)
}

func (r *ToolRegistry) executeBMCPowerStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.bmcProvider()
	if p == nil {
		return nil, ErrBMCNotConfigured
	}
	id, err := bmcProfileID(args)
	if err != nil {
		return nil, err
	}
	return p.BMCPowerStatus(ctx, id)
}

func (r *ToolRegistry) executeBMCSetBootDevice(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.bmcProvider()
	if p == nil {
		return nil, ErrBMCNotConfigured
	}
	id, err := bmcProfileID(args)
	if err != nil {
		return nil, err
	}
	device := getString(args, "device")
	if device == "" {
		return nil, ErrBMCBootDeviceRequired
	}
	persistent := getBool(args, "persistent")
	return p.BMCSetBootDevice(ctx, id, device, persistent)
}

func (r *ToolRegistry) executeBMCGetBootDevice(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.bmcProvider()
	if p == nil {
		return nil, ErrBMCNotConfigured
	}
	id, err := bmcProfileID(args)
	if err != nil {
		return nil, err
	}
	return p.BMCGetBootDevice(ctx, id)
}

func (r *ToolRegistry) executeBMCMountISO(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.bmcProvider()
	if p == nil {
		return nil, ErrBMCNotConfigured
	}
	id, err := bmcProfileID(args)
	if err != nil {
		return nil, err
	}
	isoURL := getString(args, "iso_url")
	if isoURL == "" {
		return nil, ErrBMCISOURLRequired
	}
	return p.BMCMountISO(ctx, id, isoURL)
}

func (r *ToolRegistry) executeBMCUnmountISO(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.bmcProvider()
	if p == nil {
		return nil, ErrBMCNotConfigured
	}
	id, err := bmcProfileID(args)
	if err != nil {
		return nil, err
	}
	return p.BMCUnmountISO(ctx, id)
}

func (r *ToolRegistry) executeBMCVirtualMediaStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.bmcProvider()
	if p == nil {
		return nil, ErrBMCNotConfigured
	}
	id, err := bmcProfileID(args)
	if err != nil {
		return nil, err
	}
	return p.BMCVirtualMediaStatus(ctx, id)
}

func (r *ToolRegistry) executeBMCGetSensors(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.bmcProvider()
	if p == nil {
		return nil, ErrBMCNotConfigured
	}
	id, err := bmcProfileID(args)
	if err != nil {
		return nil, err
	}
	return p.BMCGetSensors(ctx, id)
}

func (r *ToolRegistry) executeBMCGetSystemInfo(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.bmcProvider()
	if p == nil {
		return nil, ErrBMCNotConfigured
	}
	id, err := bmcProfileID(args)
	if err != nil {
		return nil, err
	}
	return p.BMCGetSystemInfo(ctx, id)
}

func (r *ToolRegistry) executeBMCGetWebCertificate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.bmcProvider()
	if p == nil {
		return nil, ErrBMCNotConfigured
	}
	id, err := bmcProfileID(args)
	if err != nil {
		return nil, err
	}
	return p.BMCGetWebCertificate(ctx, id)
}

func (r *ToolRegistry) executeBMCListUsers(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.bmcProvider()
	if p == nil {
		return nil, ErrBMCNotConfigured
	}
	id, err := bmcProfileID(args)
	if err != nil {
		return nil, err
	}
	return p.BMCListUsers(ctx, id)
}
