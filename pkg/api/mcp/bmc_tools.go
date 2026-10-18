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
	"maps"
	"slices"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// =============================================================================
// BMC tool wiring
// =============================================================================
//
// Every gRPC BMCService method has one platform_bmc_<verb> tool. A tool's
// arguments are the gRPC request in protojson form (proto field names, enums
// by name, 64-bit integers and bytes as JSON strings) and its result is the
// gRPC response in the same form. Each tool calls the gRPC BMCService
// servicer, so it validates, answers and fails exactly as gRPC does.

// ErrBMCNotConfigured indicates the BMC backend is not wired into the MCP
// tool registry. Clients see this when the daemon was started without a
// BMC service available (e.g., the IPMI client factory failed to load).
var ErrBMCNotConfigured = errors.New("bmc: service provider not configured")

// BMCProvider is implemented by a ServiceProvider that serves the gRPC
// BMCService. The platform_bmc_* tools call that servicer.
type BMCProvider interface {
	// BMCServiceServer returns the gRPC BMCService servicer, or nil while
	// no BMC service is wired.
	BMCServiceServer() platformv1.BMCServiceServer
}

// bmcTool is one BMC tool and the permission it requires.
type bmcTool struct {
	// method is the gRPC method the tool serves.
	method string
	// scope is the permission the tool requires: the scope of its gRPC
	// method in pkg/api/grpc/method_permissions.go. authz.go records why the
	// BMC scopes split on effect.
	scope       string
	description string
	binding     grpcToolBinding[platformv1.BMCServiceServer]
}

// bmcTools are the BMC tools bound to the gRPC BMCService.
var bmcTools = map[string]bmcTool{
	"platform_bmc_power_on": {
		method:      platformv1.BMCService_PowerOn_FullMethodName,
		scope:       "bmc:write",
		description: "Power on the BMC-managed system",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.PowerOn, "profile_id"),
	},
	"platform_bmc_power_off": {
		method:      platformv1.BMCService_PowerOff_FullMethodName,
		scope:       "bmc:power",
		description: "Power off the BMC-managed system",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.PowerOff, "profile_id"),
	},
	"platform_bmc_power_reset": {
		method:      platformv1.BMCService_PowerReset_FullMethodName,
		scope:       "bmc:power",
		description: "Hard reset the BMC-managed system",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.PowerReset, "profile_id"),
	},
	"platform_bmc_power_cycle": {
		method:      platformv1.BMCService_PowerCycle_FullMethodName,
		scope:       "bmc:power",
		description: "Power cycle the BMC-managed system",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.PowerCycle, "profile_id"),
	},
	"platform_bmc_power_status": {
		method:      platformv1.BMCService_PowerStatus_FullMethodName,
		scope:       "bmc:read",
		description: "Query the current power state of the BMC-managed system",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.PowerStatus, "profile_id"),
	},
	"platform_bmc_set_boot_device": {
		method:      platformv1.BMCService_SetBootDevice_FullMethodName,
		scope:       "bmc:write",
		description: "Set the next boot device override (BMC_BOOT_DEVICE_PXE, _DISK, _CDROM, _VIRTUAL_MEDIA or _NONE); persistent keeps it across reboots",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.SetBootDevice, "profile_id", "device"),
	},
	"platform_bmc_get_boot_device": {
		method:      platformv1.BMCService_GetBootDevice_FullMethodName,
		scope:       "bmc:read",
		description: "Return the current boot device override",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.GetBootDevice, "profile_id"),
	},
	"platform_bmc_mount_iso": {
		method:      platformv1.BMCService_MountISO_FullMethodName,
		scope:       "bmc:media",
		description: "Mount an ISO image via virtual media (HTTP/HTTPS URL)",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.MountISO, "profile_id", "iso_url"),
	},
	"platform_bmc_unmount_iso": {
		method:      platformv1.BMCService_UnmountISO_FullMethodName,
		scope:       "bmc:media",
		description: "Eject the currently mounted virtual media",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.UnmountISO, "profile_id"),
	},
	"platform_bmc_virtual_media_status": {
		method:      platformv1.BMCService_VirtualMediaStatus_FullMethodName,
		scope:       "bmc:read",
		description: "Report whether virtual media is mounted and what is loaded",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.VirtualMediaStatus, "profile_id"),
	},
	"platform_bmc_get_sensors": {
		method:      platformv1.BMCService_GetSensors_FullMethodName,
		scope:       "bmc:read",
		description: "Read all BMC sensor values (temperatures, fans, voltages, etc.)",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.GetSensors, "profile_id"),
	},
	"platform_bmc_get_system_info": {
		method:      platformv1.BMCService_GetSystemInfo_FullMethodName,
		scope:       "bmc:read",
		description: "Return manufacturer, product, serial, firmware/BIOS versions and power state",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.GetSystemInfo, "profile_id"),
	},
	"platform_bmc_provision": {
		method:      platformv1.BMCService_Provision_FullMethodName,
		scope:       "bmc:admin",
		description: "Start the orchestrated provisioning workflow, which composes virtual media, boot device and power control to boot the system from iso_url",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.Provision, "profile_id", "iso_url"),
	},
	"platform_bmc_provision_status": {
		method:      platformv1.BMCService_ProvisionStatus_FullMethodName,
		scope:       "bmc:read",
		description: "Report the provisioning workflow status of the BMC-managed system",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.ProvisionStatus, "profile_id"),
	},
	"platform_bmc_get_web_certificate": {
		method:      platformv1.BMCService_GetWebCertificate_FullMethodName,
		scope:       "bmc:read",
		description: "Inspect the BMC's HTTPS certificate (subject, issuer, expiry, fingerprint)",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.GetWebCertificate, "profile_id"),
	},
	"platform_bmc_replace_web_certificate": {
		method:      platformv1.BMCService_ReplaceWebCertificate_FullMethodName,
		scope:       "bmc:admin",
		description: "Install a PEM certificate (cert_pem) and private key (key_pem), both base64, as the BMC's HTTPS certificate",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.ReplaceWebCertificate, "profile_id", "cert_pem", "key_pem"),
	},
	"platform_bmc_enroll": {
		method:      platformv1.BMCService_EnrollBMC_FullMethodName,
		scope:       "bmc:admin",
		description: "Run the BMC enrollment ceremony: establish trust, capture factory certificate, optionally replace the certificate, register DNS, and publish DANE TLSA records; an absent flag uses the profile default",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.EnrollBMC, "profile_id"),
	},
	"platform_bmc_cert_restore": {
		method:      platformv1.BMCService_RestoreFactoryCert_FullMethodName,
		scope:       "bmc:admin",
		description: "Run the BMC factory-certificate restore ceremony: instruct the BMC to regenerate its default self-signed certificate, delete the stored SPKI pin, unpublish DANE TLSA records, and clear the device enrollment state",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.RestoreFactoryCert, "profile_id"),
	},
	"platform_bmc_list_users": {
		method:      platformv1.BMCService_ListUsers_FullMethodName,
		scope:       "bmc:read",
		description: "List populated BMC user slots (slot, username, enabled, privilege, channel)",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.ListUsers, "profile_id"),
	},
	"platform_bmc_create_user": {
		method:      platformv1.BMCService_CreateUser_FullMethodName,
		scope:       "bmc:admin",
		description: "Create a BMC user account in the given slot with an initial password",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.CreateUser, "profile_id", "user", "password"),
	},
	"platform_bmc_delete_user": {
		method:      platformv1.BMCService_DeleteUser_FullMethodName,
		scope:       "bmc:admin",
		description: "Delete the BMC user account in a slot",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.DeleteUser, "profile_id", "slot"),
	},
	"platform_bmc_set_user_password": {
		method:      platformv1.BMCService_SetUserPassword_FullMethodName,
		scope:       "bmc:admin",
		description: "Set the password of the BMC user account in a slot",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.SetUserPassword, "profile_id", "slot", "password"),
	},
	"platform_bmc_set_user_privilege": {
		method:      platformv1.BMCService_SetUserPrivilege_FullMethodName,
		scope:       "bmc:admin",
		description: "Set the privilege level of the BMC user account in a slot on an IPMI channel",
		binding:     grpcToolMethod(platformv1.BMCServiceServer.SetUserPrivilege, "profile_id", "slot", "privilege"),
	},
}

// registerBMCTools registers the platform_bmc_* tools.
func (r *ToolRegistry) registerBMCTools() {
	for _, name := range slices.Sorted(maps.Keys(bmcTools)) {
		tool := bmcTools[name]
		r.addTool(mcpwire.ToolDefinition{
			Name:        name,
			Description: tool.description,
			InputSchema: tool.binding.schema(),
		})
	}
}

// bmcServiceServer is the gRPC BMCService servicer the BMC tools call, or
// nil while the service provider serves none.
func (r *ToolRegistry) bmcServiceServer() platformv1.BMCServiceServer {
	if provider, ok := r.service.(BMCProvider); ok {
		return provider.BMCServiceServer()
	}
	return nil
}

// dispatchBMCTool runs a platform_bmc_* tool. handled is false when name is
// not a BMC tool, so the caller tries the next dispatcher.
func (r *ToolRegistry) dispatchBMCTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	tool, ok := bmcTools[name]
	if !ok {
		return nil, false, nil
	}
	server := r.bmcServiceServer()
	if server == nil {
		return nil, true, ErrBMCNotConfigured
	}
	result, err := tool.binding.call(server, ctx, args)
	return result, true, err
}
