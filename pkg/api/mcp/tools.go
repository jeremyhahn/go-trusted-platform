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
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// ToolRegistry manages MCP tools and their execution.
type ToolRegistry struct {
	authChecker *AuthorizationChecker
	service     ServiceProvider
	logger      *logging.Logger
	tools       []ToolDefinition
}

// NewToolRegistry creates a new tool registry.
func NewToolRegistry(svc ServiceProvider, log *logging.Logger) *ToolRegistry {
	r := &ToolRegistry{
		service: svc,
		logger:  log,
		tools:   make([]ToolDefinition, 0, 195),
	}

	// Register all tools
	r.registerTools()

	return r
}

// registerTools registers all available platform operations as MCP tools.
func (r *ToolRegistry) registerTools() {
	// Register vTPM tools
	r.registerVTPMTools()

	// Register vTPM bundle/template tools
	r.registerVTPMBundleTools()

	// Register DNS tools
	r.registerDNSTools()

	// Register DNS extended tools (zone/record management)
	r.registerDNSExtendedTools()

	// Register Device tools
	r.registerDeviceTools()

	// Register Device tools (extended V2 with profiles)
	r.registerDeviceToolsV2()

	// Register SDN tools
	r.registerSDNTools()

	// Register Overlay network tools
	r.registerOverlayTools()

	// Register Gateway tools
	r.registerGatewayTools()

	// Register Gateway load balancer tools
	r.registerGatewayLBTools()
	r.registerGatewayNAT64Tools()
	r.registerGatewayPerfTools()

	// Register NTP (time synchronization) tools
	r.registerNTPTools()

	// Register Health tools
	r.registerHealthTools()

	// Register Daemon management tools
	r.registerDaemonTools()

	// Register CA tools
	r.registerCATools()

	// Register IAM tools
	r.registerIAMTools()

	// Register KMS tools
	r.registerKMSTools()

	// Register Container tools
	r.registerContainerTools()

	// Register operational container tools (exec, metrics)
	r.registerContainerOpsTools()

	// Register VM tools
	r.registerVMTools()

	// Register operational VM tools (metrics, disk ops, logs snapshot, migrate)
	r.registerVMOpsTools()

	// Register Attestation tools
	r.registerAttestationTools()
	r.registerAttestationReportTools()

	// Register IDevID/IAK tools (IEEE 802.1AR device identity)
	r.registerIDevIDTools()

	// Register LDevID tool (IEEE 802.1AR local device identity)
	r.registerLDevIDTools()

	// Register Tenant management tools (multi-tenancy)
	r.registerTenantTools()

	// Register physical TPM tools
	r.registerTPMTools()

	// Register physical switch management tools
	r.registerSwitchTools()

	// Register BMC (baseboard management controller) tools mirroring the
	// gRPC BMCService surface.
	r.registerBMCTools()

	// Register Cluster lifecycle tools mirroring the gRPC ClusterService
	// surface.
	r.registerClusterTools()

	// Register Registry (container/artifact registry) tools mirroring the
	// non-streaming portion of the gRPC RegistryService surface.
	r.registerRegistryTools()

	// Register Invitation tools mirroring the gRPC InvitationService surface.
	r.registerInvitationTools()

	// Register EAB (External Account Binding) tools mirroring the gRPC
	// EABService surface (RFC 8555 §7.3.4 device enrollment credentials).
	r.registerEABTools()

	// Register Phase 3.5 tools (ceremony, piv, luks, fido2).
	r.registerPhase35Tools()

	// Register config delivery provisioning tools mirroring the gRPC
	// ConfigDeliveryService surface.
	r.registerProvisionTools()

	// Register reverse-proxy configuration tools mirroring the gRPC
	// ProxyService surface.
	r.registerProxyTools()
}

// registerVTPMTools registers vTPM-related tools.
func (r *ToolRegistry) registerVTPMTools() {
	r.addTool(ToolDefinition{
		Name:        "vtpm_create",
		Description: "Create a new virtual TPM instance",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name":      map[string]interface{}{"type": "string", "description": "Name for the vTPM instance"},
				"algorithm": map[string]interface{}{"type": "string", "description": "Algorithm type (RSA, ECC)", "default": "RSA"},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_delete",
		Description: "Delete a virtual TPM instance",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{"type": "string", "description": "Name of the vTPM instance to delete"},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_list",
		Description: "List all virtual TPM instances",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_start",
		Description: "Start a virtual TPM instance",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{"type": "string", "description": "Name of the vTPM instance to start"},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_stop",
		Description: "Stop a virtual TPM instance",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{"type": "string", "description": "Name of the vTPM instance to stop"},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_quote",
		Description: "Generate a TPM quote for attestation",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name":  map[string]interface{}{"type": "string", "description": "Name of the vTPM instance"},
				"nonce": map[string]interface{}{"type": "string", "description": "Base64-encoded nonce for the quote"},
				"pcrs":  map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "integer"}, "description": "PCR indices to include in quote"},
			},
			"required": []string{"name", "nonce", "pcrs"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_seal",
		Description: "Seal data to TPM PCR state",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{"type": "string", "description": "Name of the vTPM instance"},
				"data": map[string]interface{}{"type": "string", "description": "Base64-encoded data to seal"},
				"pcrs": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "integer"}, "description": "PCR indices for sealing policy"},
			},
			"required": []string{"name", "data", "pcrs"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_unseal",
		Description: "Unseal data from TPM",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name":   map[string]interface{}{"type": "string", "description": "Name of the vTPM instance"},
				"sealed": map[string]interface{}{"type": "string", "description": "Base64-encoded sealed data"},
			},
			"required": []string{"name", "sealed"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_extend_pcr",
		Description: "Extend a PCR with a measurement",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{"type": "string", "description": "Name of the vTPM instance"},
				"pcr":  map[string]interface{}{"type": "integer", "description": "PCR index to extend"},
				"data": map[string]interface{}{"type": "string", "description": "Base64-encoded data to extend into PCR"},
			},
			"required": []string{"name", "pcr", "data"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_read_pcr",
		Description: "Read a PCR value",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{"type": "string", "description": "Name of the vTPM instance"},
				"pcr":  map[string]interface{}{"type": "integer", "description": "PCR index to read"},
			},
			"required": []string{"name", "pcr"},
		},
	})

	// Extended vTPM tools - bundle get, validate, export, import
	r.addTool(ToolDefinition{
		Name:        "vtpm_get",
		Description: "Get detailed information about a vTPM bundle",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{"type": "string", "description": "Bundle ID or hostname"},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_validate",
		Description: "Validate bundle integrity",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{"type": "string", "description": "Bundle ID to validate"},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_export",
		Description: "Export a vTPM bundle to a base64-encoded archive",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{"type": "string", "description": "Bundle ID to export"},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_import",
		Description: "Import a vTPM bundle from base64-encoded archive data",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"data": map[string]interface{}{"type": "string", "description": "Base64-encoded archive data"},
			},
			"required": []string{"data"},
		},
	})

	// Template operations
	r.addTool(ToolDefinition{
		Name:        "vtpm_template_create",
		Description: "Create a reusable vTPM template",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id":          map[string]interface{}{"type": "string", "description": "Unique template identifier"},
				"description": map[string]interface{}{"type": "string", "description": "Template description"},
				"algorithm":   map[string]interface{}{"type": "string", "description": "EK algorithm (RSA or ECC)", "default": "RSA"},
				"secure_boot": map[string]interface{}{"type": "boolean", "description": "Enable Secure Boot", "default": false},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_template_get",
		Description: "Get detailed information about a vTPM template",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{"type": "string", "description": "Template ID"},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_template_delete",
		Description: "Delete a vTPM template",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{"type": "string", "description": "Template ID to delete"},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_template_list",
		Description: "List all vTPM templates",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_template_clone",
		Description: "Clone a template to create a new bundle with identity",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"template_id": map[string]interface{}{"type": "string", "description": "Template ID to clone"},
				"hostname":    map[string]interface{}{"type": "string", "description": "Hostname for the new bundle"},
				"labels":      map[string]interface{}{"type": "object", "description": "Custom metadata labels"},
			},
			"required": []string{"template_id", "hostname"},
		},
	})

	// Path operations
	r.addTool(ToolDefinition{
		Name:        "vtpm_get_bundle_path",
		Description: "Get the filesystem path to a vTPM bundle",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{"type": "string", "description": "Bundle ID"},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_get_tpm_socket_path",
		Description: "Get the TPM socket path for a bundle",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{"type": "string", "description": "Bundle ID"},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_get_nvram_path",
		Description: "Get the OVMF NVRAM path for a bundle",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{"type": "string", "description": "Bundle ID"},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "vtpm_is_running",
		Description: "Check if a vTPM bundle is running",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{"type": "string", "description": "Bundle ID"},
			},
			"required": []string{"name"},
		},
	})

}

// registerDNSTools registers DNS-related tools.
func (r *ToolRegistry) registerDNSTools() {
	r.addTool(ToolDefinition{
		Name:        "dns_add_record",
		Description: "Add a DNS record",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name":        map[string]interface{}{"type": "string", "description": "Record name (FQDN)"},
				"record_type": map[string]interface{}{"type": "string", "description": "Record type (A, AAAA, CNAME, MX, TXT, etc.)"},
				"value":       map[string]interface{}{"type": "string", "description": "Record value"},
				"ttl":         map[string]interface{}{"type": "integer", "description": "TTL in seconds", "default": 300},
			},
			"required": []string{"name", "record_type", "value"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "dns_delete_record",
		Description: "Delete a DNS record",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name":        map[string]interface{}{"type": "string", "description": "Record name (FQDN)"},
				"record_type": map[string]interface{}{"type": "string", "description": "Record type"},
			},
			"required": []string{"name", "record_type"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "dns_get_record",
		Description: "Get a DNS record",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name":        map[string]interface{}{"type": "string", "description": "Record name (FQDN)"},
				"record_type": map[string]interface{}{"type": "string", "description": "Record type"},
			},
			"required": []string{"name", "record_type"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "dns_list_records",
		Description: "List DNS records in a zone",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"zone": map[string]interface{}{"type": "string", "description": "Zone name"},
			},
			"required": []string{"zone"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "dns_resolve",
		Description: "Resolve a DNS name",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name":        map[string]interface{}{"type": "string", "description": "Name to resolve"},
				"record_type": map[string]interface{}{"type": "string", "description": "Record type", "default": "A"},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "dns_create_zone",
		Description: "Create a DNS zone",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"zone": map[string]interface{}{"type": "string", "description": "Zone name"},
			},
			"required": []string{"zone"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "dns_delete_zone",
		Description: "Delete a DNS zone",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"zone": map[string]interface{}{"type": "string", "description": "Zone name"},
			},
			"required": []string{"zone"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "dns_list_zones",
		Description: "List all DNS zones",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})
}

// registerDeviceTools registers Device-related tools.
func (r *ToolRegistry) registerDeviceTools() {
	r.addTool(ToolDefinition{
		Name:        "device_register",
		Description: "Register a new device",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name":        map[string]interface{}{"type": "string", "description": "Device name"},
				"device_type": map[string]interface{}{"type": "string", "description": "Device type"},
				"public_key":  map[string]interface{}{"type": "string", "description": "Base64-encoded device public key"},
			},
			"required": []string{"name", "device_type", "public_key"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "device_get",
		Description: "Get device details",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"device_id": map[string]interface{}{"type": "string", "description": "Device ID"},
			},
			"required": []string{"device_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "device_list",
		Description: "List devices",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"device_type": map[string]interface{}{"type": "string", "description": "Filter by device type"},
				"status":      map[string]interface{}{"type": "string", "description": "Filter by status"},
			},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "device_delete",
		Description: "Delete a device",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"device_id": map[string]interface{}{"type": "string", "description": "Device ID"},
			},
			"required": []string{"device_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "device_update",
		Description: "Update device properties",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"device_id": map[string]interface{}{"type": "string", "description": "Device ID"},
				"updates":   map[string]interface{}{"type": "object", "description": "Properties to update"},
			},
			"required": []string{"device_id", "updates"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "device_attest",
		Description: "Verify device attestation evidence",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"device_id": map[string]interface{}{"type": "string", "description": "Device ID"},
				"evidence":  map[string]interface{}{"type": "string", "description": "Base64-encoded attestation evidence"},
			},
			"required": []string{"device_id", "evidence"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "device_record_attest_cert",
		Description: "Record (or re-record) a device's attestation certificate on its platform record without re-enrolling it. Fails closed: the certificate must parse, chain to the platform CA, carry tcg-cap-verifiedTPMRestricted (2.23.133.11.1.3) and certify the device's enrolled attestation key, or nothing is written. Set reissue to let the CA issue a fresh certificate over the enrolled key.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"device_id": map[string]interface{}{"type": "string", "description": "Device ID"},
				"reissue":   map[string]interface{}{"type": "boolean", "description": "Ask the platform CA to issue a fresh attestation certificate over the enrolled attestation public key when no stored certificate passes the preflight"},
			},
			"required": []string{"device_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "device_provision",
		Description: "Provision a device with a profile",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"device_id": map[string]interface{}{"type": "string", "description": "Device ID"},
				"profile":   map[string]interface{}{"type": "string", "description": "Provisioning profile name"},
			},
			"required": []string{"device_id", "profile"},
		},
	})
}

// registerSDNTools registers SDN-related tools.
func (r *ToolRegistry) registerSDNTools() {
	r.addTool(ToolDefinition{
		Name:        "sdn_get_port_state",
		Description: "Get the state of an OVS port",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bridge_name": map[string]interface{}{"type": "string", "description": "Bridge name"},
				"port_name":   map[string]interface{}{"type": "string", "description": "Port name"},
			},
			"required": []string{"bridge_name", "port_name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "sdn_set_port_state",
		Description: "Set the state of an OVS port",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bridge_name": map[string]interface{}{"type": "string", "description": "Bridge name"},
				"port_name":   map[string]interface{}{"type": "string", "description": "Port name"},
				"state":       map[string]interface{}{"type": "string", "description": "Port state (up, down)"},
			},
			"required": []string{"bridge_name", "port_name", "state"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "sdn_list_bridges",
		Description: "List all OVS bridges",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "sdn_create_bridge",
		Description: "Create an OVS bridge",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bridge_name": map[string]interface{}{"type": "string", "description": "Bridge name"},
			},
			"required": []string{"bridge_name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "sdn_delete_bridge",
		Description: "Delete an OVS bridge",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bridge_name": map[string]interface{}{"type": "string", "description": "Bridge name"},
			},
			"required": []string{"bridge_name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "sdn_add_port",
		Description: "Add a port to an OVS bridge",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bridge_name": map[string]interface{}{"type": "string", "description": "Bridge name"},
				"port_name":   map[string]interface{}{"type": "string", "description": "Port name"},
				"port_type":   map[string]interface{}{"type": "string", "description": "Port type (internal, vxlan, etc.)"},
			},
			"required": []string{"bridge_name", "port_name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "sdn_delete_port",
		Description: "Delete a port from an OVS bridge",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bridge_name": map[string]interface{}{"type": "string", "description": "Bridge name"},
				"port_name":   map[string]interface{}{"type": "string", "description": "Port name"},
			},
			"required": []string{"bridge_name", "port_name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "sdn_apply_policy",
		Description: "Apply a network policy to a bridge",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"policy_id":   map[string]interface{}{"type": "string", "description": "Policy ID"},
				"bridge_name": map[string]interface{}{"type": "string", "description": "Bridge name"},
			},
			"required": []string{"policy_id", "bridge_name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "sdn_get_policy",
		Description: "Get a network policy",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"policy_id": map[string]interface{}{"type": "string", "description": "Policy ID"},
			},
			"required": []string{"policy_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "sdn_list_policies",
		Description: "List all network policies",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// Flow management tools
	r.addTool(ToolDefinition{
		Name:        "sdn_add_flow",
		Description: "Add a flow rule to a bridge",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bridge_name": map[string]interface{}{"type": "string", "description": "Bridge name"},
				"priority":    map[string]interface{}{"type": "integer", "description": "Flow priority"},
				"match":       map[string]interface{}{"type": "object", "description": "Match criteria for the flow"},
				"actions":     map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "Actions to perform on matching packets"},
			},
			"required": []string{"bridge_name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "sdn_delete_flow",
		Description: "Delete a flow rule from a bridge",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bridge_name": map[string]interface{}{"type": "string", "description": "Bridge name"},
				"flow_id":     map[string]interface{}{"type": "string", "description": "Flow ID to delete"},
			},
			"required": []string{"bridge_name", "flow_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "sdn_list_flows",
		Description: "List all flows on a bridge",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bridge_name": map[string]interface{}{"type": "string", "description": "Bridge name"},
			},
			"required": []string{"bridge_name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "sdn_flush_flows",
		Description: "Delete all flows on a bridge",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bridge_name": map[string]interface{}{"type": "string", "description": "Bridge name"},
			},
			"required": []string{"bridge_name"},
		},
	})

	// VLAN management tools
	r.addTool(ToolDefinition{
		Name:        "sdn_create_vlan",
		Description: "Create a VLAN on a bridge",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bridge_name": map[string]interface{}{"type": "string", "description": "Bridge name"},
				"vlan_id":     map[string]interface{}{"type": "integer", "description": "VLAN ID"},
				"name":        map[string]interface{}{"type": "string", "description": "VLAN name"},
			},
			"required": []string{"bridge_name", "vlan_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "sdn_delete_vlan",
		Description: "Delete a VLAN from a bridge",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bridge_name": map[string]interface{}{"type": "string", "description": "Bridge name"},
				"vlan_id":     map[string]interface{}{"type": "integer", "description": "VLAN ID"},
			},
			"required": []string{"bridge_name", "vlan_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "sdn_list_vlans",
		Description: "List all VLANs on a bridge",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bridge_name": map[string]interface{}{"type": "string", "description": "Bridge name"},
			},
			"required": []string{"bridge_name"},
		},
	})

	// Port authentication tools
	r.addTool(ToolDefinition{
		Name:        "sdn_authenticate_port",
		Description: "Authenticate a port (802.1X style)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bridge_name": map[string]interface{}{"type": "string", "description": "Bridge name"},
				"port_name":   map[string]interface{}{"type": "string", "description": "Port name"},
				"credentials": map[string]interface{}{"type": "object", "description": "Authentication credentials"},
			},
			"required": []string{"bridge_name", "port_name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "sdn_revoke_port_auth",
		Description: "Revoke port authentication",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bridge_name": map[string]interface{}{"type": "string", "description": "Bridge name"},
				"port_name":   map[string]interface{}{"type": "string", "description": "Port name"},
			},
			"required": []string{"bridge_name", "port_name"},
		},
	})

	// Statistics tools
	r.addTool(ToolDefinition{
		Name:        "sdn_get_port_stats",
		Description: "Get statistics for a port",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bridge_name": map[string]interface{}{"type": "string", "description": "Bridge name"},
				"port_name":   map[string]interface{}{"type": "string", "description": "Port name"},
			},
			"required": []string{"bridge_name", "port_name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "sdn_get_flow_stats",
		Description: "Get flow statistics for a bridge",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"bridge_name": map[string]interface{}{"type": "string", "description": "Bridge name"},
			},
			"required": []string{"bridge_name"},
		},
	})
}

// registerHealthTools registers health-related tools.
func (r *ToolRegistry) registerHealthTools() {
	r.addTool(ToolDefinition{
		Name:        "platform_health",
		Description: "Get platform health status",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "platform_liveness",
		Description: "Check if the platform is alive",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "platform_readiness",
		Description: "Check if the platform is ready to serve requests",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})
}

// registerCATools registers Certificate Authority related tools.
func (r *ToolRegistry) registerCATools() {
	r.addTool(ToolDefinition{
		Name:        "ca_info",
		Description: "Get Certificate Authority information including initialization status, common name, algorithm, and certificate details",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "ca_issue",
		Description: "Issue a new certificate from the Certificate Authority",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"common_name": map[string]interface{}{
					"type":        "string",
					"description": "Common name for the certificate subject",
				},
				"organization": map[string]interface{}{
					"type":        "string",
					"description": "Organization name for the certificate subject",
				},
				"organizational_unit": map[string]interface{}{
					"type":        "string",
					"description": "Organizational unit for the certificate subject",
				},
				"country": map[string]interface{}{
					"type":        "string",
					"description": "Country code (e.g., US) for the certificate subject",
				},
				"province": map[string]interface{}{
					"type":        "string",
					"description": "State or province for the certificate subject",
				},
				"locality": map[string]interface{}{
					"type":        "string",
					"description": "City or locality for the certificate subject",
				},
				"dns_names": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "DNS names for Subject Alternative Names (SANs)",
				},
				"ip_addresses": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "IP addresses for Subject Alternative Names (SANs)",
				},
				"email_addresses": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Email addresses for Subject Alternative Names (SANs)",
				},
				"uris": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "URIs for Subject Alternative Names (SANs)",
				},
				"valid_days": map[string]interface{}{
					"type":        "integer",
					"description": "Number of days the certificate should be valid",
					"default":     365,
				},
				"algorithm": map[string]interface{}{
					"type":        "string",
					"description": "Key algorithm (RSA, ECDSA, ED25519)",
					"default":     "ECDSA",
				},
				"store_type": map[string]interface{}{
					"type":        "string",
					"description": "Key store type (software, tpm, pkcs11)",
					"default":     "software",
				},
				"key_usage": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Key usage flags (DIGITAL_SIGNATURE, KEY_ENCIPHERMENT, etc.)",
				},
				"ext_key_usage": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Extended key usage (SERVER_AUTH, CLIENT_AUTH, CODE_SIGNING, etc.)",
				},
				"is_ca": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether this certificate is for a CA",
					"default":     false,
				},
				"max_path_len": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum path length for CA certificates",
					"default":     0,
				},
			},
			"required": []string{"common_name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "ca_get",
		Description: "Get a certificate by its serial number",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"serial": map[string]interface{}{
					"type":        "string",
					"description": "Certificate serial number (hex-encoded)",
				},
				"include_pem": map[string]interface{}{
					"type":        "boolean",
					"description": "Include PEM-encoded certificate in response",
					"default":     false,
				},
			},
			"required": []string{"serial"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "ca_list",
		Description: "List certificates issued by the Certificate Authority",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"limit": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of certificates to return",
					"default":     50,
				},
				"cursor": map[string]interface{}{
					"type":        "string",
					"description": "Pagination cursor for fetching next page",
				},
				"status": map[string]interface{}{
					"type":        "string",
					"description": "Filter by certificate status (VALID, EXPIRED, REVOKED)",
				},
			},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "ca_revoke",
		Description: "Revoke a certificate by its serial number",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"serial": map[string]interface{}{
					"type":        "string",
					"description": "Certificate serial number (hex-encoded)",
				},
				"reason": map[string]interface{}{
					"type":        "integer",
					"description": "Revocation reason code (0=unspecified, 1=keyCompromise, 2=cACompromise, 3=affiliationChanged, 4=superseded, 5=cessationOfOperation)",
					"default":     0,
				},
				"delete_keys": map[string]interface{}{
					"type":        "boolean",
					"description": "Also delete the associated private keys",
					"default":     false,
				},
			},
			"required": []string{"serial"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "ca_renew",
		Description: "Renew an existing certificate with extended validity",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"serial": map[string]interface{}{
					"type":        "string",
					"description": "Certificate serial number (hex-encoded) to renew",
				},
				"extend_days": map[string]interface{}{
					"type":        "integer",
					"description": "Number of days to extend validity from now",
					"default":     365,
				},
				"preserve_attrs": map[string]interface{}{
					"type":        "boolean",
					"description": "Preserve certificate attributes from the original certificate",
					"default":     true,
				},
			},
			"required": []string{"serial"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "ca_verify",
		Description: "Verify a certificate against the CA certificate chain",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"certificate_pem": map[string]interface{}{
					"type":        "string",
					"description": "PEM-encoded certificate to verify",
				},
				"certificate_der": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded DER certificate to verify",
				},
				"check_revoked": map[string]interface{}{
					"type":        "boolean",
					"description": "Check if certificate has been revoked",
					"default":     true,
				},
			},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "ca_crl",
		Description: "Get the Certificate Revocation List (CRL)",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "ca_bundle",
		Description: "Get the CA certificate bundle (chain of trust)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"store_type": map[string]interface{}{
					"type":        "string",
					"description": "Filter by key store type (software, tpm, pkcs11)",
				},
				"algorithm": map[string]interface{}{
					"type":        "string",
					"description": "Filter by key algorithm (RSA, ECDSA, ED25519)",
				},
			},
		},
	})
}

// addTool adds a tool definition to the registry.
func (r *ToolRegistry) addTool(tool ToolDefinition) {
	r.tools = append(r.tools, tool)
}

// ListTools returns all registered tools.
func (r *ToolRegistry) ListTools() []ToolDefinition {
	return r.tools
}

// SetAuthorizationChecker sets the authorization checker for the registry.
func (r *ToolRegistry) SetAuthorizationChecker(checker *AuthorizationChecker) {
	r.authChecker = checker
}

// ExecuteTool executes a tool by name with the given arguments.
func (r *ToolRegistry) ExecuteTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, error) {
	r.logger.Debug("Executing tool=%s", name)

	// Add timeout to context if not present
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}

	// Route to appropriate handler
	switch name {
	// vTPM Operations
	case "vtpm_create":
		return r.executeVTPMCreate(ctx, args)
	case "vtpm_delete":
		return r.executeVTPMDelete(ctx, args)
	case "vtpm_list":
		return r.executeVTPMList(ctx, args)
	case "vtpm_start":
		return r.executeVTPMStart(ctx, args)
	case "vtpm_stop":
		return r.executeVTPMStop(ctx, args)
	case "vtpm_quote":
		return r.executeVTPMQuote(ctx, args)
	case "vtpm_seal":
		return r.executeVTPMSeal(ctx, args)
	case "vtpm_unseal":
		return r.executeVTPMUnseal(ctx, args)
	case "vtpm_extend_pcr":
		return r.executeVTPMExtendPCR(ctx, args)
	case "vtpm_read_pcr":
		return r.executeVTPMReadPCR(ctx, args)

	case "vtpm_get":
		return r.executeVTPMGet(ctx, args)
	case "vtpm_validate":
		return r.executeVTPMValidate(ctx, args)
	case "vtpm_export":
		return r.executeVTPMExport(ctx, args)
	case "vtpm_import":
		return r.executeVTPMImport(ctx, args)
	case "vtpm_template_create":
		return r.executeVTPMTemplateCreate(ctx, args)
	case "vtpm_template_get":
		return r.executeVTPMTemplateGet(ctx, args)
	case "vtpm_template_delete":
		return r.executeVTPMTemplateDelete(ctx, args)
	case "vtpm_template_list":
		return r.executeVTPMTemplateList(ctx, args)
	case "vtpm_template_clone":
		return r.executeVTPMTemplateClone(ctx, args)
	case "vtpm_get_bundle_path":
		return r.executeVTPMGetBundlePath(ctx, args)
	case "vtpm_get_tpm_socket_path":
		return r.executeVTPMGetTPMSocketPath(ctx, args)
	case "vtpm_get_nvram_path":
		return r.executeVTPMGetNVRAMPath(ctx, args)
	case "vtpm_is_running":
		return r.executeVTPMIsRunning(ctx, args)

	// DNS Operations
	case "dns_add_record":
		return r.executeDNSAddRecord(ctx, args)
	case "dns_delete_record":
		return r.executeDNSDeleteRecord(ctx, args)
	case "dns_get_record":
		return r.executeDNSGetRecord(ctx, args)
	case "dns_list_records":
		return r.executeDNSListRecords(ctx, args)
	case "dns_resolve":
		return r.executeDNSResolve(ctx, args)
	case "dns_create_zone":
		return r.executeDNSCreateZone(ctx, args)
	case "dns_delete_zone":
		return r.executeDNSDeleteZone(ctx, args)
	case "dns_list_zones":
		return r.executeDNSListZones(ctx, args)

	// Device Operations
	case "device_register":
		return r.executeDeviceRegister(ctx, args)
	case "device_get":
		return r.executeDeviceGet(ctx, args)
	case "device_list":
		return r.executeDeviceList(ctx, args)
	case "device_delete":
		return r.executeDeviceDelete(ctx, args)
	case "device_update":
		return r.executeDeviceUpdate(ctx, args)
	case "device_attest":
		return r.executeDeviceAttest(ctx, args)
	case "device_record_attest_cert":
		return r.executeDeviceRecordAttestCert(ctx, args)
	case "device_provision":
		return r.executeDeviceProvision(ctx, args)

	// SDN Operations
	case "sdn_get_port_state":
		return r.executeSDNGetPortState(ctx, args)
	case "sdn_set_port_state":
		return r.executeSDNSetPortState(ctx, args)
	case "sdn_list_bridges":
		return r.executeSDNListBridges(ctx, args)
	case "sdn_create_bridge":
		return r.executeSDNCreateBridge(ctx, args)
	case "sdn_delete_bridge":
		return r.executeSDNDeleteBridge(ctx, args)
	case "sdn_add_port":
		return r.executeSDNAddPort(ctx, args)
	case "sdn_delete_port":
		return r.executeSDNDeletePort(ctx, args)
	case "sdn_apply_policy":
		return r.executeSDNApplyPolicy(ctx, args)
	case "sdn_get_policy":
		return r.executeSDNGetPolicy(ctx, args)
	case "sdn_list_policies":
		return r.executeSDNListPolicies(ctx, args)
	case "sdn_add_flow":
		return r.executeSDNAddFlow(ctx, args)
	case "sdn_delete_flow":
		return r.executeSDNDeleteFlow(ctx, args)
	case "sdn_list_flows":
		return r.executeSDNListFlows(ctx, args)
	case "sdn_flush_flows":
		return r.executeSDNFlushFlows(ctx, args)
	case "sdn_create_vlan":
		return r.executeSDNCreateVLAN(ctx, args)
	case "sdn_delete_vlan":
		return r.executeSDNDeleteVLAN(ctx, args)
	case "sdn_list_vlans":
		return r.executeSDNListVLANs(ctx, args)
	case "sdn_authenticate_port":
		return r.executeSDNAuthenticatePort(ctx, args)
	case "sdn_revoke_port_auth":
		return r.executeSDNRevokePortAuth(ctx, args)
	case "sdn_get_port_stats":
		return r.executeSDNGetPortStats(ctx, args)
	case "sdn_get_flow_stats":
		return r.executeSDNGetFlowStats(ctx, args)

	// Overlay Operations
	case "overlay_status":
		return r.executeOverlayStatus(ctx, args)
	case "overlay_vtep_list":
		return r.executeOverlayVTEPList(ctx, args)
	case "overlay_vtep_get":
		return r.executeOverlayVTEPGet(ctx, args)
	case "overlay_vni_list":
		return r.executeOverlayVNIList(ctx, args)
	case "overlay_vni_create":
		return r.executeOverlayVNICreate(ctx, args)
	case "overlay_vni_delete":
		return r.executeOverlayVNIDelete(ctx, args)
	case "overlay_tunnel_list":
		return r.executeOverlayTunnelList(ctx, args)
	case "overlay_mac_list":
		return r.executeOverlayMACList(ctx, args)
	case "overlay_mac_forget":
		return r.executeOverlayMACForget(ctx, args)

	// Gateway Operations
	case "gateway_status":
		return r.executeGatewayStatus(ctx, args)
	case "gateway_snapshot":
		return r.executeGatewaySnapshot(ctx, args)
	case "gateway_snapshots":
		return r.executeGatewaySnapshots(ctx, args)
	case "gateway_admitted_vtep":
		return r.executeGatewayAdmittedVTEP(ctx, args)
	case "gateway_admitted_vteps":
		return r.executeGatewayAdmittedVTEPs(ctx, args)
	case "gateway_mode_set":
		return r.executeGatewayModeSet(ctx, args)
	case "gateway_bgp_status":
		return r.executeGatewayBGPStatus(ctx, args)
	case "gateway_bgp_peers":
		return r.executeGatewayBGPPeers(ctx, args)
	case "gateway_bgp_announce":
		return r.executeGatewayBGPAnnounce(ctx, args)
	case "gateway_bgp_withdraw":
		return r.executeGatewayBGPWithdraw(ctx, args)
	case "gateway_bgp_prefixes":
		return r.executeGatewayBGPPrefixes(ctx, args)
	case "gateway_ipam_pools":
		return r.executeGatewayIPAMPools(ctx, args)
	case "gateway_ipam_allocate":
		return r.executeGatewayIPAMAllocate(ctx, args)
	case "gateway_ipam_release":
		return r.executeGatewayIPAMRelease(ctx, args)
	case "gateway_ipam_allocations":
		return r.executeGatewayIPAMAllocations(ctx, args)
	case "gateway_ipam_pool_get":
		return r.executeGatewayIPAMPoolGet(ctx, args)
	case "gateway_ipam_pool_create":
		return r.executeGatewayIPAMPoolCreate(ctx, args)
	case "gateway_ipam_pool_update":
		return r.executeGatewayIPAMPoolUpdate(ctx, args)
	case "gateway_ipam_pool_delete":
		return r.executeGatewayIPAMPoolDelete(ctx, args)

	// Gateway Network Zone Operations
	case "gateway_zone_list":
		return r.executeGatewayZoneList(ctx, args)
	case "gateway_zone_create":
		return r.executeGatewayZoneCreate(ctx, args)
	case "gateway_zone_update":
		return r.executeGatewayZoneUpdate(ctx, args)
	case "gateway_zone_delete":
		return r.executeGatewayZoneDelete(ctx, args)

	// Health Operations
	case "platform_health":
		return r.executeHealth(ctx, args)
	case "platform_liveness":
		return r.executeLiveness(ctx, args)
	case "platform_readiness":
		return r.executeReadiness(ctx, args)

	// Daemon Management Operations
	case "platform_daemon_status":
		return r.executeDaemonStatus(ctx, args)
	case "platform_daemon_version":
		return r.executeDaemonVersion(ctx, args)
	case "platform_daemon_list_services":
		return r.executeDaemonListServices(ctx, args)
	case "platform_daemon_get_service":
		return r.executeDaemonGetService(ctx, args)
	case "platform_daemon_start_service":
		return r.executeDaemonStartService(ctx, args)
	case "platform_daemon_stop_service":
		return r.executeDaemonStopService(ctx, args)
	case "platform_daemon_restart_service":
		return r.executeDaemonRestartService(ctx, args)
	case "platform_daemon_list_protocols":
		return r.executeDaemonListProtocols(ctx, args)

	// CA Operations
	case "ca_info":
		return r.executeCAInfo(ctx, args)
	case "ca_issue":
		return r.executeCAIssue(ctx, args)
	case "ca_get":
		return r.executeCAGet(ctx, args)
	case "ca_list":
		return r.executeCAList(ctx, args)
	case "ca_revoke":
		return r.executeCARevoke(ctx, args)
	case "ca_renew":
		return r.executeCARenew(ctx, args)
	case "ca_verify":
		return r.executeCAVerify(ctx, args)
	case "ca_crl":
		return r.executeCACRL(ctx, args)
	case "ca_bundle":
		return r.executeCABundle(ctx, args)

	// IAM User Operations
	case "iam_create_user":
		return r.executeIAMCreateUser(ctx, args)
	case "iam_delete_user":
		return r.executeIAMDeleteUser(ctx, args)
	case "iam_get_user":
		return r.executeIAMGetUser(ctx, args)
	case "iam_list_users":
		return r.executeIAMListUsers(ctx, args)

	// IAM Role Operations
	case "iam_create_role":
		return r.executeIAMCreateRole(ctx, args)
	case "iam_delete_role":
		return r.executeIAMDeleteRole(ctx, args)
	case "iam_get_role":
		return r.executeIAMGetRole(ctx, args)
	case "iam_list_roles":
		return r.executeIAMListRoles(ctx, args)
	case "iam_assign_role":
		return r.executeIAMAssignRole(ctx, args)
	case "iam_revoke_role":
		return r.executeIAMRevokeRole(ctx, args)

	// IAM Authorization Operations
	case "iam_check_permission":
		return r.executeIAMCheckPermission(ctx, args)
	case "iam_authenticate":
		return r.executeIAMAuthenticate(ctx, args)

	// IAM Group Operations
	case "iam_create_group":
		return r.executeIAMCreateGroup(ctx, args)
	case "iam_delete_group":
		return r.executeIAMDeleteGroup(ctx, args)
	case "iam_get_group":
		return r.executeIAMGetGroup(ctx, args)
	case "iam_list_groups":
		return r.executeIAMListGroups(ctx, args)
	case "iam_add_group_member":
		return r.executeIAMAddGroupMember(ctx, args)
	case "iam_remove_group_member":
		return r.executeIAMRemoveGroupMember(ctx, args)

	// IAM Tenant Operations
	case "iam_create_tenant":
		return r.executeIAMCreateTenant(ctx, args)
	case "iam_delete_tenant":
		return r.executeIAMDeleteTenant(ctx, args)
	case "iam_get_tenant":
		return r.executeIAMGetTenant(ctx, args)
	case "iam_list_tenants":
		return r.executeIAMListTenants(ctx, args)

	// IAM Token Operations
	case "iam_create_token":
		return r.executeIAMCreateToken(ctx, args)
	case "iam_revoke_token":
		return r.executeIAMRevokeToken(ctx, args)
	case "iam_verify_token":
		return r.executeIAMVerifyToken(ctx, args)

	// KMS Cryptographic Operations
	case "kms_sign":
		return r.executeKMSSign(ctx, args)

	// KMS Data Key Operations (envelope encryption)
	case "kms_generate_data_key":
		return r.executeKMSGenerateDataKey(ctx, args)
	case "kms_generate_wrapped_data_key":
		return r.executeKMSGenerateWrappedDataKey(ctx, args)

	// Container Operations
	case "container_create":
		return r.executeContainerCreate(ctx, args)
	case "container_start":
		return r.executeContainerStart(ctx, args)
	case "container_stop":
		return r.executeContainerStop(ctx, args)
	case "container_remove":
		return r.executeContainerRemove(ctx, args)
	case "container_get":
		return r.executeContainerGet(ctx, args)
	case "container_list":
		return r.executeContainerList(ctx, args)
	case "container_logs":
		return r.executeContainerLogs(ctx, args)
	case "container_attest":
		return r.executeContainerAttest(ctx, args)
	case "container_exec":
		return r.executeContainerExec(ctx, args)
	case "container_metrics":
		return r.executeContainerMetrics(ctx, args)

	// IDevID Operations (IEEE 802.1AR device identity)
	case "idevid_generate":
		return r.executeIDevIDGenerate(ctx, args)
	case "idevid_info":
		return r.executeIDevIDInfo(ctx, args)
	case "idevid_delete":
		return r.executeIDevIDDelete(ctx, args)
	case "idevid_csr":
		return r.executeIDevIDCSR(ctx, args)
	case "idevid_install_cert":
		return r.executeIDevIDInstallCert(ctx, args)
	case "idevid_get_cert":
		return r.executeIDevIDGetCert(ctx, args)
	case "idevid_delete_cert":
		return r.executeIDevIDDeleteCert(ctx, args)
	case "idevid_exists":
		return r.executeIDevIDExists(ctx, args)
	case "idevid_create_ldevid":
		return r.executeLDevIDCreate(ctx, args)

	// IAK Operations (IEEE 802.1AR attestation key)
	case "iak_generate":
		return r.executeIAKGenerate(ctx, args)
	case "iak_info":
		return r.executeIAKInfo(ctx, args)
	case "iak_delete":
		return r.executeIAKDelete(ctx, args)
	case "iak_csr":
		return r.executeIAKCSR(ctx, args)
	case "iak_install_cert":
		return r.executeIAKInstallCert(ctx, args)
	case "iak_get_cert":
		return r.executeIAKGetCert(ctx, args)
	case "iak_delete_cert":
		return r.executeIAKDeleteCert(ctx, args)
	case "iak_exists":
		return r.executeIAKExists(ctx, args)

	// Device Attribute and Credential Operations
	case "device_attributes":
		return r.executeDeviceAttributes(ctx, args)
	case "activate_credential":
		return r.executeActivateCredential(ctx, args)

	// Tenant Management Operations (multi-tenancy)
	case "tenant_list":
		return r.executeTenantList(ctx, args)
	case "tenant_get":
		return r.executeTenantGet(ctx, args)
	case "tenant_get_by_name":
		return r.executeTenantGetByName(ctx, args)
	case "tenant_create":
		return r.executeTenantCreate(ctx, args)
	case "tenant_update":
		return r.executeTenantUpdate(ctx, args)
	case "tenant_delete":
		return r.executeTenantDelete(ctx, args)
	case "tenant_suspend":
		return r.executeTenantSuspend(ctx, args)
	case "tenant_resume":
		return r.executeTenantResume(ctx, args)
	case "tenant_get_quotas":
		return r.executeTenantGetQuotas(ctx, args)
	case "tenant_update_quotas":
		return r.executeTenantUpdateQuotas(ctx, args)
	case "tenant_get_usage":
		return r.executeTenantGetUsage(ctx, args)
	case "tenant_check_quota":
		return r.executeTenantCheckQuota(ctx, args)
	case "tenant_sync":
		return r.executeTenantSync(ctx, args)
	case "tenant_rotate_dek":
		return r.executeTenantRotateDEK(ctx, args)
	case "tenant_get_dek_status":
		return r.executeTenantGetDEKStatus(ctx, args)

	// Per-Tenant Barrier Operations (cryptographic barrier lifecycle)
	case "platform_tenant_barrier_init":
		return r.executeTenantBarrierInit(ctx, args)
	case "platform_tenant_barrier_unseal":
		return r.executeTenantBarrierUnseal(ctx, args)
	case "platform_tenant_barrier_seal":
		return r.executeTenantBarrierSeal(ctx, args)
	case "platform_tenant_barrier_status":
		return r.executeTenantBarrierStatus(ctx, args)

	// Physical TPM Operations
	case "platform_tpm_info":
		return r.executeTPMInfo(ctx, args)
	case "platform_tpm_provision":
		return r.executeTPMProvision(ctx, args)
	case "platform_tpm_clear":
		return r.executeTPMClear(ctx, args)
	case "platform_tpm_ek":
		return r.executeTPMGetEK(ctx, args)
	case "platform_tpm_ek_cert":
		return r.executeTPMGetEKCert(ctx, args)
	case "platform_tpm_ek_import_cert":
		return r.executeTPMImportEKCert(ctx, args)
	case "platform_tpm_make_credential":
		return r.executeTPMMakeCredential(ctx, args)
	case "platform_tpm_activate_credential":
		return r.executeTPMActivateCredential(ctx, args)
	case "platform_tpm_ek_create":
		return r.executeTPMCreateEK(ctx, args)
	case "platform_tpm_ek_delete":
		return r.executeTPMDeleteEK(ctx, args)
	case "platform_tpm_srk":
		return r.executeTPMGetSRK(ctx, args)
	case "platform_tpm_srk_create":
		return r.executeTPMCreateSRK(ctx, args)
	case "platform_tpm_srk_delete":
		return r.executeTPMDeleteSRK(ctx, args)
	case "platform_tpm_iak":
		return r.executeTPMGetIAK(ctx, args)
	case "platform_tpm_iak_create":
		return r.executeTPMCreateIAK(ctx, args)
	case "platform_tpm_iak_delete":
		return r.executeTPMDeleteIAK(ctx, args)
	case "platform_tpm_quote":
		return r.executeTPMQuote(ctx, args)
	case "platform_tpm_verify_quote":
		return r.executeTPMVerifyQuote(ctx, args)
	case "platform_tpm_pcrs":
		return r.executeTPMReadPCRs(ctx, args)
	case "platform_tpm_pcr_extend":
		return r.executeTPMExtendPCR(ctx, args)
	case "platform_tpm_eventlog":
		return r.executeTPMEventLog(ctx, args)
	case "platform_tpm_capabilities":
		return r.executeTPMCapabilities(ctx, args)
	case "platform_tpm_random":
		return r.executeTPMRandom(ctx, args)
	case "platform_tpm_seal":
		return r.executeTPMSeal(ctx, args)
	case "platform_tpm_unseal":
		return r.executeTPMUnseal(ctx, args)
	case "platform_tpm_certify":
		return r.executeTPMCertify(ctx, args)
	case "platform_tpm_nv_list":
		return r.executeTPMNVList(ctx, args)
	case "platform_tpm_nv_read":
		return r.executeTPMNVRead(ctx, args)
	case "platform_tpm_nv_write":
		return r.executeTPMNVWrite(ctx, args)
	case "platform_tpm_nv_delete":
		return r.executeTPMNVDelete(ctx, args)
	case "platform_tpm_platform":
		return r.executeTPMPlatform(ctx, args)

	// Physical Switch Management Operations
	case "switch_list_ports":
		return r.executeSwitchListPorts(ctx, args)
	case "switch_port_status":
		return r.executeSwitchPortStatus(ctx, args)
	case "switch_set_vlan":
		return r.executeSwitchSetVLAN(ctx, args)
	case "switch_enable_port":
		return r.executeSwitchEnablePort(ctx, args)
	case "switch_disable_port":
		return r.executeSwitchDisablePort(ctx, args)

	default:
		// Gateway load balancer tool dispatch (gateway_lb_*) uses a
		// map-based dispatcher for O(1) routing per project conventions.
		if result, handled, err := r.dispatchGatewayLBTool(ctx, name, args); handled {
			return result, err
		}
		// Gateway perf tool dispatch (gateway_perf_*) uses a map-based
		// dispatcher for O(1) routing per project conventions.
		if result, handled, err := r.dispatchGatewayPerfTool(ctx, name, args); handled {
			return result, err
		}
		// Gateway NAT64 tool dispatch (gateway_nat64_*) uses a map-based
		// dispatcher for O(1) routing per project conventions.
		if result, handled, err := r.dispatchGatewayNAT64Tool(ctx, name, args); handled {
			return result, err
		}
		// NTP tool dispatch (ntp_*) uses a map-based dispatcher for
		// O(1) routing per project conventions.
		if result, handled, err := r.dispatchNTPTool(ctx, name); handled {
			return result, err
		}
		// BMC tool dispatch (platform_bmc_*) uses a map-based dispatcher
		// for O(1) routing per project conventions.
		if result, handled, err := r.dispatchBMCTool(ctx, name, args); handled {
			return result, err
		}
		// Cluster tool dispatch (platform_cluster_*) uses a map-based
		// dispatcher for O(1) routing per project conventions.
		if result, handled, err := r.dispatchClusterTool(ctx, name, args); handled {
			return result, err
		}
		// Registry tool dispatch (platform_registry_*) uses a map-based
		// dispatcher for O(1) routing per project conventions.
		if result, handled, err := r.dispatchRegistryTool(ctx, name, args); handled {
			return result, err
		}
		// Invitation tool dispatch (platform_invitation_*) uses a map-based
		// dispatcher for O(1) routing per project conventions.
		if result, handled, err := r.dispatchInvitationTool(ctx, name, args); handled {
			return result, err
		}
		// EAB tool dispatch (platform_eab_*) uses a map-based dispatcher
		// for O(1) routing per project conventions.
		if result, handled, err := r.dispatchEABTool(ctx, name, args); handled {
			return result, err
		}
		// Phase 3.5 tool dispatch (ceremony/piv/luks/fido2) uses a map-based
		// dispatcher for O(1) routing per project conventions.
		if result, handled, err := r.dispatchPhase35Tool(ctx, name, args); handled {
			return result, err
		}
		// KMS and secrets tool dispatch (kms_* / secret_*) uses a map-based
		// dispatcher for O(1) routing per project conventions.
		if result, handled, err := r.dispatchKMSTool(ctx, name, args); handled {
			return result, err
		}
		// Config delivery provisioning tool dispatch (provision_*) uses a
		// map-based dispatcher for O(1) routing per project conventions.
		if result, handled, err := r.dispatchProvisionTool(ctx, name, args); handled {
			return result, err
		}
		// Reverse-proxy configuration tool dispatch (proxy_*) uses a
		// map-based dispatcher for O(1) routing per project conventions.
		if result, handled, err := r.dispatchProxyTool(ctx, name, args); handled {
			return result, err
		}
		// Device profile CRUD tool dispatch (profile_*) uses a map-based
		// dispatcher for O(1) routing per project conventions.
		if result, handled, err := r.dispatchAttestationReportTool(ctx, name, args); handled {
			return result, err
		}
		if result, handled, err := r.dispatchDeviceProfileTool(ctx, name, args); handled {
			return result, err
		}
		// VM snapshot/attestation tool dispatch (vm_snapshot_* /
		// vm_attest*) uses a map-based dispatcher for O(1) routing per
		// project conventions.
		// Operational VM tool dispatch (vm_metrics / vm_disk_* / vm_logs /
		// vm_migrate) uses a map-based dispatcher for O(1) routing.
		if result, handled, err := r.dispatchVMOpsTool(ctx, name, args); handled {
			return result, err
		}
		if result, handled, err := r.dispatchVMTool(ctx, name, args); handled {
			return result, err
		}
		return nil, &MessageError{Msg: fmt.Sprintf("unknown tool: %s", name)}
	}
}

// Helper functions

func getString(args map[string]interface{}, key string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

func getInt(args map[string]interface{}, key string) int {
	return int(getInt64(args, key))
}

// getInt64 extracts an integer argument. In addition to the JSON number
// types, decimal strings are accepted per the repo-wide
// uint64-on-the-wire convention (JSON numbers lose precision past 2^53,
// so clients send large IDs as strings).
func getInt64(args map[string]interface{}, key string) int64 {
	switch v := args[key].(type) {
	case float64:
		return int64(v)
	case int:
		return int64(v)
	case int64:
		return v
	case uint64:
		return int64(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return n
		}
	case string:
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
		// Large uint64 IDs above MaxInt64 still round-trip through the
		// unsigned parser.
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return int64(n)
		}
	}
	return 0
}

func getIntSlice(args map[string]interface{}, key string) []int {
	if v, ok := args[key].([]interface{}); ok {
		result := make([]int, len(v))
		for i, item := range v {
			switch n := item.(type) {
			case float64:
				result[i] = int(n)
			case int:
				result[i] = n
			case int64:
				result[i] = int(n)
			}
		}
		return result
	}
	return nil
}

func getStringSlice(args map[string]interface{}, key string) []string {
	if v, ok := args[key].([]interface{}); ok {
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

func getBool(args map[string]interface{}, key string) bool {
	if v, ok := args[key].(bool); ok {
		return v
	}
	return false
}

func getMap(args map[string]interface{}, key string) map[string]interface{} {
	if v, ok := args[key].(map[string]interface{}); ok {
		return v
	}
	return nil
}

func getStringMap(args map[string]interface{}, key string) map[string]string {
	if v, ok := args[key].(map[string]interface{}); ok {
		result := make(map[string]string)
		for k, val := range v {
			if s, ok := val.(string); ok {
				result[k] = s
			}
		}
		return result
	}
	return nil
}

func marshalResult(v interface{}) (interface{}, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var result interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// =============================================================================
// KMS Tools
// =============================================================================

// registerKMSTools registers Key Management Service related tools.
func (r *ToolRegistry) registerKMSTools() {
	// Register comprehensive KMS key management tools
	r.registerKMSKeyManagementTools()

	// Register KMS key lifecycle tools (revoke, metadata, policy,
	// algorithms, backend status)
	r.registerKMSLifecycleTools()

	// Register secrets management tools
	r.registerSecretsTools()

	// Register cryptographic operation tools
	r.registerKMSCryptoTools()

	// Register random byte generation tool
	r.registerKMSRandomTools()

	// Register data key tools (envelope encryption)
	r.registerKMSDataKeyTools()
}
