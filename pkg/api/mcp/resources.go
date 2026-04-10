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
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// ResourceRegistry manages MCP resources and their retrieval.
type ResourceRegistry struct {
	service   ServiceProvider
	logger    *logging.Logger
	resources []ResourceDefinition
}

// NewResourceRegistry creates a new resource registry.
func NewResourceRegistry(svc ServiceProvider, log *logging.Logger) *ResourceRegistry {
	r := &ResourceRegistry{
		service:   svc,
		logger:    log,
		resources: make([]ResourceDefinition, 0, 20),
	}

	// Register all resources
	r.registerResources()

	return r
}

// registerResources registers all available platform resources.
func (r *ResourceRegistry) registerResources() {
	// vTPM resources
	r.addResource(ResourceDefinition{
		URI:         "platform://vtpm/list",
		Name:        "vTPM Instances",
		Description: "List of all virtual TPM instances",
		MimeType:    "application/json",
	})

	r.addResource(ResourceDefinition{
		URI:         "platform://vtpm/{name}",
		Name:        "vTPM Instance",
		Description: "Details of a specific vTPM instance",
		MimeType:    "application/json",
	})

	// DNS resources
	r.addResource(ResourceDefinition{
		URI:         "platform://dns/zones",
		Name:        "DNS Zones",
		Description: "List of all DNS zones",
		MimeType:    "application/json",
	})

	r.addResource(ResourceDefinition{
		URI:         "platform://dns/zone/{zone}",
		Name:        "DNS Zone Records",
		Description: "Records in a specific DNS zone",
		MimeType:    "application/json",
	})

	// Device resources
	r.addResource(ResourceDefinition{
		URI:         "platform://device/list",
		Name:        "Device List",
		Description: "List of all registered devices",
		MimeType:    "application/json",
	})

	r.addResource(ResourceDefinition{
		URI:         "platform://device/{id}",
		Name:        "Device Details",
		Description: "Details of a specific device",
		MimeType:    "application/json",
	})

	// SDN resources
	r.addResource(ResourceDefinition{
		URI:         "platform://sdn/bridges",
		Name:        "OVS Bridges",
		Description: "List of all OVS bridges",
		MimeType:    "application/json",
	})

	r.addResource(ResourceDefinition{
		URI:         "platform://sdn/policies",
		Name:        "Network Policies",
		Description: "List of all network policies",
		MimeType:    "application/json",
	})

	// Platform resources
	r.addResource(ResourceDefinition{
		URI:         "platform://health",
		Name:        "Platform Health",
		Description: "Platform health status",
		MimeType:    "application/json",
	})

	r.addResource(ResourceDefinition{
		URI:         "platform://status",
		Name:        "Platform Status",
		Description: "Comprehensive platform status including all services",
		MimeType:    "application/json",
	})
}

// addResource adds a resource definition to the registry.
func (r *ResourceRegistry) addResource(resource ResourceDefinition) {
	r.resources = append(r.resources, resource)
}

// ListResources returns all registered resources.
func (r *ResourceRegistry) ListResources() []ResourceDefinition {
	return r.resources
}

// ReadResource reads a resource by URI and returns its content.
func (r *ResourceRegistry) ReadResource(ctx context.Context, uri string) (interface{}, error) {
	r.logger.Debug("Reading resource uri=%s", uri)

	// Parse URI and route to appropriate handler
	if !strings.HasPrefix(uri, "platform://") {
		return nil, fmt.Errorf("invalid resource URI: %s", uri)
	}

	path := strings.TrimPrefix(uri, "platform://")
	parts := strings.Split(path, "/")

	if len(parts) == 0 {
		return nil, fmt.Errorf("invalid resource path: %s", path)
	}

	switch parts[0] {
	case "vtpm":
		return r.readVTPMResource(ctx, parts[1:])
	case "dns":
		return r.readDNSResource(ctx, parts[1:])
	case "device":
		return r.readDeviceResource(ctx, parts[1:])
	case "sdn":
		return r.readSDNResource(ctx, parts[1:])
	case "health":
		return r.readHealthResource(ctx)
	case "status":
		return r.readStatusResource(ctx)
	default:
		return nil, fmt.Errorf("unknown resource type: %s", parts[0])
	}
}

func (r *ResourceRegistry) readVTPMResource(ctx context.Context, parts []string) (interface{}, error) {
	if len(parts) == 0 || parts[0] == "list" {
		// List all vTPM instances
		instances, err := r.service.VTPMList(ctx)
		if err != nil {
			return nil, err
		}
		return r.formatResourceContent(instances)
	}

	// Get specific vTPM - not directly available through ServiceProvider
	// Return metadata about the vTPM
	return map[string]interface{}{
		"name":   parts[0],
		"status": "query individual vTPM not implemented",
	}, nil
}

func (r *ResourceRegistry) readDNSResource(ctx context.Context, parts []string) (interface{}, error) {
	if len(parts) == 0 || parts[0] == "zones" {
		// List all zones
		zones, err := r.service.DNSListZones(ctx)
		if err != nil {
			return nil, err
		}
		return r.formatResourceContent(zones)
	}

	if parts[0] == "zone" && len(parts) > 1 {
		// List records in zone
		records, err := r.service.DNSListRecords(ctx, parts[1])
		if err != nil {
			return nil, err
		}
		return r.formatResourceContent(records)
	}

	return nil, fmt.Errorf("invalid DNS resource path")
}

func (r *ResourceRegistry) readDeviceResource(ctx context.Context, parts []string) (interface{}, error) {
	if len(parts) == 0 || parts[0] == "list" {
		// List all devices
		devices, err := r.service.DeviceList(ctx, nil)
		if err != nil {
			return nil, err
		}
		return r.formatResourceContent(devices)
	}

	// Get specific device
	device, err := r.service.DeviceGet(ctx, parts[0])
	if err != nil {
		return nil, err
	}
	return r.formatResourceContent(device)
}

func (r *ResourceRegistry) readSDNResource(ctx context.Context, parts []string) (interface{}, error) {
	if len(parts) == 0 || parts[0] == "bridges" {
		// List all bridges
		bridges, err := r.service.SDNListBridges(ctx)
		if err != nil {
			return nil, err
		}
		return r.formatResourceContent(bridges)
	}

	if parts[0] == "policies" {
		// List all policies
		policies, err := r.service.SDNListPolicies(ctx)
		if err != nil {
			return nil, err
		}
		return r.formatResourceContent(policies)
	}

	return nil, fmt.Errorf("invalid SDN resource path")
}

func (r *ResourceRegistry) readHealthResource(ctx context.Context) (interface{}, error) {
	health, err := r.service.Health(ctx)
	if err != nil {
		return nil, err
	}
	return r.formatResourceContent(health)
}

func (r *ResourceRegistry) readStatusResource(ctx context.Context) (interface{}, error) {
	// Gather comprehensive status from all services
	status := make(map[string]interface{})

	// Get health
	if health, err := r.service.Health(ctx); err == nil {
		status["health"] = health
	}

	// Get vTPM instances count
	if vtpms, err := r.service.VTPMList(ctx); err == nil {
		status["vtpm_count"] = len(vtpms)
	}

	// Get device count
	if devices, err := r.service.DeviceList(ctx, nil); err == nil {
		status["device_count"] = len(devices)
	}

	// Get DNS zones count
	if zones, err := r.service.DNSListZones(ctx); err == nil {
		status["dns_zones_count"] = len(zones)
	}

	// Get SDN bridges count
	if bridges, err := r.service.SDNListBridges(ctx); err == nil {
		status["sdn_bridges_count"] = len(bridges)
	}

	return r.formatResourceContent(status)
}

// formatResourceContent formats resource content for MCP response.
func (r *ResourceRegistry) formatResourceContent(data interface{}) (interface{}, error) {
	// Convert to JSON for consistent formatting
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"uri":      "platform://resource",
				"mimeType": "application/json",
				"text":     string(jsonData),
			},
		},
	}, nil
}
