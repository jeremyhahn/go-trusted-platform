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
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// =============================================================================
// DNS Error Types
// =============================================================================

// DNSError represents a DNS operation error.
type DNSError struct {
	Code    string
	Message string
}

func (e *DNSError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// DNS error sentinel values.
var (
	// ErrDNSServiceUnavailable indicates the DNS service is not available.
	ErrDNSServiceUnavailable = &DNSError{
		Code:    "DNS_SERVICE_UNAVAILABLE",
		Message: "dns service is not available",
	}

	// ErrDNSZoneNameRequired indicates a zone name is required.
	ErrDNSZoneNameRequired = &DNSError{
		Code:    "DNS_ZONE_NAME_REQUIRED",
		Message: "zone name is required",
	}

	// ErrDNSRecordTypeRequired indicates a record type is required.
	ErrDNSRecordTypeRequired = &DNSError{
		Code:    "DNS_RECORD_TYPE_REQUIRED",
		Message: "record type is required",
	}

	// ErrDNSRecordNameRequired indicates a record name is required.
	ErrDNSRecordNameRequired = &DNSError{
		Code:    "DNS_RECORD_NAME_REQUIRED",
		Message: "record name is required",
	}

	// ErrDNSRecordIDRequired indicates a record ID is required.
	ErrDNSRecordIDRequired = &DNSError{
		Code:    "DNS_RECORD_ID_REQUIRED",
		Message: "record ID is required",
	}

	// ErrDNSFQDNRequired indicates an FQDN is required.
	ErrDNSFQDNRequired = &DNSError{
		Code:    "DNS_FQDN_REQUIRED",
		Message: "fqdn is required",
	}

	// ErrDNSIPRequired indicates an IP address is required.
	ErrDNSIPRequired = &DNSError{
		Code:    "DNS_IP_REQUIRED",
		Message: "ip address is required",
	}

	// ErrDNSInvalidRecordType indicates an invalid record type was specified.
	ErrDNSInvalidRecordType = &DNSError{
		Code:    "DNS_INVALID_RECORD_TYPE",
		Message: "invalid record type",
	}
)

// =============================================================================
// DNS Tool Registration
// =============================================================================

// registerDNSExtendedTools registers extended DNS tools for zone and record management.
// This supplements the basic DNS tools with full CRUD operations matching REST handlers.
func (r *ToolRegistry) registerDNSExtendedTools() {
	// Zone operations
	r.addTool(mcpwire.ToolDefinition{
		Name:        "dns_zone_create",
		Description: "Create a new DNS zone with optional SOA and NS records",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Zone name (e.g., example.com.)",
				},
				"ttl": map[string]interface{}{
					"type":        "integer",
					"description": "Default TTL for records in the zone (seconds)",
					"default":     3600,
				},
				"description": map[string]interface{}{
					"type":        "string",
					"description": "Zone description",
				},
				"internal": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether this is an internal zone",
					"default":     false,
				},
				"soa": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"mname":       map[string]interface{}{"type": "string", "description": "Primary nameserver FQDN"},
						"rname":       map[string]interface{}{"type": "string", "description": "Hostmaster email (with . instead of @)"},
						"serial":      map[string]interface{}{"type": "integer", "description": "Zone serial number"},
						"refresh":     map[string]interface{}{"type": "integer", "description": "Refresh interval (seconds)"},
						"retry":       map[string]interface{}{"type": "integer", "description": "Retry interval (seconds)"},
						"expire":      map[string]interface{}{"type": "integer", "description": "Expire time (seconds)"},
						"minimum_ttl": map[string]interface{}{"type": "integer", "description": "Minimum TTL (seconds)"},
						"ttl":         map[string]interface{}{"type": "integer", "description": "SOA record TTL (seconds)"},
					},
					"description": "SOA record configuration",
				},
				"ns_records": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"name":  map[string]interface{}{"type": "string", "description": "NS record name"},
							"value": map[string]interface{}{"type": "string", "description": "Nameserver FQDN"},
							"ttl":   map[string]interface{}{"type": "integer", "description": "Record TTL"},
						},
						"required": []string{"name", "value"},
					},
					"description": "NS records to create with the zone",
				},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "dns_zone_get",
		Description: "Get detailed information about a DNS zone including all records",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Zone name",
				},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "dns_zone_list",
		Description: "List all DNS zones",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "dns_zone_update",
		Description: "Update DNS zone properties",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Zone name",
				},
				"ttl": map[string]interface{}{
					"type":        "integer",
					"description": "New default TTL for the zone",
				},
				"description": map[string]interface{}{
					"type":        "string",
					"description": "New zone description",
				},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "dns_zone_delete",
		Description: "Delete a DNS zone and all its records",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Zone name to delete",
				},
			},
			"required": []string{"name"},
		},
	})

	// Record operations
	r.addTool(mcpwire.ToolDefinition{
		Name:        "dns_record_create",
		Description: "Create a DNS record in a zone (A, AAAA, CNAME, MX, NS, TXT, SRV, CAA, TLSA)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"zone": map[string]interface{}{
					"type":        "string",
					"description": "Zone name to add the record to",
				},
				"type": map[string]interface{}{
					"type":        "string",
					"description": "Record type (A, AAAA, CNAME, MX, NS, TXT, SRV, CAA, TLSA)",
					"enum":        []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "CAA", "TLSA"},
				},
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Record name (hostname or subdomain)",
				},
				"value": map[string]interface{}{
					"type":        "string",
					"description": "Record value (IP for A/AAAA, FQDN for CNAME/NS/MX, text for TXT)",
				},
				"ttl": map[string]interface{}{
					"type":        "integer",
					"description": "Record TTL in seconds",
					"default":     3600,
				},
				"priority": map[string]interface{}{
					"type":        "integer",
					"description": "Priority for MX/SRV records",
				},
				"weight": map[string]interface{}{
					"type":        "integer",
					"description": "Weight for SRV records",
				},
				"port": map[string]interface{}{
					"type":        "integer",
					"description": "Port for SRV records",
				},
				"target": map[string]interface{}{
					"type":        "string",
					"description": "Target for SRV records",
				},
				"flags": map[string]interface{}{
					"type":        "integer",
					"description": "Flags for CAA records (0 or 128)",
				},
				"tag": map[string]interface{}{
					"type":        "string",
					"description": "Tag for CAA records (issue, issuewild, iodef)",
				},
				"usage": map[string]interface{}{
					"type":        "integer",
					"description": "Usage for TLSA records (0-3)",
				},
				"selector": map[string]interface{}{
					"type":        "integer",
					"description": "Selector for TLSA records (0-1)",
				},
				"matching_type": map[string]interface{}{
					"type":        "integer",
					"description": "Matching type for TLSA records (0-2)",
				},
				"data": map[string]interface{}{
					"type":        "string",
					"description": "Certificate data for TLSA records",
				},
			},
			"required": []string{"zone", "type", "name"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "dns_record_get",
		Description: "Get a specific DNS record by ID and type",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"zone": map[string]interface{}{
					"type":        "string",
					"description": "Zone name",
				},
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Record ID (typically the record name)",
				},
				"type": map[string]interface{}{
					"type":        "string",
					"description": "Record type",
				},
			},
			"required": []string{"zone", "id", "type"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "dns_record_list",
		Description: "List DNS records in a zone with optional type filter",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"zone": map[string]interface{}{
					"type":        "string",
					"description": "Zone name",
				},
				"type": map[string]interface{}{
					"type":        "string",
					"description": "Filter by record type (optional)",
				},
			},
			"required": []string{"zone"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "dns_record_update",
		Description: "Update a DNS record",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"zone": map[string]interface{}{
					"type":        "string",
					"description": "Zone name",
				},
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Record ID to update",
				},
				"type": map[string]interface{}{
					"type":        "string",
					"description": "Record type",
				},
				"value": map[string]interface{}{
					"type":        "string",
					"description": "New record value",
				},
				"ttl": map[string]interface{}{
					"type":        "integer",
					"description": "New TTL",
				},
				"priority": map[string]interface{}{
					"type":        "integer",
					"description": "New priority for MX/SRV records",
				},
				"weight": map[string]interface{}{
					"type":        "integer",
					"description": "New weight for SRV records",
				},
				"port": map[string]interface{}{
					"type":        "integer",
					"description": "New port for SRV records",
				},
				"target": map[string]interface{}{
					"type":        "string",
					"description": "New target for SRV records",
				},
			},
			"required": []string{"zone", "id", "type"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "dns_record_delete",
		Description: "Delete a DNS record from a zone",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"zone": map[string]interface{}{
					"type":        "string",
					"description": "Zone name",
				},
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Record ID to delete",
				},
				"type": map[string]interface{}{
					"type":        "string",
					"description": "Record type",
				},
			},
			"required": []string{"zone", "id", "type"},
		},
	})

	// Lookup operations
	r.addTool(mcpwire.ToolDefinition{
		Name:        "dns_lookup",
		Description: "Perform a DNS lookup for a fully qualified domain name",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"fqdn": map[string]interface{}{
					"type":        "string",
					"description": "Fully qualified domain name to look up",
				},
				"type": map[string]interface{}{
					"type":        "string",
					"description": "Record type to query (default: A)",
					"default":     "A",
				},
			},
			"required": []string{"fqdn"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "dns_reverse_lookup",
		Description: "Perform a reverse DNS lookup (PTR) for an IP address",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"ip": map[string]interface{}{
					"type":        "string",
					"description": "IP address to look up",
				},
			},
			"required": []string{"ip"},
		},
	})
}
