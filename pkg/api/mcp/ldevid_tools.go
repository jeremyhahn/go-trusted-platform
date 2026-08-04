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

import "context"

// =============================================================================
// LDevID (IEEE 802.1AR) Request Types
// =============================================================================

// LDevIDCSRTemplateMCP carries the subject and SAN fields for an LDevID
// certificate request over MCP. It mirrors the pb CSRTemplate message but is
// kept pb-free so the mcp package stays transport-agnostic; the daemon
// service provider converts it to the pb type.
type LDevIDCSRTemplateMCP struct {
	CommonName         string   `json:"common_name,omitempty"`
	Organization       string   `json:"organization,omitempty"`
	OrganizationalUnit string   `json:"organizational_unit,omitempty"`
	Country            string   `json:"country,omitempty"`
	Province           string   `json:"province,omitempty"`
	Locality           string   `json:"locality,omitempty"`
	DNSNames           []string `json:"dns_names,omitempty"`
	EmailAddresses     []string `json:"email_addresses,omitempty"`
}

// CreateLDevIDMCPRequest represents an LDevID create request for MCP. Field
// names mirror the pb CreateLDevIDRequest so the SDK MCP adapter's
// structToMap round-trip lands the same keys the tool reads.
type CreateLDevIDMCPRequest struct {
	Template     *LDevIDCSRTemplateMCP `json:"template,omitempty"`
	Algorithm    string                `json:"algorithm,omitempty"`
	Handle       uint32                `json:"handle,omitempty"`
	Profile      string                `json:"profile,omitempty"`
	ValidityDays uint32                `json:"validity_days,omitempty"`
	Overwrite    bool                  `json:"overwrite,omitempty"`
}

// LDevIDCreator is the capability a ServiceProvider implements to support
// LDevID (IEEE 802.1AR) issuance. It is declared here (rather than embedded
// in the core ServiceProvider interface) so the idevid_create_ldevid tool
// stays self-contained; the daemon MCPServiceProvider satisfies it, so the
// tool is fully wired in production — the not-supported branch below is a
// defensive guard, never a shipped stub.
type LDevIDCreator interface {
	CreateLDevID(ctx context.Context, req *CreateLDevIDMCPRequest) (interface{}, error)
}

// ErrLDevIDNotSupported indicates the configured service provider does not
// implement LDevID issuance.
var ErrLDevIDNotSupported = &IDevIDError{
	Code:    "LDEVID_NOT_SUPPORTED",
	Message: "LDevID issuance is not supported by the configured service provider",
}

// =============================================================================
// LDevID Tool Registration
// =============================================================================

// registerLDevIDTools registers the LDevID (IEEE 802.1AR) MCP tool. LDevID is
// a locally significant, CA-issued operational identity layered on top of the
// permanent IDevID birth identity; issuance is refused unless the device has
// a proven IDevID.
func (r *ToolRegistry) registerLDevIDTools() {
	r.addTool(ToolDefinition{
		Name: "idevid_create_ldevid",
		Description: "Provision an LDevID (Local Device Identifier, IEEE 802.1AR): " +
			"create a TPM-resident LDevID signing key distinct from the IDevID/IAK " +
			"birth keys, build a PKCS#10 CSR, and have the platform CA issue the " +
			"certificate. Requires a proven, currently-valid IDevID.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"template": map[string]interface{}{
					"type":        "object",
					"description": "Subject and SAN fields for the LDevID certificate",
					"properties": map[string]interface{}{
						"common_name":         map[string]interface{}{"type": "string"},
						"organization":        map[string]interface{}{"type": "string"},
						"organizational_unit": map[string]interface{}{"type": "string"},
						"country":             map[string]interface{}{"type": "string"},
						"province":            map[string]interface{}{"type": "string"},
						"locality":            map[string]interface{}{"type": "string"},
						"dns_names": map[string]interface{}{
							"type":  "array",
							"items": map[string]interface{}{"type": "string"},
						},
						"email_addresses": map[string]interface{}{
							"type":  "array",
							"items": map[string]interface{}{"type": "string"},
						},
					},
				},
				"algorithm": map[string]interface{}{
					"type":        "string",
					"description": "LDevID key algorithm (default: ECDSA-P256)",
					"enum":        []string{"ECDSA-P256", "ECDSA-P384", "RSA-2048", "RSA-3072"},
					"default":     "ECDSA-P256",
				},
				"handle": map[string]interface{}{
					"type":        "integer",
					"description": "Persistent TPM handle for the LDevID key (default: 0x81010102)",
				},
				"profile": map[string]interface{}{
					"type":        "string",
					"description": "Platform CA certificate profile used for issuance",
				},
				"validity_days": map[string]interface{}{
					"type":        "integer",
					"description": "Issued certificate validity period in days (0 = CA/profile default)",
				},
				"overwrite": map[string]interface{}{
					"type":        "boolean",
					"description": "Overwrite an existing LDevID key at the handle",
					"default":     false,
				},
			},
		},
	})
}

// =============================================================================
// LDevID Tool Execution Handler
// =============================================================================

// executeLDevIDCreate provisions an LDevID by delegating to the service
// provider, which in turn delegates to the shared IDevIDGRPCService.
func (r *ToolRegistry) executeLDevIDCreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	creator, ok := r.service.(LDevIDCreator)
	if !ok {
		return nil, ErrLDevIDNotSupported
	}

	req := &CreateLDevIDMCPRequest{
		Algorithm:    getString(args, "algorithm"),
		Handle:       uint32(getInt(args, "handle")),
		Profile:      getString(args, "profile"),
		ValidityDays: uint32(getInt(args, "validity_days")),
		Overwrite:    getBool(args, "overwrite"),
	}

	if tmplArgs := getMap(args, "template"); tmplArgs != nil {
		req.Template = &LDevIDCSRTemplateMCP{
			CommonName:         getString(tmplArgs, "common_name"),
			Organization:       getString(tmplArgs, "organization"),
			OrganizationalUnit: getString(tmplArgs, "organizational_unit"),
			Country:            getString(tmplArgs, "country"),
			Province:           getString(tmplArgs, "province"),
			Locality:           getString(tmplArgs, "locality"),
			DNSNames:           getStringSlice(tmplArgs, "dns_names"),
			EmailAddresses:     getStringSlice(tmplArgs, "email_addresses"),
		}
	}

	result, err := creator.CreateLDevID(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}
