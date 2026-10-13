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
	"encoding/base64"
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"google.golang.org/grpc/status"
)

// =============================================================================
// IDevID/IAK Error Types
// =============================================================================

// IDevIDError represents an IDevID/IAK operation error.
type IDevIDError struct {
	Code    string
	Message string
}

func (e *IDevIDError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// GRPCStatus classifies the error by its Code (codeClass), so the MCP
// server answers it with the matching JSON-RPC code.
func (e *IDevIDError) GRPCStatus() *status.Status {
	return codeStatus(e.Code, e.Error())
}

// IDevID/IAK error instances.
var (
	// ErrIDevIDServiceUnavailable indicates the IDevID service is not available.
	ErrIDevIDServiceUnavailable = &IDevIDError{
		Code:    "IDEVID_SERVICE_UNAVAILABLE",
		Message: "IDevID service is not available",
	}

	// ErrIDevIDNotFound indicates the IDevID key was not found.
	ErrIDevIDNotFound = &IDevIDError{
		Code:    "IDEVID_NOT_FOUND",
		Message: "IDevID key not found",
	}

	// ErrIAKNotFound indicates the IAK key was not found.
	ErrIAKNotFound = &IDevIDError{
		Code:    "IAK_NOT_FOUND",
		Message: "IAK key not found",
	}

	// ErrIDevIDCertificateNotFound indicates the IDevID certificate was not found.
	ErrIDevIDCertificateNotFound = &IDevIDError{
		Code:    "IDEVID_CERTIFICATE_NOT_FOUND",
		Message: "IDevID certificate not found",
	}

	// ErrIAKCertificateNotFound indicates the IAK certificate was not found.
	ErrIAKCertificateNotFound = &IDevIDError{
		Code:    "IAK_CERTIFICATE_NOT_FOUND",
		Message: "IAK certificate not found",
	}

	// ErrIDevIDCertificatePEMRequired indicates a certificate PEM is required.
	ErrIDevIDCertificatePEMRequired = &IDevIDError{
		Code:    "IDEVID_CERTIFICATE_PEM_REQUIRED",
		Message: "certificate_pem is required",
	}

	// ErrIDevIDInvalidCertificatePEM indicates an invalid certificate PEM was provided.
	ErrIDevIDInvalidCertificatePEM = &IDevIDError{
		Code:    "IDEVID_INVALID_CERTIFICATE_PEM",
		Message: "invalid certificate PEM encoding",
	}

	// ErrIDevIDCredentialBlobRequired indicates a credential blob is required.
	ErrIDevIDCredentialBlobRequired = &IDevIDError{
		Code:    "IDEVID_CREDENTIAL_BLOB_REQUIRED",
		Message: "credential_blob is required",
	}

	// ErrIDevIDSecretRequired indicates a secret is required.
	ErrIDevIDSecretRequired = &IDevIDError{
		Code:    "IDEVID_SECRET_REQUIRED",
		Message: "secret is required",
	}

	// ErrIDevIDInvalidBase64 indicates invalid base64 encoding.
	ErrIDevIDInvalidBase64 = &IDevIDError{
		Code:    "IDEVID_INVALID_BASE64",
		Message: "invalid base64 encoding",
	}
)

// =============================================================================
// IDevID/IAK Request Types
// =============================================================================

// IDevIDGenerateMCPRequest represents an IDevID key generation request for MCP.
type IDevIDGenerateMCPRequest struct {
	Algorithm string `json:"algorithm,omitempty"`
	Overwrite bool   `json:"overwrite,omitempty"`
}

// IDevIDCSRMCPRequest represents an IDevID CSR generation request for MCP.
type IDevIDCSRMCPRequest struct {
	CommonName         string   `json:"common_name,omitempty"`
	Organization       string   `json:"organization,omitempty"`
	OrganizationalUnit string   `json:"organizational_unit,omitempty"`
	Country            string   `json:"country,omitempty"`
	Province           string   `json:"province,omitempty"`
	Locality           string   `json:"locality,omitempty"`
	DNSNames           []string `json:"dns_names,omitempty"`
	EmailAddresses     []string `json:"email_addresses,omitempty"`
	IncludeTCGAttrs    bool     `json:"include_tcg_attrs,omitempty"`
}

// IDevIDInstallCertMCPRequest represents a certificate installation request for MCP.
type IDevIDInstallCertMCPRequest struct {
	CertificatePEM string `json:"certificate_pem"`
}

// ActivateCredentialMCPRequest represents an activate credential request for MCP.
type ActivateCredentialMCPRequest struct {
	CredentialBlob string `json:"credential_blob"`
	Secret         string `json:"secret" secret:"true"`
}

// =============================================================================
// IDevID/IAK Tool Registration
// =============================================================================

// registerIDevIDTools registers IDevID/IAK-related MCP tools.
func (r *ToolRegistry) registerIDevIDTools() {
	// IDevID operations
	r.addTool(mcpwire.ToolDefinition{
		Name:        "idevid_generate",
		Description: "Generate an IDevID (Initial Device Identifier) key in the TPM. IDevID is a long-term device identity key per IEEE 802.1AR.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"algorithm": map[string]interface{}{
					"type":        "string",
					"description": "Key algorithm (RSA or ECC, default: ECC)",
					"enum":        []string{"RSA", "ECC"},
					"default":     "ECC",
				},
				"overwrite": map[string]interface{}{
					"type":        "boolean",
					"description": "Overwrite existing IDevID key if present",
					"default":     false,
				},
			},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "idevid_info",
		Description: "Get information about the IDevID key including handle, algorithm, and certificate if installed",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "idevid_delete",
		Description: "Delete the IDevID key and associated certificate from the TPM",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "idevid_csr",
		Description: "Generate a Certificate Signing Request (CSR) for the IDevID key using TCG format",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"common_name": map[string]interface{}{
					"type":        "string",
					"description": "Common name for the certificate subject",
				},
				"organization": map[string]interface{}{
					"type":        "string",
					"description": "Organization name",
				},
				"organizational_unit": map[string]interface{}{
					"type":        "string",
					"description": "Organizational unit",
				},
				"country": map[string]interface{}{
					"type":        "string",
					"description": "Country code (e.g., US)",
				},
				"province": map[string]interface{}{
					"type":        "string",
					"description": "State or province",
				},
				"locality": map[string]interface{}{
					"type":        "string",
					"description": "City or locality",
				},
				"dns_names": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "DNS names for Subject Alternative Names",
				},
				"email_addresses": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Email addresses for Subject Alternative Names",
				},
				"include_tcg_attrs": map[string]interface{}{
					"type":        "boolean",
					"description": "Include TCG platform attributes in the CSR",
					"default":     true,
				},
			},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "idevid_install_cert",
		Description: "Install an IDevID certificate issued by a CA",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"certificate_pem": map[string]interface{}{
					"type":        "string",
					"description": "PEM-encoded certificate to install",
				},
			},
			"required": []string{"certificate_pem"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "idevid_get_cert",
		Description: "Get the installed IDevID certificate",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"include_pem": map[string]interface{}{
					"type":        "boolean",
					"description": "Include PEM-encoded certificate in response",
					"default":     true,
				},
			},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "idevid_delete_cert",
		Description: "Delete the IDevID certificate",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "idevid_exists",
		Description: "Check if an IDevID key exists in the TPM",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// IAK operations
	r.addTool(mcpwire.ToolDefinition{
		Name:        "iak_generate",
		Description: "Generate an IAK (Initial Attestation Key) in the TPM. IAK is used for device attestation per IEEE 802.1AR.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"algorithm": map[string]interface{}{
					"type":        "string",
					"description": "Key algorithm (RSA or ECC, default: ECC)",
					"enum":        []string{"RSA", "ECC"},
					"default":     "ECC",
				},
				"overwrite": map[string]interface{}{
					"type":        "boolean",
					"description": "Overwrite existing IAK key if present",
					"default":     false,
				},
			},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iak_info",
		Description: "Get information about the IAK key including handle, algorithm, and certificate if installed",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iak_delete",
		Description: "Delete the IAK key and associated certificate from the TPM",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iak_csr",
		Description: "Generate a Certificate Signing Request (CSR) for the IAK key using TCG format",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"common_name": map[string]interface{}{
					"type":        "string",
					"description": "Common name for the certificate subject",
				},
				"organization": map[string]interface{}{
					"type":        "string",
					"description": "Organization name",
				},
				"organizational_unit": map[string]interface{}{
					"type":        "string",
					"description": "Organizational unit",
				},
				"country": map[string]interface{}{
					"type":        "string",
					"description": "Country code (e.g., US)",
				},
				"province": map[string]interface{}{
					"type":        "string",
					"description": "State or province",
				},
				"locality": map[string]interface{}{
					"type":        "string",
					"description": "City or locality",
				},
				"dns_names": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "DNS names for Subject Alternative Names",
				},
				"email_addresses": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Email addresses for Subject Alternative Names",
				},
				"include_tcg_attrs": map[string]interface{}{
					"type":        "boolean",
					"description": "Include TCG platform attributes in the CSR",
					"default":     true,
				},
			},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iak_install_cert",
		Description: "Install an IAK certificate issued by a CA",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"certificate_pem": map[string]interface{}{
					"type":        "string",
					"description": "PEM-encoded certificate to install",
				},
			},
			"required": []string{"certificate_pem"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iak_get_cert",
		Description: "Get the installed IAK certificate",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"include_pem": map[string]interface{}{
					"type":        "boolean",
					"description": "Include PEM-encoded certificate in response",
					"default":     true,
				},
			},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iak_delete_cert",
		Description: "Delete the IAK certificate",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iak_exists",
		Description: "Check if an IAK key exists in the TPM",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	// Device attributes and credential activation
	r.addTool(mcpwire.ToolDefinition{
		Name:        "device_attributes",
		Description: "Get TCG device attributes including TPM manufacturer, model, version, and platform information",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "activate_credential",
		Description: "Activate a TPM credential challenge. Used in device enrollment to prove possession of the EK and IAK.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"credential_blob": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded credential blob from the CA",
				},
				"secret": map[string]interface{}{
					"type":        "string",
					"description": "Base64-encoded encrypted secret from the CA",
				},
			},
			"required": []string{"credential_blob", "secret"},
		},
	})
}

// =============================================================================
// IDevID/IAK Tool Execution Handlers
// =============================================================================

// executeIDevIDGenerate generates an IDevID key.
func (r *ToolRegistry) executeIDevIDGenerate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	req := &IDevIDGenerateMCPRequest{
		Algorithm: getString(args, "algorithm"),
		Overwrite: getBool(args, "overwrite"),
	}
	if req.Algorithm == "" {
		req.Algorithm = "ECC"
	}

	result, err := r.service.IDevIDGenerate(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeIDevIDInfo retrieves IDevID key information.
func (r *ToolRegistry) executeIDevIDInfo(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.IDevIDInfo(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeIDevIDDelete deletes the IDevID key.
func (r *ToolRegistry) executeIDevIDDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if err := r.service.IDevIDDelete(ctx); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true, "message": "IDevID key deleted"}, nil
}

// executeIDevIDCSR generates a CSR for the IDevID key.
func (r *ToolRegistry) executeIDevIDCSR(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	req := &IDevIDCSRMCPRequest{
		CommonName:         getString(args, "common_name"),
		Organization:       getString(args, "organization"),
		OrganizationalUnit: getString(args, "organizational_unit"),
		Country:            getString(args, "country"),
		Province:           getString(args, "province"),
		Locality:           getString(args, "locality"),
		DNSNames:           getStringSlice(args, "dns_names"),
		EmailAddresses:     getStringSlice(args, "email_addresses"),
		IncludeTCGAttrs:    true,
	}
	if _, ok := args["include_tcg_attrs"]; ok {
		req.IncludeTCGAttrs = getBool(args, "include_tcg_attrs")
	}

	result, err := r.service.IDevIDCSR(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeIDevIDInstallCert installs an IDevID certificate.
func (r *ToolRegistry) executeIDevIDInstallCert(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	certPEM := getString(args, "certificate_pem")
	if certPEM == "" {
		return nil, ErrIDevIDCertificatePEMRequired
	}

	result, err := r.service.IDevIDInstallCert(ctx, certPEM)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeIDevIDGetCert retrieves the IDevID certificate.
func (r *ToolRegistry) executeIDevIDGetCert(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	includePEM := true
	if _, ok := args["include_pem"]; ok {
		includePEM = getBool(args, "include_pem")
	}

	result, err := r.service.IDevIDGetCert(ctx, includePEM)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeIDevIDDeleteCert deletes the IDevID certificate.
func (r *ToolRegistry) executeIDevIDDeleteCert(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if err := r.service.IDevIDDeleteCert(ctx); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true, "message": "IDevID certificate deleted"}, nil
}

// executeIDevIDExists checks if an IDevID key exists.
func (r *ToolRegistry) executeIDevIDExists(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	exists, err := r.service.IDevIDExists(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"exists": exists}, nil
}

// executeIAKGenerate generates an IAK key.
func (r *ToolRegistry) executeIAKGenerate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	req := &IDevIDGenerateMCPRequest{
		Algorithm: getString(args, "algorithm"),
		Overwrite: getBool(args, "overwrite"),
	}
	if req.Algorithm == "" {
		req.Algorithm = "ECC"
	}

	result, err := r.service.IAKGenerate(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeIAKInfo retrieves IAK key information.
func (r *ToolRegistry) executeIAKInfo(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.IAKInfo(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeIAKDelete deletes the IAK key.
func (r *ToolRegistry) executeIAKDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if err := r.service.IAKDelete(ctx); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true, "message": "IAK key deleted"}, nil
}

// executeIAKCSR generates a CSR for the IAK key.
func (r *ToolRegistry) executeIAKCSR(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	req := &IDevIDCSRMCPRequest{
		CommonName:         getString(args, "common_name"),
		Organization:       getString(args, "organization"),
		OrganizationalUnit: getString(args, "organizational_unit"),
		Country:            getString(args, "country"),
		Province:           getString(args, "province"),
		Locality:           getString(args, "locality"),
		DNSNames:           getStringSlice(args, "dns_names"),
		EmailAddresses:     getStringSlice(args, "email_addresses"),
		IncludeTCGAttrs:    true,
	}
	if _, ok := args["include_tcg_attrs"]; ok {
		req.IncludeTCGAttrs = getBool(args, "include_tcg_attrs")
	}

	result, err := r.service.IAKCSR(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeIAKInstallCert installs an IAK certificate.
func (r *ToolRegistry) executeIAKInstallCert(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	certPEM := getString(args, "certificate_pem")
	if certPEM == "" {
		return nil, ErrIDevIDCertificatePEMRequired
	}

	result, err := r.service.IAKInstallCert(ctx, certPEM)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeIAKGetCert retrieves the IAK certificate.
func (r *ToolRegistry) executeIAKGetCert(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	includePEM := true
	if _, ok := args["include_pem"]; ok {
		includePEM = getBool(args, "include_pem")
	}

	result, err := r.service.IAKGetCert(ctx, includePEM)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeIAKDeleteCert deletes the IAK certificate.
func (r *ToolRegistry) executeIAKDeleteCert(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if err := r.service.IAKDeleteCert(ctx); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true, "message": "IAK certificate deleted"}, nil
}

// executeIAKExists checks if an IAK key exists.
func (r *ToolRegistry) executeIAKExists(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	exists, err := r.service.IAKExists(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"exists": exists}, nil
}

// executeDeviceAttributes retrieves TCG device attributes.
func (r *ToolRegistry) executeDeviceAttributes(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.DeviceAttributes(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeActivateCredential activates a TPM credential challenge.
func (r *ToolRegistry) executeActivateCredential(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	credentialBlobB64 := getString(args, "credential_blob")
	if credentialBlobB64 == "" {
		return nil, ErrIDevIDCredentialBlobRequired
	}

	secretB64 := getString(args, "secret")
	if secretB64 == "" {
		return nil, ErrIDevIDSecretRequired
	}

	credentialBlob, err := base64.StdEncoding.DecodeString(credentialBlobB64)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrIDevIDInvalidBase64, Cause: &mcpwire.MessageError{Msg: fmt.Sprintf("credential_blob: %v", err)}}
	}

	secret, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrIDevIDInvalidBase64, Cause: &mcpwire.MessageError{Msg: fmt.Sprintf("secret: %v", err)}}
	}

	decrypted, err := r.service.ActivateCredential(ctx, credentialBlob, secret)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"decrypted": base64.StdEncoding.EncodeToString(decrypted),
	}, nil
}
