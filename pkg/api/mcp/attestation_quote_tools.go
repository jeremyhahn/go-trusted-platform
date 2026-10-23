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
	"maps"
	"slices"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// =============================================================================
// Attestation quote and collection tool wiring
// =============================================================================
//
// The quote and collection tools are bound to the gRPC AttestationService. A
// tool's arguments are the gRPC request in protojson form and its result is
// the gRPC response in the same form; each calls the servicer, so it
// validates, answers and fails exactly as gRPC does. The two tools that make
// the node's TPM quote a caller's nonce (attestation_get_quote and
// attestation_collect_host) bind the quote to the connection the call
// arrived on: over HTTPS that is the request's TLS state, and over stdio
// there is none, so the servicer refuses them (docs/attestation/api.md §5.1a).

// ErrAttestationServiceNotConfigured is returned when the MCP server has no
// gRPC AttestationService servicer to call.
var ErrAttestationServiceNotConfigured = &AttestationError{
	Code:    "ATTESTATION_SERVICE_NOT_CONFIGURED",
	Message: "the attestation service is not configured on this node",
}

// AttestationServiceProvider is implemented by a ServiceProvider that serves
// the gRPC AttestationService. The attestation quote and collection tools
// call that servicer.
type AttestationServiceProvider interface {
	// AttestationServiceServer returns the gRPC AttestationService
	// servicer, or nil while no attestation service is wired.
	AttestationServiceServer() platformv1.AttestationServiceServer
}

// attestationQuoteTool is one attestation tool bound to the gRPC
// AttestationService and the permission it requires.
type attestationQuoteTool struct {
	method string
	// scope is the permission the tool requires: the scope of its gRPC
	// method in pkg/api/grpc/method_permissions.go.
	scope       string
	description string
	binding     grpcToolBinding[platformv1.AttestationServiceServer]
}

// attestationQuoteTools are the attestation tools bound to the gRPC
// AttestationService.
var attestationQuoteTools = map[string]attestationQuoteTool{
	"attestation_get_quote": {
		method:      platformv1.AttestationService_GetAttestationQuote_FullMethodName,
		scope:       "attestation:read",
		description: "Quote the node's PCRs over a nonce, bound to this HTTPS connection (refused over stdio)",
		binding:     grpcToolMethod(platformv1.AttestationServiceServer.GetAttestationQuote, "config", "nonce"),
	},
	"attestation_verify_quote": {
		method:      platformv1.AttestationService_VerifyAttestationQuote_FullMethodName,
		scope:       "attestation:read",
		description: "Verify a quote's signature against an AK public key, and optionally its nonce and PCR values",
		binding:     grpcToolMethod(platformv1.AttestationServiceServer.VerifyAttestationQuote, "quote", "ak_public_key_pem"),
	},
	"attestation_collect_host": {
		method:      platformv1.AttestationService_CollectHostAttestation_FullMethodName,
		scope:       "attestation:write",
		description: "Collect the node's host attestation over a nonce, bound to this HTTPS connection (refused over stdio)",
		binding:     grpcToolMethod(platformv1.AttestationServiceServer.CollectHostAttestation, "nonce"),
	},
	"attestation_collect_vm": {
		method:      platformv1.AttestationService_CollectVMAttestation_FullMethodName,
		scope:       "attestation:write",
		description: "Collect a VM's attestation from its vTPM",
		binding:     grpcToolMethod(platformv1.AttestationServiceServer.CollectVMAttestation, "vm_id", "config", "nonce"),
	},
	"attestation_collect_container": {
		method:      platformv1.AttestationService_CollectContainerAttestation_FullMethodName,
		scope:       "attestation:write",
		description: "Collect a container's attestation",
		binding:     grpcToolMethod(platformv1.AttestationServiceServer.CollectContainerAttestation, "container_id"),
	},
}

// registerAttestationQuoteTools registers the attestation tools bound to the
// gRPC AttestationService.
func (r *ToolRegistry) registerAttestationQuoteTools() {
	for _, name := range slices.Sorted(maps.Keys(attestationQuoteTools)) {
		tool := attestationQuoteTools[name]
		r.addTool(mcpwire.ToolDefinition{
			Name:        name,
			Description: tool.description,
			InputSchema: tool.binding.schema(),
		})
	}
}

// attestationServiceServer is the gRPC AttestationService servicer the
// attestation quote and collection tools call, or nil while the service
// provider serves none.
func (r *ToolRegistry) attestationServiceServer() platformv1.AttestationServiceServer {
	if provider, ok := r.service.(AttestationServiceProvider); ok {
		return provider.AttestationServiceServer()
	}
	return nil
}

// dispatchAttestationQuoteTool runs an attestation tool bound to the gRPC
// AttestationService; handled is false for any other tool name.
func (r *ToolRegistry) dispatchAttestationQuoteTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	tool, ok := attestationQuoteTools[name]
	if !ok {
		return nil, false, nil
	}
	server := r.attestationServiceServer()
	if server == nil {
		return nil, true, ErrAttestationServiceNotConfigured
	}
	result, err := tool.binding.call(server, ctx, args)
	return result, true, err
}
