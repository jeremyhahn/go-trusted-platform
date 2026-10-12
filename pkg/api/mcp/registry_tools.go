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

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// =============================================================================
// Registry tool wiring
// =============================================================================
//
// These tools mirror the non-streaming surface of the gRPC RegistryService so
// AI/LLM clients can drive container/artifact registry workflows over MCP.
// Tool names follow the project convention `platform_registry_<verb>` and
// are routed through a map-based dispatcher (O(1) lookup per project
// conventions).
//
// Streaming Push/Pull RPCs are intentionally not exposed via MCP: binary
// blob transfer is a poor fit for the JSON-RPC surface and is already
// covered by the gRPC and REST adapters. AI/LLM clients that need image
// bytes should call those transports directly.
//
// The MCP server stays decoupled from the daemon: the underlying
// RegistryService is exposed via the optional RegistryProvider interface,
// satisfied by the daemon's MCPServiceProvider when a registry service is
// wired in. When a provider is not wired, every registry tool returns
// ErrRegistryNotConfigured so clients get a clear, structured failure
// rather than a generic "unknown tool" error.

// ErrRegistryNotConfigured indicates the registry backend is not wired
// into the MCP tool registry. Clients see this when the daemon was
// started without a registry service available (e.g., the registry
// service is disabled in config).
var ErrRegistryNotConfigured = errors.New("registry: service provider not configured")

// ErrRegistryRepositoryRequired indicates the `repository` argument is
// missing. Repository is the primary key for every artifact-scoped RPC.
var ErrRegistryRepositoryRequired = errors.New("registry: repository is required")

// ErrRegistryReferenceRequired indicates that neither `reference` (tag)
// nor `digest` was supplied. At least one must be present to identify
// an artifact for inspect/delete operations.
var ErrRegistryReferenceRequired = errors.New("registry: reference (tag) or digest is required")

// RegistryProvider is the optional interface a ServiceProvider can satisfy
// to unlock registry MCP tools. Implementations are expected to delegate
// to the platform RegistryService (the same backing implementation that
// powers the gRPC RegistryServiceServer) so the MCP and gRPC surfaces
// remain in lockstep.
//
// Method names map to MCP tools: platform_registry_list, etc.
type RegistryProvider interface {
	// RegistryList returns a paginated set of artifacts. The `repository`
	// filter is optional — when empty, artifacts across all repositories
	// are returned. `artifact_type` is also optional and matches the
	// gRPC ArtifactType enum value.
	RegistryList(ctx context.Context, repository string, artifactType int32, limit, offset int32) (interface{}, error)

	// RegistryInspect returns detailed metadata for a single artifact
	// identified by (repository, reference) or (repository, digest).
	RegistryInspect(ctx context.Context, repository, reference, digest string, includeSignatures, includeScanResult bool) (interface{}, error)

	// RegistryDelete removes an artifact from the registry. The `force`
	// flag tells the backend to bypass the soft-delete grace period when
	// supported.
	RegistryDelete(ctx context.Context, repository, reference, digest string, force bool) (interface{}, error)

	// RegistryStatus returns registry health, version, and storage stats.
	RegistryStatus(ctx context.Context) (interface{}, error)
}

// registryProvider returns the RegistryProvider interface if the
// ServiceProvider implements it, else nil.
func (r *ToolRegistry) registryProvider() RegistryProvider {
	if p, ok := r.service.(RegistryProvider); ok {
		return p
	}
	return nil
}

// registerRegistryTools registers the platform_registry_* MCP tools.
// Each tool definition mirrors the equivalent gRPC RPC so AI/LLM clients
// can issue the same calls they would over gRPC.
func (r *ToolRegistry) registerRegistryTools() {
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_registry_list",
		Description: "List artifacts in the container/artifact registry, optionally filtered by repository and type",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"repository": map[string]interface{}{
					"type":        "string",
					"description": "Optional repository filter (e.g. 'platform/gateway')",
				},
				"artifact_type": map[string]interface{}{
					"type":        "integer",
					"description": "Optional artifact type filter (1=container_image, 2=helm_chart, 3=oci_artifact, 4=wasm_module, 5=binary)",
				},
				"limit": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of artifacts to return (default 100)",
					"default":     100,
				},
				"offset": map[string]interface{}{
					"type":        "integer",
					"description": "Pagination offset (default 0)",
					"default":     0,
				},
			},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_registry_inspect",
		Description: "Inspect a registry artifact and return its manifest, signatures, and scan result",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"repository": map[string]interface{}{
					"type":        "string",
					"description": "Repository name (e.g. 'platform/gateway')",
				},
				"reference": map[string]interface{}{
					"type":        "string",
					"description": "Tag (e.g. 'v1.2.3' or 'latest'). Either reference or digest is required",
				},
				"digest": map[string]interface{}{
					"type":        "string",
					"description": "Content digest (e.g. 'sha256:...'). Either reference or digest is required",
				},
				"include_signatures": map[string]interface{}{
					"type":        "boolean",
					"description": "Include attached signatures in the response",
					"default":     false,
				},
				"include_scan_result": map[string]interface{}{
					"type":        "boolean",
					"description": "Include vulnerability scan result in the response",
					"default":     false,
				},
			},
			"required": []string{"repository"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_registry_delete",
		Description: "Delete an artifact from the registry by tag or digest",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"repository": map[string]interface{}{
					"type":        "string",
					"description": "Repository name",
				},
				"reference": map[string]interface{}{
					"type":        "string",
					"description": "Tag identifying the artifact (either reference or digest is required)",
				},
				"digest": map[string]interface{}{
					"type":        "string",
					"description": "Digest identifying the artifact (either reference or digest is required)",
				},
				"force": map[string]interface{}{
					"type":        "boolean",
					"description": "Bypass soft-delete grace period",
					"default":     false,
				},
			},
			"required": []string{"repository"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_registry_status",
		Description: "Return registry health, version, storage stats, and component health",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})
}

// =============================================================================
// Map-based dispatch
// =============================================================================

// registryToolHandler dispatches a registry tool by name. Map-based
// dispatch keeps routing O(1) per project conventions.
type registryToolHandler func(*ToolRegistry, context.Context, map[string]interface{}) (interface{}, error)

var registryToolDispatch = map[string]registryToolHandler{
	"platform_registry_list":    (*ToolRegistry).executeRegistryList,
	"platform_registry_inspect": (*ToolRegistry).executeRegistryInspect,
	"platform_registry_delete":  (*ToolRegistry).executeRegistryDelete,
	"platform_registry_status":  (*ToolRegistry).executeRegistryStatus,
}

// dispatchRegistryTool looks up a registry tool and invokes it. Returns
// (result, handled, err) so the caller can fall through when handled is
// false (tool name doesn't belong to the registry surface).
func (r *ToolRegistry) dispatchRegistryTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	fn, ok := registryToolDispatch[name]
	if !ok {
		return nil, false, nil
	}
	result, err := fn(r, ctx, args)
	return result, true, err
}

// =============================================================================
// Argument helpers
// =============================================================================

// registryRepository extracts the required `repository` argument.
// Returns ErrRegistryRepositoryRequired when missing or empty.
func registryRepository(args map[string]interface{}) (string, error) {
	repo := getString(args, "repository")
	if repo == "" {
		return "", ErrRegistryRepositoryRequired
	}
	return repo, nil
}

// registryReference extracts (reference, digest). At least one must be
// non-empty; otherwise ErrRegistryReferenceRequired is returned.
func registryReference(args map[string]interface{}) (string, string, error) {
	ref := getString(args, "reference")
	digest := getString(args, "digest")
	if ref == "" && digest == "" {
		return "", "", ErrRegistryReferenceRequired
	}
	return ref, digest, nil
}

// =============================================================================
// Executors
// =============================================================================

func (r *ToolRegistry) executeRegistryList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.registryProvider()
	if p == nil {
		return nil, ErrRegistryNotConfigured
	}
	repo := getString(args, "repository") // optional
	artifactType := int32(getInt(args, "artifact_type"))
	limit := int32(getInt(args, "limit"))
	offset := int32(getInt(args, "offset"))
	return p.RegistryList(ctx, repo, artifactType, limit, offset)
}

func (r *ToolRegistry) executeRegistryInspect(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.registryProvider()
	if p == nil {
		return nil, ErrRegistryNotConfigured
	}
	repo, err := registryRepository(args)
	if err != nil {
		return nil, err
	}
	ref, digest, err := registryReference(args)
	if err != nil {
		return nil, err
	}
	return p.RegistryInspect(ctx, repo, ref, digest, getBool(args, "include_signatures"), getBool(args, "include_scan_result"))
}

func (r *ToolRegistry) executeRegistryDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.registryProvider()
	if p == nil {
		return nil, ErrRegistryNotConfigured
	}
	repo, err := registryRepository(args)
	if err != nil {
		return nil, err
	}
	ref, digest, err := registryReference(args)
	if err != nil {
		return nil, err
	}
	return p.RegistryDelete(ctx, repo, ref, digest, getBool(args, "force"))
}

func (r *ToolRegistry) executeRegistryStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.registryProvider()
	if p == nil {
		return nil, ErrRegistryNotConfigured
	}
	return p.RegistryStatus(ctx)
}
