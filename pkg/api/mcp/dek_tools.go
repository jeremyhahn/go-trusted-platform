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

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// DEK tools.
//
// dek_create, dek_list, dek_get, dek_status, dek_rotate and dek_delete call
// the quicbaas.kms.v1 DEKManagement service the gRPC and QUIC transports
// call, so a DEK created on one transport is the same DEK on every other.
// Each answer has the layout of the DEKManagement response message.

// ErrDEKPathRequired indicates a DEK path is required.
var ErrDEKPathRequired = &KMSError{
	Code:    "DEK_PATH_REQUIRED",
	Message: "DEK path is required",
}

// dekPathSchema is the input schema of a tool that takes only a DEK path.
func dekPathSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"path": map[string]interface{}{
				"type":        "string",
				"description": "DEK path",
			},
		},
		"required": []string{"path"},
	}
}

// registerDEKTools registers the DEK management tools.
func (r *ToolRegistry) registerDEKTools() {
	r.addTool(mcpwire.ToolDefinition{
		Name:        "dek_create",
		Description: "Create a data encryption key at a path",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "DEK path",
				},
				"algorithm": map[string]interface{}{
					"type":        "integer",
					"description": "quicbaas.kms.v1 KeyAlgorithm number; 0 selects the default",
				},
				"description": map[string]interface{}{
					"type":        "string",
					"description": "DEK description",
				},
				"max_operations": map[string]interface{}{
					"type":        "integer",
					"description": "Operations before the DEK must rotate; 0 is unlimited",
				},
				"max_bytes": map[string]interface{}{
					"type":        "integer",
					"description": "Bytes processed before the DEK must rotate; 0 is unlimited",
				},
				"warning_percent": map[string]interface{}{
					"type":        "integer",
					"description": "Usage percent that raises the rotation warning",
				},
				"tags": map[string]interface{}{
					"type":        "object",
					"description": "DEK tags",
				},
			},
			"required": []string{"path"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "dek_list",
		Description: "List data encryption keys under a prefix",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"prefix": map[string]interface{}{
					"type":        "string",
					"description": "Path prefix",
				},
				"recursive": map[string]interface{}{
					"type":        "boolean",
					"description": "Include DEKs below the prefix's children",
				},
				"limit": map[string]interface{}{
					"type":        "integer",
					"description": "Page size",
				},
				"cursor": map[string]interface{}{
					"type":        "string",
					"description": "Cursor from the previous page",
				},
			},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "dek_get",
		Description: "Get a data encryption key's metadata",
		InputSchema: dekPathSchema(),
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "dek_status",
		Description: "Get a data encryption key's usage and rotation status",
		InputSchema: dekPathSchema(),
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "dek_rotate",
		Description: "Rotate a data encryption key to a new version",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "DEK path",
				},
				"background": map[string]interface{}{
					"type":        "boolean",
					"description": "Re-encrypt existing data in the background",
				},
			},
			"required": []string{"path"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "dek_delete",
		Description: "Delete a data encryption key",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "DEK path",
				},
				"force": map[string]interface{}{
					"type":        "boolean",
					"description": "Delete even when data is still encrypted under the DEK",
				},
				"migrate_to": map[string]interface{}{
					"type":        "string",
					"description": "DEK path to re-encrypt existing data under first",
				},
			},
			"required": []string{"path"},
		},
	})
}

func (r *ToolRegistry) executeDEKCreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	path := getString(args, "path")
	if path == "" {
		return nil, ErrDEKPathRequired
	}

	result, err := r.service.DEKCreate(ctx, &DEKCreateRequest{
		Path:           path,
		Algorithm:      int32(getInt64(args, "algorithm")),
		Description:    getString(args, "description"),
		MaxOperations:  uint64(getInt64(args, "max_operations")),
		MaxBytes:       uint64(getInt64(args, "max_bytes")),
		WarningPercent: int32(getInt64(args, "warning_percent")),
		Tags:           getStringMap(args, "tags"),
	})
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeDEKList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.DEKList(ctx, &DEKListRequest{
		Prefix:    getString(args, "prefix"),
		Recursive: getBool(args, "recursive"),
		Limit:     int32(getInt64(args, "limit")),
		Cursor:    getString(args, "cursor"),
	})
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeDEKGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	path := getString(args, "path")
	if path == "" {
		return nil, ErrDEKPathRequired
	}

	result, err := r.service.DEKGet(ctx, path)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeDEKStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	path := getString(args, "path")
	if path == "" {
		return nil, ErrDEKPathRequired
	}

	result, err := r.service.DEKStatus(ctx, path)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeDEKRotate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	path := getString(args, "path")
	if path == "" {
		return nil, ErrDEKPathRequired
	}

	result, err := r.service.DEKRotate(ctx, path, getBool(args, "background"))
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeDEKDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	path := getString(args, "path")
	if path == "" {
		return nil, ErrDEKPathRequired
	}

	result, err := r.service.DEKDelete(ctx, &DEKDeleteRequest{
		Path:      path,
		Force:     getBool(args, "force"),
		MigrateTo: getString(args, "migrate_to"),
	})
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}
