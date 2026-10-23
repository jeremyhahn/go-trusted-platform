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

// Package mcpwire is the platform MCP wire contract: the JSON-RPC 2.0
// envelopes, protocol version, error codes, tool and resource descriptors,
// and the client that speaks them. The daemon's MCP server (pkg/api/mcp) and
// the SDK MCP transport import this one definition, so the two cannot drift.
package mcpwire

const (
	// MCPVersion is the supported MCP protocol version.
	MCPVersion = "2024-11-05"

	// JSON-RPC 2.0 error codes.
	ParseError     = -32700
	InvalidRequest = -32600
	MethodNotFound = -32601
	InvalidParams  = -32602
	InternalError  = -32603

	// Platform error codes, in the JSON-RPC server-error range. The first
	// four predate the tool error classes and also answer authorization
	// failures; errorcodes.go maps each to the platform error class.
	AuthenticationRequired = -32001
	InvalidToken           = -32002
	PermissionDenied       = -32003
	ServiceUnavailable     = -32004
	NotFound               = -32005
	AlreadyExists          = -32006
	FailedPrecondition     = -32007
)

// JSONRPCRequest represents a JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      interface{}   `json:"id,omitempty"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

// JSONRPCError represents a JSON-RPC 2.0 error.
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// ToolDefinition describes an MCP tool.
type ToolDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// ResourceDefinition describes an MCP resource.
type ResourceDefinition struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MimeType    string `json:"mimeType,omitempty"`
}
