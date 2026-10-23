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

package mcpwire

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// ClientConfig contains MCP client configuration.
type ClientConfig struct {
	// ServerAddr is the MCP server HTTP address
	ServerAddr string

	// Timeout is the request timeout
	Timeout time.Duration

	// MaxRetries is the maximum number of retry attempts. Only a failure
	// IsRetryable accepts is retried.
	MaxRetries int

	// RetryDelay is the delay between retry attempts, unless the answer's
	// Retry-After header asks for another
	RetryDelay time.Duration

	// TLSConfig verifies an https:// server (roots, client certificate,
	// server name). When nil the system roots are used.
	TLSConfig *tls.Config
}

// DefaultClientConfig returns default MCP client configuration.
func DefaultClientConfig(serverAddr string) *ClientConfig {
	return &ClientConfig{
		ServerAddr: serverAddr,
		Timeout:    30 * time.Second,
		MaxRetries: 3,
		RetryDelay: 1 * time.Second,
	}
}

// Client is an MCP client for the Trusted Platform.
type Client struct {
	config     *ClientConfig
	httpClient *http.Client
	logger     *slog.Logger
	requestID  atomic.Uint64

	mu     sync.RWMutex
	token  string
	closed bool
}

// ClientOption configures the MCP client.
type ClientOption func(*clientOptions)

type clientOptions struct {
	logger *slog.Logger
	token  string
}

// WithMCPClientLogger sets a custom logger.
func WithMCPClientLogger(l *slog.Logger) ClientOption {
	return func(o *clientOptions) {
		o.logger = l
	}
}

// WithMCPToken sets the authentication token.
func WithMCPToken(token string) ClientOption {
	return func(o *clientOptions) {
		o.token = token
	}
}

// NewClient creates a new MCP client.
func NewClient(config *ClientConfig, opts ...ClientOption) (*Client, error) {
	if config == nil {
		return nil, &MessageError{Msg: "config cannot be nil"}
	}

	if config.ServerAddr == "" {
		return nil, &MessageError{Msg: "server address cannot be empty"}
	}

	options := &clientOptions{}
	for _, opt := range opts {
		opt(options)
	}

	if options.logger == nil {
		options.logger = slog.Default()
	}

	httpClient := &http.Client{Timeout: config.Timeout}
	if config.TLSConfig != nil {
		httpClient.Transport = &http.Transport{TLSClientConfig: config.TLSConfig}
	}

	c := &Client{
		config:     config,
		httpClient: httpClient,
		logger:     options.logger,
		token:      options.token,
	}

	return c, nil
}

// Close closes the MCP client.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	c.httpClient.CloseIdleConnections()
	c.logger.Debug("MCP client closed")

	return nil
}

// SetToken sets the authentication token for requests.
func (c *Client) SetToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
}

// Initialize sends the initialize request to the MCP server.
func (c *Client) Initialize(ctx context.Context) (*InitializeResult, error) {
	resp, err := c.call(ctx, "initialize", nil)
	if err != nil {
		return nil, err
	}

	var result InitializeResult
	if err := mapToStruct(resp, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// ListTools retrieves the list of available tools from the server.
func (c *Client) ListTools(ctx context.Context) ([]ToolDefinition, error) {
	resp, err := c.call(ctx, "tools/list", nil)
	if err != nil {
		return nil, err
	}

	result, ok := resp.(map[string]interface{})
	if !ok {
		return nil, &MessageError{Msg: "unexpected response format"}
	}

	toolsRaw, ok := result["tools"]
	if !ok {
		return nil, &MessageError{Msg: "missing tools in response"}
	}

	var tools []ToolDefinition
	if err := mapToStruct(toolsRaw, &tools); err != nil {
		return nil, err
	}

	return tools, nil
}

// CallTool executes a tool on the MCP server.
func (c *Client) CallTool(ctx context.Context, name string, arguments map[string]interface{}) (interface{}, error) {
	params := map[string]interface{}{
		"name":      name,
		"arguments": arguments,
	}

	return c.call(ctx, "tools/call", params)
}

// ListResources retrieves the list of available resources from the server.
func (c *Client) ListResources(ctx context.Context) ([]ResourceDefinition, error) {
	resp, err := c.call(ctx, "resources/list", nil)
	if err != nil {
		return nil, err
	}

	result, ok := resp.(map[string]interface{})
	if !ok {
		return nil, &MessageError{Msg: "unexpected response format"}
	}

	resourcesRaw, ok := result["resources"]
	if !ok {
		return nil, &MessageError{Msg: "missing resources in response"}
	}

	var resources []ResourceDefinition
	if err := mapToStruct(resourcesRaw, &resources); err != nil {
		return nil, err
	}

	return resources, nil
}

// ReadResource reads a resource by URI from the MCP server.
func (c *Client) ReadResource(ctx context.Context, uri string) (interface{}, error) {
	params := map[string]interface{}{
		"uri": uri,
	}

	return c.call(ctx, "resources/read", params)
}

// Ping sends a ping request to verify connectivity.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.call(ctx, "ping", nil)
	return err
}

// call makes a JSON-RPC call to the MCP server.
func (c *Client) call(ctx context.Context, method string, params interface{}) (interface{}, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return nil, &MessageError{Msg: "client is closed"}
	}
	token := c.token
	c.mu.RUnlock()

	requestID := c.requestID.Add(1)

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      requestID,
		Method:  method,
		Params:  params,
	}

	var result interface{}
	attempt := 0
	backoff := &retryAfterBackoff{base: &quicbaas.ConstantBackoff{Delay: c.config.RetryDelay}}
	retryCfg := &quicbaas.RetryConfig{
		MaxAttempts: c.config.MaxRetries + 1,
		Backoff:     backoff,
		RetryableFunc: func(err error) bool {
			return IsRetryable(ctx, method, err)
		},
	}
	err := quicbaas.RetryDo(ctx, retryCfg, func(ctx context.Context) error {
		attempt++
		res, reqErr := c.doRequest(ctx, req, token)
		if reqErr != nil {
			backoff.observe(reqErr)
			c.logger.Debug("MCP request failed",
				slog.Int("attempt", attempt),
				slog.Int("max_attempts", c.config.MaxRetries+1),
				slog.Any("error", reqErr))
			return reqErr
		}
		result = res
		return nil
	})
	if err != nil {
		// Preserve pre-SDK behavior: cancellation surfaces as the raw
		// context error rather than a wrapped retry error.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}

	return result, nil
}

// doRequest performs the actual HTTP request.
func (c *Client) doRequest(ctx context.Context, req *JSONRPCRequest, token string) (interface{}, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to marshal request", Err: err}
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.ServerAddr+"/mcp", bytes.NewReader(body))
	if err != nil {
		return nil, &WrappedError{Msg: "failed to create request", Err: err}
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, &WrappedError{Msg: "request failed", Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, newHTTPStatusError(resp, time.Now())
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to read response", Err: err}
	}

	var rpcResp JSONRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, &WrappedError{Msg: "failed to parse response", Err: err}
	}

	if rpcResp.Error != nil {
		return nil, &MCPError{
			Code:    rpcResp.Error.Code,
			Message: rpcResp.Error.Message,
			Data:    rpcResp.Error.Data,
		}
	}

	return rpcResp.Result, nil
}

// IsConnected returns true if the client is not closed.
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return !c.closed
}

// ServerAddr returns the server address.
func (c *Client) ServerAddr() string {
	return c.config.ServerAddr
}

// InitializeResult is the result of an initialize request.
type InitializeResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	ServerInfo      ServerInfo             `json:"serverInfo"`
	Capabilities    map[string]interface{} `json:"capabilities"`
}

// ServerInfo contains information about the MCP server.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// MCPError represents an MCP protocol error.
type MCPError struct {
	Code    int
	Message string
	Data    interface{}
}

func (e *MCPError) Error() string {
	return fmt.Sprintf("MCP error %d: %s", e.Code, e.Message)
}

// mapToStruct converts a map to a struct via JSON round-trip.
func mapToStruct(src interface{}, dst interface{}) error {
	data, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dst)
}
