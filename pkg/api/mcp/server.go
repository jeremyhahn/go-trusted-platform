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
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// Config contains MCP server configuration.
type Config struct {
	// ServerName is the MCP server name
	ServerName string

	// ServerVersion is the platform version
	ServerVersion string

	// Transport is the transport type: "stdio" or "http"
	Transport string

	// HTTPAddr is the HTTP listen address (for HTTP transport)
	HTTPAddr string

	// TLSConfig is the server TLS configuration for the HTTP transport. It
	// is required: the HTTP transport serves TLS 1.3 only, and Start
	// refuses with HTTPTLSRequiredError when TLSConfig carries no server
	// certificate. There is no plaintext mode. Unused by stdio.
	TLSConfig *tls.Config

	// RequestTimeout is the default timeout for operations
	RequestTimeout time.Duration

	// MaxConcurrentRequests limits concurrent requests
	MaxConcurrentRequests int

	// AuthorizationService for checking permissions (optional)
	AuthorizationService AuthorizationService

	// AuthManager for validating tokens (optional)
	AuthManager AuthManager

	// OAuthMetadata is the OAuth 2.1 Protected Resource Metadata configuration.
	// Required for OAuth 2.1 compliance per RFC 9728.
	OAuthMetadata *OAuthMetadataConfig
}

// DefaultConfig returns default MCP server configuration.
func DefaultConfig() *Config {
	return &Config{
		ServerName:            "Trusted Platform MCP Server",
		ServerVersion:         "1.0.0",
		Transport:             "http",
		HTTPAddr:              "127.0.0.1:9445",
		RequestTimeout:        30 * time.Second,
		MaxConcurrentRequests: 100,
	}
}

// Server implements the MCP protocol server.
type Server struct {
	service ServiceProvider
	logger  *logging.Logger
	config  *Config

	// Authorization
	authChecker *AuthorizationChecker

	// OAuth 2.1 metadata handler
	oauthMetadata *OAuthMetadataHandler

	// Runtime state
	running  atomic.Bool
	shutdown chan struct{}
	wg       sync.WaitGroup

	// HTTP server for HTTP transport, and the listener it serves TLS on
	httpServer   *http.Server
	httpListener net.Listener

	// Tools and resources registry
	tools     *ToolRegistry
	resources *ResourceRegistry
}

// NewServer creates a new MCP server instance.
func NewServer(svc ServiceProvider, config *Config, log *logging.Logger) *Server {
	if config == nil {
		config = DefaultConfig()
	}

	if log == nil {
		log = logging.DefaultLogger()
	}

	s := &Server{
		service:  svc,
		logger:   log,
		config:   config,
		shutdown: make(chan struct{}),
	}

	// Initialize authorization checker
	s.authChecker = NewAuthorizationChecker(config.AuthorizationService, config.AuthManager)

	// Initialize OAuth 2.1 metadata handler
	s.oauthMetadata = NewOAuthMetadataHandler(config.OAuthMetadata)

	// Initialize tools and resources registries
	s.tools = NewToolRegistry(svc, log)
	s.resources = NewResourceRegistry(svc, log)

	// Set authorization checker on tools registry
	s.tools.SetAuthorizationChecker(s.authChecker)

	return s
}

// SetAuthorizationService sets the authorization service for the server.
func (s *Server) SetAuthorizationService(authService AuthorizationService, authManager AuthManager) {
	s.authChecker = NewAuthorizationChecker(authService, authManager)
	s.tools.SetAuthorizationChecker(s.authChecker)
}

// SetOAuthMetadata configures the OAuth 2.1 metadata for this server.
// This should be called before Start() to ensure the metadata endpoint
// returns correct information.
func (s *Server) SetOAuthMetadata(resourceURL string, authServers []string) {
	s.oauthMetadata.SetResourceURL(resourceURL)
	s.oauthMetadata.SetAuthorizationServers(authServers)
}

// GetOAuthMetadataHandler returns the OAuth metadata handler.
func (s *Server) GetOAuthMetadataHandler() *OAuthMetadataHandler {
	return s.oauthMetadata
}

// Start starts the MCP server with the configured transport.
func (s *Server) Start() error {
	if s.running.Swap(true) {
		return &mcpwire.MessageError{Msg: "server already running"}
	}

	s.logger.Info("Starting MCP server",
		"transport", s.config.Transport, "server", s.config.ServerName, "version", s.config.ServerVersion)

	switch s.config.Transport {
	case "stdio":
		return s.startStdioTransport()
	case "http":
		return s.startHTTPTransport()
	default:
		s.running.Store(false)
		return &mcpwire.MessageError{Msg: fmt.Sprintf("unsupported transport: %s", s.config.Transport)}
	}
}

// Stop gracefully shuts down the MCP server.
func (s *Server) Stop() error {
	if !s.running.Swap(false) {
		return &mcpwire.MessageError{Msg: "server not running"}
	}

	s.logger.Info("Stopping MCP server")

	// Signal shutdown
	close(s.shutdown)

	// Stop HTTP server if running
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.logger.Errorf("Error shutting down HTTP server: %v", err)
		}
	}

	// Wait for all goroutines to finish
	s.wg.Wait()

	s.logger.Info("MCP server stopped")
	return nil
}

// IsRunning returns true if the server is running.
func (s *Server) IsRunning() bool {
	return s.running.Load()
}

// startStdioTransport starts the stdio transport (JSON-RPC over stdin/stdout).
func (s *Server) startStdioTransport() error {
	s.logger.Info("Starting stdio transport")

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.handleStdioRequests()
	}()

	return nil
}

// handleStdioRequests handles JSON-RPC requests from stdin and writes responses to stdout.
func (s *Server) handleStdioRequests() {
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)

	for scanner.Scan() {
		select {
		case <-s.shutdown:
			return
		default:
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}

			// Parse JSON-RPC request
			var req mcpwire.JSONRPCRequest
			if err := json.Unmarshal(line, &req); err != nil {
				resp := s.makeErrorResponse(nil, mcpwire.ParseError, "Parse error", err.Error())
				if err := encoder.Encode(resp); err != nil {
					s.logger.Errorf("Failed to write error response: %v", err)
				}
				continue
			}

			// Handle request with timeout
			ctx, cancel := context.WithTimeout(context.Background(), s.config.RequestTimeout)
			resp := s.handleRequest(ctx, &req)
			cancel()

			// Write response
			if err := encoder.Encode(resp); err != nil {
				s.logger.Errorf("Failed to write response: %v", err)
			}
		}
	}

	if err := scanner.Err(); err != nil && !stderrors.Is(err, io.EOF) {
		s.logger.Errorf("Error reading from stdin: %v", err)
	}
}

// startHTTPTransport starts the HTTP transport (JSON-RPC over HTTPS). It
// serves TLS 1.3 only and refuses to start without a server certificate;
// there is no plaintext listener.
func (s *Server) startHTTPTransport() error {
	s.logger.Info("Starting HTTPS transport", "addr", s.config.HTTPAddr)

	tlsConfig := serverTLSConfig(s.config.TLSConfig)
	if tlsConfig == nil {
		s.running.Store(false)
		return &HTTPTLSRequiredError{Addr: s.config.HTTPAddr}
	}

	mux := http.NewServeMux()

	// OAuth 2.1 Protected Resource Metadata (RFC 9728)
	// This endpoint MUST be available without authentication
	mux.Handle("/.well-known/oauth-protected-resource", s.oauthMetadata)

	// MCP protocol endpoints
	mux.HandleFunc("/mcp", s.handleHTTPRequest)
	mux.HandleFunc("/health", s.handleHealthCheck)

	s.httpServer = &http.Server{
		Addr:         s.config.HTTPAddr,
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  s.config.RequestTimeout,
		WriteTimeout: s.config.RequestTimeout,
	}

	// Bind before returning so a bad address fails Start instead of being
	// logged from a goroutine after the daemon reports the server up.
	listener, err := net.Listen("tcp", s.config.HTTPAddr)
	if err != nil {
		s.running.Store(false)
		return &HTTPListenError{Addr: s.config.HTTPAddr, Err: err}
	}
	s.httpListener = listener

	// Start HTTPS server in goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		// The certificate comes from httpServer.TLSConfig, so no files.
		if err := s.httpServer.ServeTLS(listener, "", ""); err != nil && err != http.ErrServerClosed {
			s.logger.Errorf("HTTP server error: %v", err)
		}
	}()

	return nil
}

// serverTLSConfig returns a clone of cfg pinned to TLS 1.3, or nil when cfg
// cannot present a server certificate. The caller's config is not modified.
func serverTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return nil
	}
	if len(cfg.Certificates) == 0 && cfg.GetCertificate == nil {
		return nil
	}

	pinned := pinTLS13(cfg.Clone())

	// A per-client config replaces this one for the handshake, so it is
	// pinned too; otherwise it could reopen TLS 1.2.
	if perClient := cfg.GetConfigForClient; perClient != nil {
		pinned.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			clientCfg, err := perClient(hello)
			if err != nil || clientCfg == nil {
				return clientCfg, err
			}
			return pinTLS13(clientCfg.Clone()), nil
		}
	}
	return pinned
}

// pinTLS13 restricts cfg to TLS 1.3 and returns it.
func pinTLS13(cfg *tls.Config) *tls.Config {
	cfg.MinVersion = tls.VersionTLS13
	cfg.MaxVersion = tls.VersionTLS13
	return cfg
}

// handleHTTPRequest handles HTTP POST requests containing JSON-RPC payloads.
func (s *Server) handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse JSON-RPC request
	var req mcpwire.JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		resp := s.makeErrorResponse(nil, mcpwire.ParseError, "Parse error", err.Error())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	// Extract token from Authorization header for HTTP requests
	token := extractTokenFromHTTPRequest(r)

	// Create context with token
	ctx := ContextWithToken(r.Context(), token)

	// Handle request
	resp := s.handleRequest(ctx, &req)

	// Write response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Errorf("Failed to write HTTP response: %v", err)
	}
}

// handleHealthCheck handles health check requests.
func (s *Server) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "healthy",
		"version": s.config.ServerVersion,
		"mcp":     mcpwire.MCPVersion,
	})
}

// handleRequest processes a JSON-RPC request and returns a response.
func (s *Server) handleRequest(ctx context.Context, req *mcpwire.JSONRPCRequest) *mcpwire.JSONRPCResponse {
	s.logger.Debug("Handling MCP request", "method", req.Method, "id", req.ID)

	// Validate JSON-RPC version
	if req.JSONRPC != "2.0" {
		return s.makeErrorResponse(req.ID, mcpwire.InvalidRequest, "Invalid request", "JSON-RPC version must be 2.0")
	}

	// Route to appropriate handler
	switch req.Method {
	case "initialize":
		return s.handleInitialize(ctx, req)
	case "tools/list":
		return s.handleToolsList(ctx, req)
	case "tools/call":
		return s.handleToolsCall(ctx, req)
	case "resources/list":
		return s.handleResourcesList(ctx, req)
	case "resources/read":
		return s.handleResourcesRead(ctx, req)
	case "ping":
		return s.handlePing(ctx, req)
	default:
		return s.makeErrorResponse(req.ID, mcpwire.MethodNotFound, "Method not found", fmt.Sprintf("Unknown method: %s", req.Method))
	}
}

// handleInitialize handles the "initialize" method.
func (s *Server) handleInitialize(ctx context.Context, req *mcpwire.JSONRPCRequest) *mcpwire.JSONRPCResponse {
	result := map[string]interface{}{
		"protocolVersion": mcpwire.MCPVersion,
		"serverInfo": map[string]interface{}{
			"name":    s.config.ServerName,
			"version": s.config.ServerVersion,
		},
		"capabilities": map[string]interface{}{
			"tools":     map[string]interface{}{},
			"resources": map[string]interface{}{},
		},
	}

	return &mcpwire.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

// handleToolsList handles the "tools/list" method.
func (s *Server) handleToolsList(ctx context.Context, req *mcpwire.JSONRPCRequest) *mcpwire.JSONRPCResponse {
	tools := s.tools.ListTools()

	result := map[string]interface{}{
		"tools": tools,
	}

	return &mcpwire.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

// handleToolsCall handles the "tools/call" method.
func (s *Server) handleToolsCall(ctx context.Context, req *mcpwire.JSONRPCRequest) *mcpwire.JSONRPCResponse {
	// Parse parameters
	params, ok := req.Params.(map[string]interface{})
	if !ok {
		return s.makeErrorResponse(req.ID, mcpwire.InvalidParams, "Invalid params", "Params must be an object")
	}

	name, ok := params["name"].(string)
	if !ok {
		return s.makeErrorResponse(req.ID, mcpwire.InvalidParams, "Invalid params", "Missing or invalid 'name' parameter")
	}

	arguments, _ := params["arguments"].(map[string]interface{})

	// Extract token from params or context
	token := extractTokenFromParams(params)
	if token == "" {
		token = TokenFromContext(ctx)
	}

	// Check authorization before executing tool. AuthorizeTool returns a
	// context enriched with the validated AuthorizedContext (scp -> RBAC,
	// tenant_id -> RLS) when the platform-token claims path is in effect, so
	// downstream tool handlers can enforce tenant isolation uniformly.
	authCtx, authErr := s.authChecker.AuthorizeTool(ctx, name, token)
	if authErr != nil {
		return s.handleAuthError(req.ID, authErr)
	}
	ctx = authCtx

	// Execute tool
	result, err := s.tools.ExecuteTool(ctx, name, arguments)
	if err != nil {
		// Pass through the actual error message so clients can detect
		// specific error conditions (e.g., "not implemented" for graceful skips).
		// The tool name is included in the data field for debugging context.
		return s.makeErrorResponse(req.ID, mcpwire.InternalError, err.Error(), name)
	}

	return &mcpwire.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

// handleResourcesList handles the "resources/list" method.
func (s *Server) handleResourcesList(ctx context.Context, req *mcpwire.JSONRPCRequest) *mcpwire.JSONRPCResponse {
	resources := s.resources.ListResources()

	result := map[string]interface{}{
		"resources": resources,
	}

	return &mcpwire.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

// handleResourcesRead handles the "resources/read" method.
func (s *Server) handleResourcesRead(ctx context.Context, req *mcpwire.JSONRPCRequest) *mcpwire.JSONRPCResponse {
	// Parse parameters
	params, ok := req.Params.(map[string]interface{})
	if !ok {
		return s.makeErrorResponse(req.ID, mcpwire.InvalidParams, "Invalid params", "Params must be an object")
	}

	uri, ok := params["uri"].(string)
	if !ok {
		return s.makeErrorResponse(req.ID, mcpwire.InvalidParams, "Invalid params", "Missing or invalid 'uri' parameter")
	}

	// Read resource
	result, err := s.resources.ReadResource(ctx, uri)
	if err != nil {
		// Pass through the actual error message so clients can detect
		// specific error conditions (e.g., "not implemented" for graceful skips).
		// The resource URI is included in the data field for debugging context.
		return s.makeErrorResponse(req.ID, mcpwire.InternalError, err.Error(), uri)
	}

	return &mcpwire.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

// handlePing handles the "ping" method for connection testing.
func (s *Server) handlePing(ctx context.Context, req *mcpwire.JSONRPCRequest) *mcpwire.JSONRPCResponse {
	return &mcpwire.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  map[string]interface{}{"pong": true},
	}
}

// handleAuthError converts an authorization error to a JSON-RPC error response.
func (s *Server) handleAuthError(id interface{}, authErr *AuthorizationError) *mcpwire.JSONRPCResponse {
	var code int
	switch authErr.Type {
	case AuthErrorMissingToken:
		code = mcpwire.AuthenticationRequired
	case AuthErrorInvalidToken:
		code = mcpwire.InvalidToken
	case AuthErrorPermissionDenied:
		code = mcpwire.PermissionDenied
	default:
		code = mcpwire.InternalError
	}

	return s.makeErrorResponse(id, code, authErr.Message, "")
}

// makeErrorResponse creates a JSON-RPC error response.
func (s *Server) makeErrorResponse(id interface{}, code int, message string, data string) *mcpwire.JSONRPCResponse {
	var dataVal interface{}
	if data != "" {
		dataVal = data
	}
	return &mcpwire.JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &mcpwire.JSONRPCError{
			Code:    code,
			Message: message,
			Data:    dataVal,
		},
	}
}

// extractTokenFromHTTPRequest extracts the authentication token from HTTP headers.
func extractTokenFromHTTPRequest(r *http.Request) string {
	// Check Authorization header (Bearer token)
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			return strings.TrimPrefix(authHeader, "Bearer ")
		}
		return authHeader
	}

	// Check X-Auth-Token header
	if token := r.Header.Get("X-Auth-Token"); token != "" {
		return token
	}

	return ""
}

// extractTokenFromParams extracts the authentication token from MCP params.
func extractTokenFromParams(params map[string]interface{}) string {
	// Check for token in arguments
	if args, ok := params["arguments"].(map[string]interface{}); ok {
		if token, ok := args["_token"].(string); ok {
			return token
		}
		if token, ok := args["accessToken"].(string); ok {
			return token
		}
	}

	// Check for token at top level
	if token, ok := params["_token"].(string); ok {
		return token
	}

	return ""
}
