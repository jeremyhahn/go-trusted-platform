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

//go:build integration

package container

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// Environment Variables
// =============================================================================

const (
	// EnvPlatformctlBinary is the path to the platformctl binary.
	EnvPlatformctlBinary = "PLATFORMCTL_BINARY"

	// EnvPlatformdSocket is the Unix socket path for platformd.
	EnvPlatformdSocket = "PLATFORMD_SOCKET"

	// EnvPlatformAPIEndpoint is the REST API endpoint.
	EnvPlatformAPIEndpoint = "PLATFORM_API_ENDPOINT"

	// EnvPlatformdGRPCEndpoint is the gRPC endpoint.
	EnvPlatformdGRPCEndpoint = "PLATFORMD_GRPC_ENDPOINT"

	// EnvPlatformdQUICEndpoint is the QUIC endpoint.
	EnvPlatformdQUICEndpoint = "PLATFORMD_QUIC_ENDPOINT"

	// EnvPlatformdMCPEndpoint is the MCP endpoint.
	EnvPlatformdMCPEndpoint = "PLATFORMD_MCP_ENDPOINT"

	// DefaultPlatformctlBinary is the default binary name.
	DefaultPlatformctlBinary = "platformctl"

	// DefaultPlatformdSocket is the default Unix socket path.
	DefaultPlatformdSocket = "/run/platformd.sock"

	// DefaultPlatformAPIEndpoint is the default REST API endpoint.
	DefaultPlatformAPIEndpoint = "127.0.0.1:8443"

	// DefaultPlatformdGRPCEndpoint is the default gRPC endpoint.
	DefaultPlatformdGRPCEndpoint = "127.0.0.1:10443"

	// DefaultPlatformdQUICEndpoint is the default QUIC endpoint.
	DefaultPlatformdQUICEndpoint = "127.0.0.1:9444"

	// DefaultPlatformdMCPEndpoint is the default MCP endpoint.
	DefaultPlatformdMCPEndpoint = "127.0.0.1:9445"

	// DefaultCommandTimeout is the default timeout for commands.
	DefaultCommandTimeout = 30 * time.Second
)

// =============================================================================
// Common Error Types
// =============================================================================

// ErrAdapterConnectionFailed is returned when adapter connection fails.
type ErrAdapterConnectionFailed struct {
	Adapter string
	URL     string
	Err     error
}

func (e ErrAdapterConnectionFailed) Error() string {
	return fmt.Sprintf("%s adapter connection to %s failed: %v", e.Adapter, e.URL, e.Err)
}

func (e ErrAdapterConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrCommandFailed is returned when a command execution fails.
type ErrCommandFailed struct {
	Command string
	Output  string
	Err     error
}

func (e ErrCommandFailed) Error() string {
	if e.Output != "" {
		return fmt.Sprintf("command %q failed: %v (output: %s)", e.Command, e.Err, e.Output)
	}
	return fmt.Sprintf("command %q failed: %v", e.Command, e.Err)
}

func (e ErrCommandFailed) Unwrap() error {
	return e.Err
}

// ErrContainerNotFound is returned when a container cannot be found.
type ErrContainerNotFound struct {
	ID string
}

func (e ErrContainerNotFound) Error() string {
	return fmt.Sprintf("container not found: %s", e.ID)
}

// ErrInvalidResponse is returned when the response cannot be parsed.
type ErrInvalidResponse struct {
	Operation string
	Err       error
}

func (e ErrInvalidResponse) Error() string {
	return fmt.Sprintf("invalid response for %s: %v", e.Operation, e.Err)
}

func (e ErrInvalidResponse) Unwrap() error {
	return e.Err
}

// =============================================================================
// Compile-time interface checks
// =============================================================================

var (
	_ ContainerCommands = (*CLIAdapter)(nil)
	_ ContainerCommands = (*RESTAdapter)(nil)
	_ ContainerCommands = (*GRPCAdapter)(nil)
	_ ContainerCommands = (*QUICAdapter)(nil)
	_ ContainerCommands = (*MCPAdapter)(nil)
	_ ContainerCommands = (*UnixAdapter)(nil)
)

// =============================================================================
// REST Adapter Implementation
// =============================================================================

// RESTAdapter implements ContainerCommands using HTTP/REST calls.
type RESTAdapter struct {
	baseURL    string
	httpClient *http.Client
}

// NewRESTAdapter creates a new REST adapter for integration testing.
func NewRESTAdapter() *RESTAdapter {
	return &RESTAdapter{}
}

// Name returns the protocol adapter identifier.
func (r *RESTAdapter) Name() string {
	return "REST"
}

// Setup initializes the REST client.
func (r *RESTAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformAPIEndpoint)
	if endpoint == "" {
		endpoint = DefaultPlatformAPIEndpoint
	}
	r.baseURL = "http://" + endpoint

	r.httpClient = &http.Client{
		Timeout: DefaultCommandTimeout,
	}

	// Verify connectivity
	_, statusCode, err := r.doRequest(ctx, http.MethodGet, "/api/v1/health", nil)
	if err != nil {
		return ErrAdapterConnectionFailed{Adapter: "REST", URL: r.baseURL, Err: err}
	}
	if statusCode != http.StatusOK {
		return ErrAdapterConnectionFailed{Adapter: "REST", URL: r.baseURL, Err: fmt.Errorf("unexpected status: %d", statusCode)}
	}

	return nil
}

// Teardown cleans up REST client resources.
func (r *RESTAdapter) Teardown() error {
	if r.httpClient != nil {
		r.httpClient.CloseIdleConnections()
	}
	return nil
}

// doRequest performs an HTTP request.
func (r *RESTAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to marshal request: %w", err)
		}
		reqBody = bytes.NewReader(jsonBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, r.baseURL+path, reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

// handleResponse processes the response and checks for errors.
func (r *RESTAdapter) handleResponse(respBody []byte, statusCode int, target interface{}) error {
	if statusCode >= 400 {
		var errResp struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			msg := errResp.Error
			if msg == "" {
				msg = errResp.Message
			}
			if strings.Contains(strings.ToLower(msg), "not found") {
				return ErrContainerNotFound{ID: ""}
			}
			return fmt.Errorf("API error (%d): %s", statusCode, msg)
		}
		return fmt.Errorf("API error (%d): %s", statusCode, string(respBody))
	}

	if target != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, target); err != nil {
			return ErrInvalidResponse{Operation: "response", Err: err}
		}
	}

	return nil
}

// Create creates a new container via REST.
func (r *RESTAdapter) Create(ctx context.Context, opts CreateOptions) (*Container, error) {
	body, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/containers", opts)
	if err != nil {
		return nil, err
	}

	var result restContainerResponse
	if err := r.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toContainer(), nil
}

// Start starts a container via REST.
func (r *RESTAdapter) Start(ctx context.Context, id string) error {
	body, statusCode, err := r.doRequest(ctx, http.MethodPost, fmt.Sprintf("/api/v1/containers/%s/start", id), nil)
	if err != nil {
		return err
	}

	return r.handleResponse(body, statusCode, nil)
}

// Stop stops a container via REST.
func (r *RESTAdapter) Stop(ctx context.Context, id string, timeout time.Duration) error {
	req := map[string]interface{}{"timeout": int(timeout.Seconds())}
	body, statusCode, err := r.doRequest(ctx, http.MethodPost, fmt.Sprintf("/api/v1/containers/%s/stop", id), req)
	if err != nil {
		return err
	}

	return r.handleResponse(body, statusCode, nil)
}

// Remove removes a container via REST.
func (r *RESTAdapter) Remove(ctx context.Context, id string, force bool) error {
	path := fmt.Sprintf("/api/v1/containers/%s", id)
	if force {
		path += "?force=true"
	}
	body, statusCode, err := r.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}

	return r.handleResponse(body, statusCode, nil)
}

// Get retrieves a container via REST.
func (r *RESTAdapter) Get(ctx context.Context, id string) (*Container, error) {
	body, statusCode, err := r.doRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/containers/%s", id), nil)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusNotFound {
		return nil, ErrContainerNotFound{ID: id}
	}

	var result restContainerResponse
	if err := r.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toContainer(), nil
}

// List lists containers via REST.
func (r *RESTAdapter) List(ctx context.Context, opts ListOptions) ([]*Container, error) {
	path := "/api/v1/containers"
	params := make([]string, 0)

	if opts.All {
		params = append(params, "all=true")
	}
	if opts.Limit > 0 {
		params = append(params, fmt.Sprintf("limit=%d", opts.Limit))
	}
	if opts.StateFilter != "" {
		params = append(params, fmt.Sprintf("state=%s", opts.StateFilter))
	}
	if opts.NameFilter != "" {
		params = append(params, fmt.Sprintf("name=%s", opts.NameFilter))
	}

	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}

	body, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result restContainerListResponse
	if err := r.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	containers := make([]*Container, len(result.Containers))
	for i, c := range result.Containers {
		containers[i] = c.toContainer()
	}

	return containers, nil
}

// Logs retrieves container logs via REST.
func (r *RESTAdapter) Logs(ctx context.Context, id string, opts LogOptions) ([]string, error) {
	path := fmt.Sprintf("/api/v1/containers/%s/logs", id)
	params := make([]string, 0)

	if opts.Tail > 0 {
		params = append(params, fmt.Sprintf("tail=%d", opts.Tail))
	}
	if opts.Timestamps {
		params = append(params, "timestamps=true")
	}

	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}

	body, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result restLogsResponse
	if err := r.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.Lines, nil
}

// Attest performs attestation via REST.
func (r *RESTAdapter) Attest(ctx context.Context, id string) (*AttestationReport, error) {
	body, statusCode, err := r.doRequest(ctx, http.MethodPost, fmt.Sprintf("/api/v1/containers/%s/attest", id), nil)
	if err != nil {
		return nil, err
	}

	var result restAttestationResponse
	if err := r.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toAttestationReport(), nil
}

// =============================================================================
// gRPC Adapter Implementation
// =============================================================================

// GRPCAdapter implements ContainerCommands using the compute SDK client over gRPC.
type GRPCAdapter struct {
	endpoint string
	conn     *grpc.ClientConn
	client   *computesvc.Client
}

// NewGRPCAdapter creates a new gRPC adapter for integration testing.
func NewGRPCAdapter() *GRPCAdapter {
	return &GRPCAdapter{}
}

// Name returns the protocol adapter identifier.
func (g *GRPCAdapter) Name() string {
	return "gRPC"
}

// Setup initializes the gRPC connection.
func (g *GRPCAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformdGRPCEndpoint)
	if endpoint == "" {
		endpoint = DefaultPlatformdGRPCEndpoint
	}
	g.endpoint = endpoint

	conn, err := grpc.DialContext(ctx, endpoint,
		helpers.GRPCTransportCredentials(),
		grpc.WithBlock(),
	)
	if err != nil {
		return ErrAdapterConnectionFailed{Adapter: "gRPC", URL: endpoint, Err: err}
	}

	g.conn = conn
	g.client = computesvc.NewClientFromGRPC(pb.NewComputeServiceClient(conn))
	return nil
}

// Teardown closes the gRPC connection.
func (g *GRPCAdapter) Teardown() error {
	if g.conn != nil {
		return g.conn.Close()
	}
	return nil
}

// Create creates a new container via the SDK client over gRPC.
func (g *GRPCAdapter) Create(ctx context.Context, opts CreateOptions) (*Container, error) {
	created, err := g.client.CreateContainerDomain(ctx, createContainerParamsFromOptions(opts))
	if err != nil {
		return nil, ErrCommandFailed{Command: "gRPC CreateContainer", Err: err}
	}
	if created == nil {
		return nil, ErrInvalidResponse{Operation: "CreateContainer", Err: fmt.Errorf("empty container in response")}
	}

	return containerFromDomain(created), nil
}

// Start starts a container via the SDK client over gRPC.
func (g *GRPCAdapter) Start(ctx context.Context, id string) error {
	status, err := g.client.StartContainerDomain(ctx, id)
	if err != nil {
		return ErrCommandFailed{Command: "gRPC StartContainer", Err: err}
	}
	if status != nil && !status.Success {
		return ErrCommandFailed{Command: "gRPC StartContainer", Output: status.Message, Err: fmt.Errorf("server reported failure")}
	}
	return nil
}

// Stop stops a container via the SDK client over gRPC.
func (g *GRPCAdapter) Stop(ctx context.Context, id string, timeout time.Duration) error {
	status, err := g.client.StopContainerDomain(ctx, &computesvc.StopContainerParams{
		ID:             id,
		TimeoutSeconds: uint32(timeout / time.Second),
	})
	if err != nil {
		return ErrCommandFailed{Command: "gRPC StopContainer", Err: err}
	}
	if status != nil && !status.Success {
		return ErrCommandFailed{Command: "gRPC StopContainer", Output: status.Message, Err: fmt.Errorf("server reported failure")}
	}
	return nil
}

// Remove removes a container via the SDK client over gRPC.
func (g *GRPCAdapter) Remove(ctx context.Context, id string, force bool) error {
	status, err := g.client.DeleteContainerDomain(ctx, &computesvc.DeleteContainerParams{
		ID:    id,
		Force: force,
	})
	if err != nil {
		return ErrCommandFailed{Command: "gRPC DeleteContainer", Err: err}
	}
	if status != nil && !status.Success {
		return ErrCommandFailed{Command: "gRPC DeleteContainer", Output: status.Message, Err: fmt.Errorf("server reported failure")}
	}
	return nil
}

// Get retrieves a container via the SDK client over gRPC.
func (g *GRPCAdapter) Get(ctx context.Context, id string) (*Container, error) {
	found, err := g.client.GetContainerDomain(ctx, id)
	if err != nil {
		return nil, ErrCommandFailed{Command: "gRPC GetContainer", Err: err}
	}
	if found == nil {
		return nil, ErrContainerNotFound{ID: id}
	}

	return containerFromDomain(found), nil
}

// List lists containers via the SDK client over gRPC.
func (g *GRPCAdapter) List(ctx context.Context, opts ListOptions) ([]*Container, error) {
	params := &computesvc.ListContainersParams{
		Labels:     opts.Filters,
		NameFilter: opts.NameFilter,
	}
	if opts.Limit > 0 {
		params.PageSize = uint32(opts.Limit)
	}
	if opts.StateFilter != "" {
		if state, ok := computesvc.ParseContainerState(string(opts.StateFilter)); ok {
			params.States = []computesvc.ContainerState{state}
		}
	}

	result, err := g.client.ListContainersDomain(ctx, params)
	if err != nil {
		return nil, ErrCommandFailed{Command: "gRPC ListContainers", Err: err}
	}
	if result == nil {
		return []*Container{}, nil
	}

	containers := make([]*Container, 0, len(result.Containers))
	for _, c := range result.Containers {
		containers = append(containers, containerFromDomain(c))
	}
	return containers, nil
}

// Logs retrieves container logs via the SDK client over gRPC.
func (g *GRPCAdapter) Logs(ctx context.Context, id string, opts LogOptions) ([]string, error) {
	params := &computesvc.GetContainerLogsParams{
		ID:         id,
		Stdout:     opts.Stdout,
		Stderr:     opts.Stderr,
		Since:      opts.Since,
		Until:      opts.Until,
		Timestamps: opts.Timestamps,
	}
	if opts.Tail > 0 {
		params.TailLines = uint32(opts.Tail)
	}

	entries, err := g.client.GetContainerLogsBatch(ctx, params)
	if err != nil {
		return nil, ErrCommandFailed{Command: "gRPC GetContainerLogs", Err: err}
	}

	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry != nil {
			lines = append(lines, entry.Message)
		}
	}
	return lines, nil
}

// Attest performs quote-based container attestation via the SDK client over
// gRPC. It returns the same quote/signature report shape as the REST
// POST /api/v1/containers/{id}/attest route.
func (g *GRPCAdapter) Attest(ctx context.Context, id string) (*AttestationReport, error) {
	report, err := g.client.AttestContainerDomain(ctx, &computesvc.AttestContainerParams{ID: id})
	if err != nil {
		return nil, ErrCommandFailed{Command: "gRPC AttestContainer", Err: err}
	}
	if report == nil {
		return nil, ErrInvalidResponse{Operation: "AttestContainer", Err: fmt.Errorf("empty attestation report in response")}
	}

	return attestationReportFromDomain(report), nil
}

// =============================================================================
// SDK Domain Mapping Helpers
// =============================================================================

// createContainerParamsFromOptions converts CreateOptions to SDK CreateContainerParams.
func createContainerParamsFromOptions(opts CreateOptions) *computesvc.CreateContainerParams {
	params := &computesvc.CreateContainerParams{
		Name:           opts.Name,
		Image:          opts.Image,
		Command:        opts.Command,
		Labels:         opts.Labels,
		WorkingDir:     opts.WorkingDir,
		User:           opts.User,
		Privileged:     opts.Privileged,
		Network:        opts.NetworkMode,
		AttestOnCreate: opts.AttestOnCreate,
	}

	for name, value := range opts.Environment {
		params.Env = append(params.Env, &computesvc.EnvVar{Name: name, Value: value})
	}

	for _, m := range opts.Mounts {
		params.Volumes = append(params.Volumes, &computesvc.VolumeMount{
			Source:      m.Source,
			Destination: m.Target,
			Readonly:    m.ReadOnly,
		})
	}

	for _, p := range opts.ExposedPorts {
		params.Ports = append(params.Ports, &computesvc.PortMapping{
			HostPort:      uint32(p.HostPort),
			ContainerPort: uint32(p.ContainerPort),
			Protocol:      p.Protocol,
		})
	}

	if opts.RestartPolicy != "" {
		if policy, ok := computesvc.ParseRestartPolicy(opts.RestartPolicy); ok {
			params.RestartPolicy = policy
		}
	}

	if opts.Memory > 0 || opts.CPUs > 0 {
		params.Resources = &computesvc.ResourceLimits{}
		if opts.Memory > 0 {
			params.Resources.MaxMemoryMB = uint64(opts.Memory) / (1024 * 1024)
		}
		if opts.CPUs > 0 {
			params.Resources.MaxCPUs = uint32(opts.CPUs)
		}
	}

	return params
}

// containerFromDomain converts a SDK domain Container to the test Container type.
func containerFromDomain(c *computesvc.Container) *Container {
	if c == nil {
		return nil
	}

	result := &Container{
		ID:        c.ID,
		State:     ContainerState(strings.ToLower(string(c.State))),
		ExitCode:  int(c.ExitCode),
		CreatedAt: c.CreatedAt,
		StartedAt: c.StartedAt,
		StoppedAt: c.FinishedAt,
	}

	if c.Config != nil {
		result.Name = c.Config.Name
		result.Image = c.Config.Image
		result.ImageID = c.Config.ImageHash
		result.Labels = c.Config.Labels
		if len(c.Config.Env) > 0 {
			result.Environment = make(map[string]string, len(c.Config.Env))
			for _, env := range c.Config.Env {
				if env != nil {
					result.Environment[env.Name] = env.Value
				}
			}
		}
	}

	return result
}

// attestationReportFromDomain converts a SDK domain ContainerAttestation to the
// test AttestationReport type. Digest fields are hex-encoded to match the REST
// route's presentation.
func attestationReportFromDomain(report *computesvc.ContainerAttestation) *AttestationReport {
	if report == nil {
		return nil
	}

	result := &AttestationReport{
		ContainerID:   report.ContainerID,
		ContainerName: report.ContainerName,
		ImageDigest:   hex.EncodeToString(report.ImageDigest),
		ConfigDigest:  hex.EncodeToString(report.ConfigDigest),
		Quote:         report.Quote,
		Signature:     report.Signature,
		Timestamp:     report.Timestamp,
		Verified:      report.Verified,
	}

	if len(report.PCRValues) > 0 {
		result.PCRValues = make(map[int][]byte, len(report.PCRValues))
		for _, pv := range report.PCRValues {
			if pv != nil {
				result.PCRValues[int(pv.Index)] = pv.Value
			}
		}
	}

	return result
}

// =============================================================================
// QUIC Adapter Implementation
// =============================================================================

// QUICAdapter implements ContainerCommands using QUIC protocol.
type QUICAdapter struct {
	endpoint string
}

// NewQUICAdapter creates a new QUIC adapter for integration testing.
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{}
}

// Name returns the protocol adapter identifier.
func (q *QUICAdapter) Name() string {
	return "QUIC"
}

// Setup initializes the QUIC connection.
func (q *QUICAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformdQUICEndpoint)
	if endpoint == "" {
		endpoint = DefaultPlatformdQUICEndpoint
	}
	q.endpoint = endpoint

	// TODO: Implement QUIC connection verification
	return nil
}

// Teardown closes the QUIC connection.
func (q *QUICAdapter) Teardown() error {
	return nil
}

// Create creates a new container via QUIC.
func (q *QUICAdapter) Create(ctx context.Context, opts CreateOptions) (*Container, error) {
	return nil, fmt.Errorf("QUIC Create not yet implemented")
}

// Start starts a container via QUIC.
func (q *QUICAdapter) Start(ctx context.Context, id string) error {
	return fmt.Errorf("QUIC Start not yet implemented")
}

// Stop stops a container via QUIC.
func (q *QUICAdapter) Stop(ctx context.Context, id string, timeout time.Duration) error {
	return fmt.Errorf("QUIC Stop not yet implemented")
}

// Remove removes a container via QUIC.
func (q *QUICAdapter) Remove(ctx context.Context, id string, force bool) error {
	return fmt.Errorf("QUIC Remove not yet implemented")
}

// Get retrieves a container via QUIC.
func (q *QUICAdapter) Get(ctx context.Context, id string) (*Container, error) {
	return nil, fmt.Errorf("QUIC Get not yet implemented")
}

// List lists containers via QUIC.
func (q *QUICAdapter) List(ctx context.Context, opts ListOptions) ([]*Container, error) {
	return nil, fmt.Errorf("QUIC List not yet implemented")
}

// Logs retrieves container logs via QUIC.
func (q *QUICAdapter) Logs(ctx context.Context, id string, opts LogOptions) ([]string, error) {
	return nil, fmt.Errorf("QUIC Logs not yet implemented")
}

// Attest performs attestation via QUIC.
func (q *QUICAdapter) Attest(ctx context.Context, id string) (*AttestationReport, error) {
	return nil, fmt.Errorf("QUIC Attest not yet implemented")
}

// =============================================================================
// MCP Adapter Implementation
// =============================================================================

// MCPAdapter implements ContainerCommands using Model Context Protocol.
type MCPAdapter struct {
	endpoint string
}

// NewMCPAdapter creates a new MCP adapter for integration testing.
func NewMCPAdapter() *MCPAdapter {
	return &MCPAdapter{}
}

// Name returns the protocol adapter identifier.
func (m *MCPAdapter) Name() string {
	return "MCP"
}

// Setup initializes the MCP connection.
func (m *MCPAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformdMCPEndpoint)
	if endpoint == "" {
		endpoint = DefaultPlatformdMCPEndpoint
	}
	m.endpoint = endpoint

	// TODO: Implement MCP connection verification
	return nil
}

// Teardown closes the MCP connection.
func (m *MCPAdapter) Teardown() error {
	return nil
}

// Create creates a new container via MCP.
func (m *MCPAdapter) Create(ctx context.Context, opts CreateOptions) (*Container, error) {
	return nil, fmt.Errorf("MCP Create not yet implemented")
}

// Start starts a container via MCP.
func (m *MCPAdapter) Start(ctx context.Context, id string) error {
	return fmt.Errorf("MCP Start not yet implemented")
}

// Stop stops a container via MCP.
func (m *MCPAdapter) Stop(ctx context.Context, id string, timeout time.Duration) error {
	return fmt.Errorf("MCP Stop not yet implemented")
}

// Remove removes a container via MCP.
func (m *MCPAdapter) Remove(ctx context.Context, id string, force bool) error {
	return fmt.Errorf("MCP Remove not yet implemented")
}

// Get retrieves a container via MCP.
func (m *MCPAdapter) Get(ctx context.Context, id string) (*Container, error) {
	return nil, fmt.Errorf("MCP Get not yet implemented")
}

// List lists containers via MCP.
func (m *MCPAdapter) List(ctx context.Context, opts ListOptions) ([]*Container, error) {
	return nil, fmt.Errorf("MCP List not yet implemented")
}

// Logs retrieves container logs via MCP.
func (m *MCPAdapter) Logs(ctx context.Context, id string, opts LogOptions) ([]string, error) {
	return nil, fmt.Errorf("MCP Logs not yet implemented")
}

// Attest performs attestation via MCP.
func (m *MCPAdapter) Attest(ctx context.Context, id string) (*AttestationReport, error) {
	return nil, fmt.Errorf("MCP Attest not yet implemented")
}

// =============================================================================
// Unix Socket Adapter Implementation
// =============================================================================

// UnixAdapter implements ContainerCommands using Unix socket.
type UnixAdapter struct {
	socketPath string
	httpClient *http.Client
}

// NewUnixAdapter creates a new Unix socket adapter for integration testing.
func NewUnixAdapter() *UnixAdapter {
	return &UnixAdapter{}
}

// Name returns the protocol adapter identifier.
func (u *UnixAdapter) Name() string {
	return "Unix"
}

// Setup initializes the Unix socket connection.
func (u *UnixAdapter) Setup(ctx context.Context) error {
	socketPath := os.Getenv(EnvPlatformdSocket)
	if socketPath == "" {
		socketPath = DefaultPlatformdSocket
	}
	u.socketPath = socketPath

	// Create HTTP client that uses Unix socket
	u.httpClient = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", u.socketPath)
			},
		},
		Timeout: DefaultCommandTimeout,
	}

	// Verify socket exists
	if _, err := os.Stat(u.socketPath); os.IsNotExist(err) {
		return ErrAdapterConnectionFailed{Adapter: "Unix", URL: u.socketPath, Err: err}
	}

	return nil
}

// Teardown closes the Unix socket connection.
func (u *UnixAdapter) Teardown() error {
	if u.httpClient != nil {
		u.httpClient.CloseIdleConnections()
	}
	return nil
}

// doRequest performs an HTTP request over Unix socket.
func (u *UnixAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to marshal request: %w", err)
		}
		reqBody = bytes.NewReader(jsonBytes)
	}

	// Use http://localhost as dummy host - the transport uses Unix socket
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

// handleResponse processes the response.
func (u *UnixAdapter) handleResponse(respBody []byte, statusCode int, target interface{}) error {
	if statusCode >= 400 {
		var errResp struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			msg := errResp.Error
			if msg == "" {
				msg = errResp.Message
			}
			if strings.Contains(strings.ToLower(msg), "not found") {
				return ErrContainerNotFound{ID: ""}
			}
			return fmt.Errorf("API error (%d): %s", statusCode, msg)
		}
		return fmt.Errorf("API error (%d): %s", statusCode, string(respBody))
	}

	if target != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, target); err != nil {
			return ErrInvalidResponse{Operation: "response", Err: err}
		}
	}

	return nil
}

// Create creates a new container via Unix socket.
func (u *UnixAdapter) Create(ctx context.Context, opts CreateOptions) (*Container, error) {
	body, statusCode, err := u.doRequest(ctx, http.MethodPost, "/api/v1/containers", opts)
	if err != nil {
		return nil, err
	}

	var result restContainerResponse
	if err := u.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toContainer(), nil
}

// Start starts a container via Unix socket.
func (u *UnixAdapter) Start(ctx context.Context, id string) error {
	body, statusCode, err := u.doRequest(ctx, http.MethodPost, fmt.Sprintf("/api/v1/containers/%s/start", id), nil)
	if err != nil {
		return err
	}

	return u.handleResponse(body, statusCode, nil)
}

// Stop stops a container via Unix socket.
func (u *UnixAdapter) Stop(ctx context.Context, id string, timeout time.Duration) error {
	req := map[string]interface{}{"timeout": int(timeout.Seconds())}
	body, statusCode, err := u.doRequest(ctx, http.MethodPost, fmt.Sprintf("/api/v1/containers/%s/stop", id), req)
	if err != nil {
		return err
	}

	return u.handleResponse(body, statusCode, nil)
}

// Remove removes a container via Unix socket.
func (u *UnixAdapter) Remove(ctx context.Context, id string, force bool) error {
	path := fmt.Sprintf("/api/v1/containers/%s", id)
	if force {
		path += "?force=true"
	}
	body, statusCode, err := u.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}

	return u.handleResponse(body, statusCode, nil)
}

// Get retrieves a container via Unix socket.
func (u *UnixAdapter) Get(ctx context.Context, id string) (*Container, error) {
	body, statusCode, err := u.doRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/containers/%s", id), nil)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusNotFound {
		return nil, ErrContainerNotFound{ID: id}
	}

	var result restContainerResponse
	if err := u.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toContainer(), nil
}

// List lists containers via Unix socket.
func (u *UnixAdapter) List(ctx context.Context, opts ListOptions) ([]*Container, error) {
	path := "/api/v1/containers"
	params := make([]string, 0)

	if opts.All {
		params = append(params, "all=true")
	}
	if opts.Limit > 0 {
		params = append(params, fmt.Sprintf("limit=%d", opts.Limit))
	}

	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}

	body, statusCode, err := u.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result restContainerListResponse
	if err := u.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	containers := make([]*Container, len(result.Containers))
	for i, c := range result.Containers {
		containers[i] = c.toContainer()
	}

	return containers, nil
}

// Logs retrieves container logs via Unix socket.
func (u *UnixAdapter) Logs(ctx context.Context, id string, opts LogOptions) ([]string, error) {
	path := fmt.Sprintf("/api/v1/containers/%s/logs", id)
	params := make([]string, 0)

	if opts.Tail > 0 {
		params = append(params, fmt.Sprintf("tail=%d", opts.Tail))
	}

	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}

	body, statusCode, err := u.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result restLogsResponse
	if err := u.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.Lines, nil
}

// Attest performs attestation via Unix socket.
func (u *UnixAdapter) Attest(ctx context.Context, id string) (*AttestationReport, error) {
	body, statusCode, err := u.doRequest(ctx, http.MethodPost, fmt.Sprintf("/api/v1/containers/%s/attest", id), nil)
	if err != nil {
		return nil, err
	}

	var result restAttestationResponse
	if err := u.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toAttestationReport(), nil
}

// =============================================================================
// Response Types for JSON Parsing
// =============================================================================

// cliContainerResponse represents CLI JSON output for a container.
type cliContainerResponse struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Image       string            `json:"image"`
	ImageID     string            `json:"image_id,omitempty"`
	State       string            `json:"state"`
	PID         int               `json:"pid,omitempty"`
	ExitCode    int               `json:"exit_code,omitempty"`
	CreatedAt   string            `json:"created_at"`
	StartedAt   string            `json:"started_at,omitempty"`
	StoppedAt   string            `json:"stopped_at,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
}

func (r *cliContainerResponse) toContainer() *Container {
	c := &Container{
		ID:          r.ID,
		Name:        r.Name,
		Image:       r.Image,
		ImageID:     r.ImageID,
		State:       ContainerState(r.State),
		PID:         r.PID,
		ExitCode:    r.ExitCode,
		Labels:      r.Labels,
		Environment: r.Environment,
	}

	if r.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, r.CreatedAt); err == nil {
			c.CreatedAt = t
		}
	}
	if r.StartedAt != "" {
		if t, err := time.Parse(time.RFC3339, r.StartedAt); err == nil {
			c.StartedAt = t
		}
	}
	if r.StoppedAt != "" {
		if t, err := time.Parse(time.RFC3339, r.StoppedAt); err == nil {
			c.StoppedAt = t
		}
	}

	return c
}

// cliContainerListResponse represents CLI JSON output for container list.
type cliContainerListResponse struct {
	Containers []cliContainerResponse `json:"containers"`
	Count      int                    `json:"count"`
}

// cliLogsResponse represents CLI JSON output for container logs.
type cliLogsResponse struct {
	ContainerID string   `json:"container_id"`
	Lines       []string `json:"lines"`
}

// cliAttestationResponse represents CLI JSON output for attestation.
type cliAttestationResponse struct {
	ContainerID   string             `json:"container_id"`
	ContainerName string             `json:"container_name"`
	ImageDigest   string             `json:"image_digest"`
	ConfigDigest  string             `json:"config_digest"`
	Quote         string             `json:"quote"`
	Signature     string             `json:"signature"`
	PCRValues     map[int]string     `json:"pcr_values,omitempty"`
	Timestamp     string             `json:"timestamp"`
	Verified      bool               `json:"verified"`
	Nonce         string             `json:"nonce,omitempty"`
	Log           []measurementEntry `json:"log,omitempty"`
}

type measurementEntry struct {
	PCRIndex  int    `json:"pcr_index"`
	EventType string `json:"event_type"`
	Digest    string `json:"digest"`
	Data      string `json:"data,omitempty"`
	Timestamp string `json:"timestamp"`
}

func (r *cliAttestationResponse) toAttestationReport() *AttestationReport {
	report := &AttestationReport{
		ContainerID:   r.ContainerID,
		ContainerName: r.ContainerName,
		ImageDigest:   r.ImageDigest,
		ConfigDigest:  r.ConfigDigest,
		Verified:      r.Verified,
	}

	if r.Quote != "" {
		report.Quote, _ = base64.StdEncoding.DecodeString(r.Quote)
	}
	if r.Signature != "" {
		report.Signature, _ = base64.StdEncoding.DecodeString(r.Signature)
	}
	if r.Nonce != "" {
		report.Nonce, _ = base64.StdEncoding.DecodeString(r.Nonce)
	}
	if r.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339, r.Timestamp); err == nil {
			report.Timestamp = t
		}
	}

	if len(r.PCRValues) > 0 {
		report.PCRValues = make(map[int][]byte)
		for k, v := range r.PCRValues {
			report.PCRValues[k], _ = base64.StdEncoding.DecodeString(v)
		}
	}

	if len(r.Log) > 0 {
		report.Log = make([]MeasurementLogEntry, len(r.Log))
		for i, e := range r.Log {
			report.Log[i] = MeasurementLogEntry{
				PCRIndex:  e.PCRIndex,
				EventType: e.EventType,
			}
			if e.Digest != "" {
				report.Log[i].Digest, _ = base64.StdEncoding.DecodeString(e.Digest)
			}
			if e.Data != "" {
				report.Log[i].Data, _ = base64.StdEncoding.DecodeString(e.Data)
			}
			if e.Timestamp != "" {
				if t, err := time.Parse(time.RFC3339, e.Timestamp); err == nil {
					report.Log[i].Timestamp = t
				}
			}
		}
	}

	return report
}

// restContainerResponse represents REST API JSON output for a container.
type restContainerResponse struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Image       string            `json:"image"`
	ImageID     string            `json:"image_id,omitempty"`
	State       string            `json:"state"`
	PID         int               `json:"pid,omitempty"`
	ExitCode    int               `json:"exit_code,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	StartedAt   time.Time         `json:"started_at,omitempty"`
	StoppedAt   time.Time         `json:"stopped_at,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
}

func (r *restContainerResponse) toContainer() *Container {
	return &Container{
		ID:          r.ID,
		Name:        r.Name,
		Image:       r.Image,
		ImageID:     r.ImageID,
		State:       ContainerState(r.State),
		PID:         r.PID,
		ExitCode:    r.ExitCode,
		CreatedAt:   r.CreatedAt,
		StartedAt:   r.StartedAt,
		StoppedAt:   r.StoppedAt,
		Labels:      r.Labels,
		Environment: r.Environment,
	}
}

// restContainerListResponse represents REST API JSON output for container list.
type restContainerListResponse struct {
	Containers []restContainerResponse `json:"containers"`
	Count      int                     `json:"count"`
}

// restLogsResponse represents REST API JSON output for container logs.
type restLogsResponse struct {
	ContainerID string   `json:"container_id"`
	Lines       []string `json:"lines"`
	Logs        string   `json:"logs,omitempty"`
}

// restAttestationResponse represents REST API JSON output for attestation.
type restAttestationResponse struct {
	ContainerID   string             `json:"container_id"`
	ContainerName string             `json:"container_name"`
	ImageDigest   string             `json:"image_digest"`
	ConfigDigest  string             `json:"config_digest"`
	Quote         string             `json:"quote"`
	Signature     string             `json:"signature"`
	PCRValues     map[int]string     `json:"pcr_values,omitempty"`
	Timestamp     time.Time          `json:"timestamp"`
	Verified      bool               `json:"verified"`
	Nonce         string             `json:"nonce,omitempty"`
	Log           []measurementEntry `json:"log,omitempty"`
}

func (r *restAttestationResponse) toAttestationReport() *AttestationReport {
	report := &AttestationReport{
		ContainerID:   r.ContainerID,
		ContainerName: r.ContainerName,
		ImageDigest:   r.ImageDigest,
		ConfigDigest:  r.ConfigDigest,
		Verified:      r.Verified,
		Timestamp:     r.Timestamp,
	}

	if r.Quote != "" {
		report.Quote, _ = base64.StdEncoding.DecodeString(r.Quote)
	}
	if r.Signature != "" {
		report.Signature, _ = base64.StdEncoding.DecodeString(r.Signature)
	}
	if r.Nonce != "" {
		report.Nonce, _ = base64.StdEncoding.DecodeString(r.Nonce)
	}

	if len(r.PCRValues) > 0 {
		report.PCRValues = make(map[int][]byte)
		for k, v := range r.PCRValues {
			report.PCRValues[k], _ = base64.StdEncoding.DecodeString(v)
		}
	}

	if len(r.Log) > 0 {
		report.Log = make([]MeasurementLogEntry, len(r.Log))
		for i, e := range r.Log {
			report.Log[i] = MeasurementLogEntry{
				PCRIndex:  e.PCRIndex,
				EventType: e.EventType,
			}
			if e.Digest != "" {
				report.Log[i].Digest, _ = base64.StdEncoding.DecodeString(e.Digest)
			}
			if e.Data != "" {
				report.Log[i].Data, _ = base64.StdEncoding.DecodeString(e.Data)
			}
			if e.Timestamp != "" {
				if t, err := time.Parse(time.RFC3339, e.Timestamp); err == nil {
					report.Log[i].Timestamp = t
				}
			}
		}
	}

	return report
}
