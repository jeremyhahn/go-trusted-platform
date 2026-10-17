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
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
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

// RESTAdapter implements ContainerCommands through the SDK REST transport,
// which maps each ComputeService RPC onto the /api/v1/compute/containers
// routes pkg/api/rest/compute_handlers.go serves.
type RESTAdapter struct {
	GRPCAdapter
}

// NewRESTAdapter creates a new REST adapter for integration testing.
func NewRESTAdapter() *RESTAdapter {
	return &RESTAdapter{}
}

// Name returns the protocol adapter identifier.
func (r *RESTAdapter) Name() string {
	return "REST"
}

// Setup connects the SDK over REST (HTTPS with the suite's mTLS identity).
func (r *RESTAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformAPIEndpoint)
	if endpoint == "" {
		endpoint = DefaultPlatformAPIEndpoint
	}
	return r.connectSDK(ctx, r.Name(), endpoint,
		platform.WithOnlyProtocol(platform.ProtocolREST),
		platform.WithRESTAddr(endpoint),
	)
}

// Logs has no REST route.
func (r *RESTAdapter) Logs(ctx context.Context, id string, opts LogOptions) ([]string, error) {
	return nil, noSurface(r.Name(), opLogs)
}

// =============================================================================
// gRPC Adapter Implementation
// =============================================================================

// GRPCAdapter implements ContainerCommands using the compute SDK client over
// gRPC. The REST, QUIC, MCP and Unix adapters embed it: they share its
// operations and differ only in how Setup reaches platformd.
type GRPCAdapter struct {
	endpoint  string
	transport string
	closer    io.Closer
	client    *computesvc.Client
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

	g.transport = g.Name()
	g.closer = conn
	g.client = computesvc.NewClientFromGRPC(pb.NewComputeServiceClient(conn))
	return nil
}

// connectSDK connects the platform SDK over one transport and binds the
// compute client to it.
func (g *GRPCAdapter) connectSDK(ctx context.Context, transport, endpoint string, opts ...platform.Option) error {
	opts = append(opts, platform.WithTLSConfig(helpers.TLSConfigOrInsecure()))
	client, err := platform.Connect(ctx, platform.NewOptions(opts...))
	if err != nil {
		return ErrAdapterConnectionFailed{Adapter: transport, URL: endpoint, Err: err}
	}
	g.endpoint = endpoint
	g.transport = transport
	g.closer = client
	g.client = computesvc.NewClientFromGRPC(client.Compute())
	return nil
}

// Teardown closes the connection to platformd.
func (g *GRPCAdapter) Teardown() error {
	if g.closer != nil {
		return g.closer.Close()
	}
	return nil
}

// Create creates a new container via the SDK client over gRPC.
func (g *GRPCAdapter) Create(ctx context.Context, opts CreateOptions) (*Container, error) {
	created, err := g.client.CreateContainerDomain(ctx, createContainerParamsFromOptions(opts))
	if err != nil {
		return nil, ErrCommandFailed{Command: g.transport + " CreateContainer", Err: err}
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
		return ErrCommandFailed{Command: g.transport + " StartContainer", Err: err}
	}
	if status != nil && !status.Success {
		return ErrCommandFailed{Command: g.transport + " StartContainer", Output: status.Message, Err: fmt.Errorf("server reported failure")}
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
		return ErrCommandFailed{Command: g.transport + " StopContainer", Err: err}
	}
	if status != nil && !status.Success {
		return ErrCommandFailed{Command: g.transport + " StopContainer", Output: status.Message, Err: fmt.Errorf("server reported failure")}
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
		return ErrCommandFailed{Command: g.transport + " DeleteContainer", Err: err}
	}
	if status != nil && !status.Success {
		return ErrCommandFailed{Command: g.transport + " DeleteContainer", Output: status.Message, Err: fmt.Errorf("server reported failure")}
	}
	return nil
}

// Get retrieves a container via the SDK client over gRPC.
func (g *GRPCAdapter) Get(ctx context.Context, id string) (*Container, error) {
	found, err := g.client.GetContainerDomain(ctx, id)
	if err != nil {
		return nil, ErrCommandFailed{Command: g.transport + " GetContainer", Err: err}
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
		return nil, ErrCommandFailed{Command: g.transport + " ListContainers", Err: err}
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
		return nil, ErrCommandFailed{Command: g.transport + " GetContainerLogs", Err: err}
	}

	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry != nil {
			lines = append(lines, entry.Message)
		}
	}
	return lines, nil
}

// Attest performs quote-based container attestation via the SDK client
// (AttestContainer, served on REST as POST /api/v1/compute/containers/{id}/attest).
func (g *GRPCAdapter) Attest(ctx context.Context, id string) (*AttestationReport, error) {
	report, err := g.client.AttestContainerDomain(ctx, &computesvc.AttestContainerParams{ID: id})
	if err != nil {
		return nil, ErrCommandFailed{Command: g.transport + " AttestContainer", Err: err}
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

// QUICAdapter implements ContainerCommands through the SDK QUIC transport,
// which carries the ComputeService container RPCs as the quicwire container
// opcodes pkg/api/daemon/quic_container.go serves.
type QUICAdapter struct {
	GRPCAdapter
}

// NewQUICAdapter creates a new QUIC adapter for integration testing.
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{}
}

// Name returns the protocol adapter identifier.
func (q *QUICAdapter) Name() string {
	return "QUIC"
}

// Setup connects the SDK over QUIC.
func (q *QUICAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformdQUICEndpoint)
	if endpoint == "" {
		endpoint = DefaultPlatformdQUICEndpoint
	}
	return q.connectSDK(ctx, q.Name(), endpoint,
		platform.WithOnlyProtocol(platform.ProtocolQUIC),
		platform.WithQUICAddr(endpoint),
	)
}

// Attest has no QUIC mapping in the SDK.
func (q *QUICAdapter) Attest(ctx context.Context, id string) (*AttestationReport, error) {
	return nil, noSurface(q.Name(), opAttest)
}

// =============================================================================
// MCP Adapter Implementation
// =============================================================================

// MCPAdapter implements ContainerCommands through the SDK MCP transport,
// which calls the container_* tools pkg/api/mcp/container_tools.go registers.
type MCPAdapter struct {
	GRPCAdapter
}

// NewMCPAdapter creates a new MCP adapter for integration testing.
func NewMCPAdapter() *MCPAdapter {
	return &MCPAdapter{}
}

// Name returns the protocol adapter identifier.
func (m *MCPAdapter) Name() string {
	return "MCP"
}

// Setup connects the SDK over MCP.
func (m *MCPAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformdMCPEndpoint)
	if endpoint == "" {
		endpoint = DefaultPlatformdMCPEndpoint
	}
	return m.connectSDK(ctx, m.Name(), endpoint,
		platform.WithOnlyProtocol(platform.ProtocolMCP),
		platform.WithMCPAddr(endpoint),
	)
}

// Attest has no MCP mapping in the SDK.
func (m *MCPAdapter) Attest(ctx context.Context, id string) (*AttestationReport, error) {
	return nil, noSurface(m.Name(), opAttest)
}

// =============================================================================
// Unix Socket Adapter Implementation
// =============================================================================

// UnixAdapter implements ContainerCommands over the daemon's Unix socket.
// platformd serves gRPC on that socket, not HTTP, so this is the gRPC
// adapter dialled over the socket instead of TCP.
type UnixAdapter struct {
	GRPCAdapter
	socketPath string
}

// NewUnixAdapter creates a new Unix socket adapter.
func NewUnixAdapter() *UnixAdapter {
	return &UnixAdapter{}
}

// Name returns the adapter name.
func (u *UnixAdapter) Name() string {
	return "Unix"
}

// Setup dials the daemon's gRPC server over the Unix socket.
func (u *UnixAdapter) Setup(ctx context.Context) error {
	socketPath := os.Getenv(EnvPlatformdSocket)
	if socketPath == "" {
		socketPath = DefaultPlatformdSocket
	}
	u.socketPath = socketPath

	conn, err := grpc.DialContext(ctx, "unix://"+socketPath,
		helpers.GRPCUnixCredentials(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", strings.TrimPrefix(addr, "unix://"))
		}),
		grpc.WithBlock(),
	)
	if err != nil {
		return ErrAdapterConnectionFailed{Adapter: "Unix", URL: socketPath, Err: err}
	}

	u.transport = u.Name()
	u.closer = conn
	u.client = computesvc.NewClientFromGRPC(pb.NewComputeServiceClient(conn))
	return nil
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
