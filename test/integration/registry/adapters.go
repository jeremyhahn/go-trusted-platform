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

package registry

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	regsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/registry"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// Common Constants
// =============================================================================

const (
	// EnvPlatformctlBinary is the path to the platformctl binary.
	EnvPlatformctlBinary = "PLATFORMCTL_BINARY"

	// EnvPlatformdSocket is the Unix socket path for platformd.
	EnvPlatformdSocket = "PLATFORMD_SOCKET"

	// DefaultPlatformctlBinary is the default binary name.
	DefaultPlatformctlBinary = "platformctl"

	// DefaultPlatformdSocket is the default Unix socket path.
	DefaultPlatformdSocket = "/run/platformd.sock"

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

// ErrSetupFailed is returned when adapter setup fails.
type ErrSetupFailed struct {
	Adapter string
	Reason  string
	Err     error
}

func (e ErrSetupFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s adapter setup failed: %s: %v", e.Adapter, e.Reason, e.Err)
	}
	return fmt.Sprintf("%s adapter setup failed: %s", e.Adapter, e.Reason)
}

func (e ErrSetupFailed) Unwrap() error {
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

// ErrImageNotFound is returned when an image cannot be found.
type ErrImageNotFound struct {
	Reference string
}

func (e ErrImageNotFound) Error() string {
	return fmt.Sprintf("image not found: %s", e.Reference)
}

// ErrImageNotSigned is returned when a verifying pull meets an image whose
// manifest carries no signature.
type ErrImageNotSigned struct {
	Reference string
}

func (e ErrImageNotSigned) Error() string {
	return fmt.Sprintf("image %s is not signed", e.Reference)
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

// ErrSessionNotFound is returned when a session cannot be found.
type ErrSessionNotFound struct {
	ClientID string
}

func (e ErrSessionNotFound) Error() string {
	return fmt.Sprintf("session not found: %s", e.ClientID)
}

// ErrInvalidArgument is returned when an argument is invalid.
type ErrInvalidArgument struct {
	Argument string
	Reason   string
}

func (e ErrInvalidArgument) Error() string {
	return fmt.Sprintf("invalid argument %q: %s", e.Argument, e.Reason)
}

// =============================================================================
// Compile-time interface checks
// =============================================================================

var (
	_ RegistryCommands = (*CLIAdapter)(nil)
	_ RegistryCommands = (*RESTAdapter)(nil)
	_ RegistryCommands = (*GRPCAdapter)(nil)
	_ RegistryCommands = (*QUICAdapter)(nil)
	_ RegistryCommands = (*MCPAdapter)(nil)
	_ RegistryCommands = (*UnixAdapter)(nil)
)

// =============================================================================
// gRPC Adapter Implementation
// =============================================================================

// GRPCAdapter implements RegistryCommands using gRPC calls.
type GRPCAdapter struct {
	endpoint string
	conn     *grpc.ClientConn
	client   *regsvc.Client
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
	g.client = regsvc.NewClientFromGRPC(pb.NewRegistryServiceClient(conn))
	return nil
}

// Teardown closes the gRPC connection.
func (g *GRPCAdapter) Teardown() error {
	if g.conn != nil {
		return g.conn.Close()
	}
	return nil
}

// =============================================================================
// QUIC Adapter Implementation
// =============================================================================

// QUICAdapter implements RegistryCommands for QUIC. QUIC carries no registry
// opcode (docs/registry/api.md §2), so every operation returns the suite's
// surface.ErrNoSurface.
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

	// QUIC carries no registry opcode, so there is no registry call to open
	// a connection for: every operation reports the missing surface.
	return nil
}

// Teardown closes the QUIC connection.
func (q *QUICAdapter) Teardown() error {
	return nil
}

// Push pushes an image to the registry via QUIC.
func (q *QUICAdapter) Push(ctx context.Context, ref string, opts PushOptions) (*PushResult, error) {
	return nil, noSurface("QUIC", opPush)
}

// Pull pulls an image from the registry via QUIC.
func (q *QUICAdapter) Pull(ctx context.Context, ref string, opts PullOptions) (*PullResult, error) {
	return nil, noSurface("QUIC", opPull)
}

// List lists images in the registry via QUIC.
func (q *QUICAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	return nil, noSurface("QUIC", opList)
}

// Delete deletes an image from the registry via QUIC.
func (q *QUICAdapter) Delete(ctx context.Context, ref string, opts DeleteOptions) (*DeleteResult, error) {
	return nil, noSurface("QUIC", opDelete)
}

// Inspect inspects an image in the registry via QUIC.
func (q *QUICAdapter) Inspect(ctx context.Context, ref string) (*InspectResult, error) {
	return nil, noSurface("QUIC", opInspect)
}

// Status retrieves the registry status via QUIC.
func (q *QUICAdapter) Status(ctx context.Context) (*StatusResult, error) {
	return nil, noSurface("QUIC", opStatus)
}

// Tag adds a tag to an existing image via QUIC.
func (q *QUICAdapter) Tag(ctx context.Context, sourceRef, targetRef string) (*TagResult, error) {
	return nil, noSurface("QUIC", opTag)
}

// VerifyClient verifies a client's attestation via QUIC.
func (q *QUICAdapter) VerifyClient(ctx context.Context, opts VerifyClientOptions) (*VerifyClientResult, error) {
	return nil, noSurface("QUIC", opVerifyClient)
}

// GetSession retrieves a client session via QUIC.
func (q *QUICAdapter) GetSession(ctx context.Context, clientID string) (*SessionResult, error) {
	return nil, noSurface("QUIC", opGetSession)
}

// InvalidateSession invalidates a client session via QUIC.
func (q *QUICAdapter) InvalidateSession(ctx context.Context, clientID string) error {
	return noSurface("QUIC", opInvalidateSession)
}

// EncryptImage encrypts an image via QUIC.
func (q *QUICAdapter) EncryptImage(ctx context.Context, ref string, keyID string) (*EncryptImageResult, error) {
	return nil, noSurface("QUIC", opEncryptImage)
}

// DecryptImage decrypts an image via QUIC.
func (q *QUICAdapter) DecryptImage(ctx context.Context, ref string) (*DecryptImageResult, error) {
	return nil, noSurface("QUIC", opDecryptImage)
}

// =============================================================================
// Unix Socket Adapter Implementation
// =============================================================================

// UnixAdapter implements RegistryCommands over the daemon's Unix socket.
// platformd serves gRPC on that socket, not HTTP, so this is the gRPC
// adapter dialled over the socket instead of TCP (docs/registry/api.md §2).
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

	u.conn = conn
	u.client = regsvc.NewClientFromGRPC(pb.NewRegistryServiceClient(conn))
	return nil
}

// Tag has no RegistryService call on the socket.
func (u *UnixAdapter) Tag(ctx context.Context, sourceRef, targetRef string) (*TagResult, error) {
	return nil, noSurface(u.Name(), opTag)
}

// VerifyClient has no RegistryService call on the socket.
func (u *UnixAdapter) VerifyClient(ctx context.Context, opts VerifyClientOptions) (*VerifyClientResult, error) {
	return nil, noSurface(u.Name(), opVerifyClient)
}

// GetSession has no RegistryService call on the socket.
func (u *UnixAdapter) GetSession(ctx context.Context, clientID string) (*SessionResult, error) {
	return nil, noSurface(u.Name(), opGetSession)
}

// InvalidateSession has no RegistryService call on the socket.
func (u *UnixAdapter) InvalidateSession(ctx context.Context, clientID string) error {
	return noSurface(u.Name(), opInvalidateSession)
}

// EncryptImage has no RegistryService call on the socket.
func (u *UnixAdapter) EncryptImage(ctx context.Context, ref string, keyID string) (*EncryptImageResult, error) {
	return nil, noSurface(u.Name(), opEncryptImage)
}

// DecryptImage has no RegistryService call on the socket.
func (u *UnixAdapter) DecryptImage(ctx context.Context, ref string) (*DecryptImageResult, error) {
	return nil, noSurface(u.Name(), opDecryptImage)
}

// =============================================================================
// Response Types for JSON Parsing
// =============================================================================

// CLI Response Types

type cliPushResponse struct {
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Encrypted bool   `json:"encrypted"`
	Signed    bool   `json:"signed"`
	Timestamp int64  `json:"timestamp"`
}

func (r *cliPushResponse) toPushResult() *PushResult {
	return &PushResult{
		Reference: r.Reference,
		Digest:    r.Digest,
		Size:      r.Size,
		Encrypted: r.Encrypted,
		Signed:    r.Signed,
		PushedAt:  time.Unix(r.Timestamp, 0).UTC(),
	}
}

type cliPullResponse struct {
	Reference      string              `json:"reference"`
	Manifest       cliManifestResponse `json:"manifest"`
	Config         string              `json:"config"`
	Layers         []cliLayerResponse  `json:"layers"`
	Encrypted      bool                `json:"encrypted"`
	Signed         bool                `json:"signed"`
	SignatureValid bool                `json:"signature_valid"`
	PulledAt       time.Time           `json:"pulled_at"`
}

func (r *cliPullResponse) toPullResult() *PullResult {
	result := &PullResult{
		Reference:      r.Reference,
		Manifest:       r.Manifest.toImageManifest(),
		Encrypted:      r.Encrypted,
		Signed:         r.Signed,
		SignatureValid: r.SignatureValid,
		PulledAt:       r.PulledAt,
	}

	if r.Config != "" {
		result.Config, _ = base64.StdEncoding.DecodeString(r.Config)
	}

	if len(r.Layers) > 0 {
		result.Layers = make([]LayerData, len(r.Layers))
		for i, layer := range r.Layers {
			result.Layers[i] = layer.toLayerData()
		}
	}

	return result
}

type cliLayerResponse struct {
	MediaType   string            `json:"media_type"`
	Content     string            `json:"content"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func (r *cliLayerResponse) toLayerData() LayerData {
	content, _ := base64.StdEncoding.DecodeString(r.Content)
	return LayerData{
		MediaType:   r.MediaType,
		Content:     content,
		Annotations: r.Annotations,
	}
}

type cliManifestResponse struct {
	SchemaVersion int                     `json:"schemaVersion"`
	MediaType     string                  `json:"mediaType"`
	Config        cliDescriptorResponse   `json:"config"`
	Layers        []cliDescriptorResponse `json:"layers"`
	Annotations   map[string]string       `json:"annotations,omitempty"`
	Reference     string                  `json:"reference"`
	Digest        string                  `json:"digest"`
	Size          int64                   `json:"size"`
	CreatedAt     time.Time               `json:"created_at"`
	UpdatedAt     time.Time               `json:"updated_at"`
	Encrypted     bool                    `json:"encrypted"`
	Signed        bool                    `json:"signed"`
}

func (r *cliManifestResponse) toImageManifest() *ImageManifest {
	layers := make([]Descriptor, len(r.Layers))
	for i, l := range r.Layers {
		layers[i] = l.toDescriptor()
	}

	return &ImageManifest{
		SchemaVersion: r.SchemaVersion,
		MediaType:     r.MediaType,
		Config:        r.Config.toDescriptor(),
		Layers:        layers,
		Annotations:   r.Annotations,
		Reference:     r.Reference,
		Digest:        r.Digest,
		Size:          r.Size,
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
		Encrypted:     r.Encrypted,
		Signed:        r.Signed,
	}
}

type cliDescriptorResponse struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func (r *cliDescriptorResponse) toDescriptor() Descriptor {
	return Descriptor{
		MediaType:   r.MediaType,
		Digest:      r.Digest,
		Size:        r.Size,
		Annotations: r.Annotations,
	}
}

type cliListResponse struct {
	Images     []cliManifestResponse `json:"images"`
	TotalCount int                   `json:"total_count"`
	HasMore    bool                  `json:"has_more"`
	NextCursor string                `json:"next_cursor,omitempty"`
}

func (r *cliListResponse) toListResult() *ListResult {
	images := make([]ImageManifest, len(r.Images))
	for i, img := range r.Images {
		images[i] = *img.toImageManifest()
	}

	return &ListResult{
		Images:     images,
		TotalCount: r.TotalCount,
		HasMore:    r.HasMore,
		NextCursor: r.NextCursor,
	}
}

type cliDeleteResponse struct {
	Reference     string    `json:"reference"`
	Digest        string    `json:"digest"`
	DeletedAt     time.Time `json:"deleted_at"`
	LayersDeleted int       `json:"layers_deleted"`
}

func (r *cliDeleteResponse) toDeleteResult() *DeleteResult {
	return &DeleteResult{
		Reference:     r.Reference,
		Digest:        r.Digest,
		DeletedAt:     r.DeletedAt,
		LayersDeleted: r.LayersDeleted,
	}
}

type cliInspectResponse struct {
	Reference       string                 `json:"reference"`
	Manifest        cliManifestResponse    `json:"manifest"`
	Config          cliImageConfigResponse `json:"config"`
	TotalSize       int64                  `json:"total_size"`
	LayerCount      int                    `json:"layer_count"`
	Encrypted       bool                   `json:"encrypted"`
	EncryptionKeyID string                 `json:"encryption_key_id,omitempty"`
	Signed          bool                   `json:"signed"`
	SigningKeyID    string                 `json:"signing_key_id,omitempty"`
	SignatureValid  bool                   `json:"signature_valid"`
}

func (r *cliInspectResponse) toInspectResult() *InspectResult {
	return &InspectResult{
		Reference:       r.Reference,
		Manifest:        r.Manifest.toImageManifest(),
		Config:          r.Config.toImageConfig(),
		TotalSize:       r.TotalSize,
		LayerCount:      r.LayerCount,
		Encrypted:       r.Encrypted,
		EncryptionKeyID: r.EncryptionKeyID,
		Signed:          r.Signed,
		SigningKeyID:    r.SigningKeyID,
		SignatureValid:  r.SignatureValid,
	}
}

type cliImageConfigResponse struct {
	Architecture string            `json:"architecture"`
	OS           string            `json:"os"`
	Author       string            `json:"author,omitempty"`
	Created      time.Time         `json:"created"`
	Entrypoint   []string          `json:"entrypoint,omitempty"`
	Cmd          []string          `json:"cmd,omitempty"`
	Env          []string          `json:"env,omitempty"`
	WorkingDir   string            `json:"working_dir,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	ExposedPorts []string          `json:"exposed_ports,omitempty"`
	Volumes      []string          `json:"volumes,omitempty"`
}

func (r *cliImageConfigResponse) toImageConfig() *ImageConfig {
	return &ImageConfig{
		Architecture: r.Architecture,
		OS:           r.OS,
		Author:       r.Author,
		Created:      r.Created,
		Entrypoint:   r.Entrypoint,
		Cmd:          r.Cmd,
		Env:          r.Env,
		WorkingDir:   r.WorkingDir,
		Labels:       r.Labels,
		ExposedPorts: r.ExposedPorts,
		Volumes:      r.Volumes,
	}
}

type cliStatusResponse struct {
	Status *struct {
		Healthy bool   `json:"healthy"`
		Version string `json:"version"`
		Uptime  int64  `json:"uptime_seconds"`
		Storage *struct {
			Backend    string `json:"backend"`
			Healthy    bool   `json:"healthy"`
			UsedBytes  int64  `json:"used_bytes"`
			ImageCount int    `json:"image_count"`
		} `json:"storage"`
		Attestation *struct {
			Enabled bool `json:"enabled"`
		} `json:"attestation"`
		Encryption *struct {
			Enabled bool `json:"enabled"`
		} `json:"encryption"`
	} `json:"status"`
}

// toStatusResult maps platformctl registry status's {"status": {...}}
// document (docs/registry/cli.md §7) onto the shared result, deriving
// Status the way the gRPC adapter does from the health verdict.
func (r *cliStatusResponse) toStatusResult() *StatusResult {
	result := &StatusResult{Status: "degraded"}
	s := r.Status
	if s == nil {
		return result
	}
	result.Healthy = s.Healthy
	if s.Healthy {
		result.Status = "running"
	}
	result.Version = s.Version
	result.Uptime = time.Duration(s.Uptime) * time.Second
	if s.Storage != nil {
		result.ImageCount = s.Storage.ImageCount
		result.TotalSize = s.Storage.UsedBytes
		result.StorageBackend = s.Storage.Backend
		result.StorageStatus = "unhealthy"
		if s.Storage.Healthy {
			result.StorageStatus = "healthy"
		}
	}
	if s.Attestation != nil {
		result.AttestationEnabled = s.Attestation.Enabled
	}
	if s.Encryption != nil {
		result.EncryptionEnabled = s.Encryption.Enabled
	}
	return result
}
