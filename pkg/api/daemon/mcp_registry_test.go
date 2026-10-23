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

package daemon

import (
	"context"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
)

// =============================================================================
// Fakes
// =============================================================================

// fakeRegistryService implements grpcapi.RegistryService for tests.
// Each method returns the configured response and records the last
// request so tests can assert delegation.
type fakeRegistryService struct {
	listResp     *grpcapi.RegistryListResponse
	listErr      error
	lastList     *grpcapi.RegistryListRequest
	inspectResp  *grpcapi.RegistryInspectResponse
	inspectErr   error
	lastInspect  *grpcapi.RegistryInspectRequest
	deleteResp   *grpcapi.RegistryDeleteResponse
	deleteErr    error
	lastDelete   *grpcapi.RegistryDeleteRequest
	statusResp   *grpcapi.RegistryStatusResponse
	statusErr    error
	statusCalled bool
}

func (f *fakeRegistryService) Push(_ context.Context, _ *grpcapi.RegistryPushRequest) (*grpcapi.RegistryPushResponse, error) {
	return nil, errors.New("Push not used by MCP")
}

func (f *fakeRegistryService) PushStream(_ context.Context, _ *grpcapi.RegistryPushMetadata, _ io.Reader) (*grpcapi.RegistryPushResponse, error) {
	return nil, errors.New("PushStream not used by MCP")
}

func (f *fakeRegistryService) Pull(_ context.Context, _ *grpcapi.RegistryPullRequest) (*grpcapi.RegistryPullResponse, error) {
	return nil, errors.New("Pull not used by MCP")
}

func (f *fakeRegistryService) PullStream(_ context.Context, _ *grpcapi.RegistryPullRequest) (*grpcapi.RegistryPullStreamResponse, error) {
	return nil, errors.New("PullStream not used by MCP")
}

func (f *fakeRegistryService) List(_ context.Context, req *grpcapi.RegistryListRequest) (*grpcapi.RegistryListResponse, error) {
	f.lastList = req
	return f.listResp, f.listErr
}

func (f *fakeRegistryService) Inspect(_ context.Context, req *grpcapi.RegistryInspectRequest) (*grpcapi.RegistryInspectResponse, error) {
	f.lastInspect = req
	return f.inspectResp, f.inspectErr
}

func (f *fakeRegistryService) Delete(_ context.Context, req *grpcapi.RegistryDeleteRequest) (*grpcapi.RegistryDeleteResponse, error) {
	f.lastDelete = req
	return f.deleteResp, f.deleteErr
}

func (f *fakeRegistryService) Status(_ context.Context) (*grpcapi.RegistryStatusResponse, error) {
	f.statusCalled = true
	return f.statusResp, f.statusErr
}

// Compile-time interface compliance check.
var _ grpcapi.RegistryService = (*fakeRegistryService)(nil)

// =============================================================================
// Helpers
// =============================================================================

// newProviderWithRegistry creates an MCPServiceProvider wired to the
// supplied registry service. Other dependencies are intentionally nil:
// the registry-bridge tests don't touch them.
func newProviderWithRegistry(svc grpcapi.RegistryService) *MCPServiceProvider {
	return NewMCPServiceProvider(&MCPServiceProviderConfig{
		RegistryService: svc,
	})
}

// =============================================================================
// Tests — error-paths when no service is wired
// =============================================================================

// TestMCPServiceProvider_Registry_NotConfigured verifies that all
// registry MCP methods return ErrRegistryNotConfigured when no service
// is wired into the provider. Mirrors the BMC bridge contract.
func TestMCPServiceProvider_Registry_NotConfigured(t *testing.T) {
	p := newProviderWithRegistry(nil)
	ctx := context.Background()

	t.Run("List", func(t *testing.T) {
		_, err := p.RegistryList(ctx, mcp.RegistryListQuery{})
		var want ErrRegistryNotConfigured
		if !errors.As(err, &want) {
			t.Errorf("expected ErrRegistryNotConfigured, got %v", err)
		}
	})
	t.Run("Inspect", func(t *testing.T) {
		_, err := p.RegistryInspect(ctx, "x", "latest", "", false, false)
		var want ErrRegistryNotConfigured
		if !errors.As(err, &want) {
			t.Errorf("expected ErrRegistryNotConfigured, got %v", err)
		}
	})
	t.Run("Delete", func(t *testing.T) {
		_, err := p.RegistryDelete(ctx, "x", "latest", "", false)
		var want ErrRegistryNotConfigured
		if !errors.As(err, &want) {
			t.Errorf("expected ErrRegistryNotConfigured, got %v", err)
		}
	})
	t.Run("Status", func(t *testing.T) {
		_, err := p.RegistryStatus(ctx)
		var want ErrRegistryNotConfigured
		if !errors.As(err, &want) {
			t.Errorf("expected ErrRegistryNotConfigured, got %v", err)
		}
	})
}

// =============================================================================
// Tests — argument validation
// =============================================================================

// TestMCPServiceProvider_RegistryInspect_MissingArgs verifies inspect
// rejects calls missing repository or both reference+digest.
func TestMCPServiceProvider_RegistryInspect_MissingArgs(t *testing.T) {
	svc := &fakeRegistryService{}
	p := newProviderWithRegistry(svc)
	ctx := context.Background()

	t.Run("missing repo", func(t *testing.T) {
		_, err := p.RegistryInspect(ctx, "", "latest", "", false, false)
		var want ErrRegistryRepositoryRequired
		if !errors.As(err, &want) {
			t.Errorf("expected ErrRegistryRepositoryRequired, got %v", err)
		}
	})
	t.Run("missing reference and digest", func(t *testing.T) {
		_, err := p.RegistryInspect(ctx, "x", "", "", false, false)
		var want ErrRegistryReferenceRequired
		if !errors.As(err, &want) {
			t.Errorf("expected ErrRegistryReferenceRequired, got %v", err)
		}
	})
}

// TestMCPServiceProvider_RegistryDelete_MissingArgs mirrors inspect's
// argument validation for delete.
func TestMCPServiceProvider_RegistryDelete_MissingArgs(t *testing.T) {
	svc := &fakeRegistryService{}
	p := newProviderWithRegistry(svc)
	ctx := context.Background()

	t.Run("missing repo", func(t *testing.T) {
		_, err := p.RegistryDelete(ctx, "", "latest", "", false)
		var want ErrRegistryRepositoryRequired
		if !errors.As(err, &want) {
			t.Errorf("expected ErrRegistryRepositoryRequired, got %v", err)
		}
	})
	t.Run("missing reference and digest", func(t *testing.T) {
		_, err := p.RegistryDelete(ctx, "x", "", "", false)
		var want ErrRegistryReferenceRequired
		if !errors.As(err, &want) {
			t.Errorf("expected ErrRegistryReferenceRequired, got %v", err)
		}
	})
}

// =============================================================================
// Tests — happy path delegation
// =============================================================================

// TestMCPServiceProvider_RegistryList_Success exercises the happy path
// for List: arguments are forwarded, the response is shaped into a JSON
// map, and pagination is included when present.
func TestMCPServiceProvider_RegistryList_Success(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	svc := &fakeRegistryService{
		listResp: &grpcapi.RegistryListResponse{
			Total:      1,
			HasMore:    false,
			NextCursor: "cursor-z",
			Artifacts: []*grpcapi.RegistryArtifact{
				{
					ID:         "platform/gateway:v1.2.3",
					Repository: "platform/gateway",
					Tag:        "v1.2.3",
					Digest:     "sha256:abc",
					Type:       grpcapi.ArtifactTypeContainerImage,
					State:      grpcapi.ArtifactStateAvailable,
					Size:       42,
					CreatedAt:  now,
					Manifest: &grpcapi.RegistryArtifactManifest{
						Digest:    "sha256:m",
						MediaType: "application/vnd.oci.image.manifest.v1+json",
						Layers: []*grpcapi.RegistryArtifactLayer{
							{
								Digest:      "sha256:layer1",
								Size:        100,
								MediaType:   "application/vnd.oci.image.layer.v1.tar",
								Compression: grpcapi.CompressionTypeGzip,
							},
						},
					},
				},
			},
			Pagination: &grpcapi.RegistryPaginationResponse{
				Page:       1,
				PageSize:   25,
				TotalPages: 1,
				TotalItems: 1,
			},
		},
	}
	p := newProviderWithRegistry(svc)
	ctx := context.Background()

	out, err := p.RegistryList(ctx, mcp.RegistryListQuery{
		Repository:       "platform/gateway",
		ArtifactType:     int32(grpcapi.ArtifactTypeContainerImage),
		Limit:            25,
		Cursor:           "cursor-a",
		SortBy:           "created_at",
		Ascending:        true,
		MatchLabels:      map[string]string{"env": "prod"},
		MatchExpressions: []string{"tier in (edge)"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc.lastList == nil {
		t.Fatal("List was not invoked")
	}
	wantReq := &grpcapi.RegistryListRequest{
		Repository: "platform/gateway",
		Type:       grpcapi.ArtifactTypeContainerImage,
		Limit:      25,
		Cursor:     "cursor-a",
		SortBy:     "created_at",
		Ascending:  true,
		Selector: &grpcapi.RegistryLabelSelector{
			MatchLabels:      map[string]string{"env": "prod"},
			MatchExpressions: []string{"tier in (edge)"},
		},
	}
	if !reflect.DeepEqual(svc.lastList, wantReq) {
		t.Errorf("list request = %+v, want %+v", svc.lastList, wantReq)
	}

	m, ok := out.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", out)
	}
	if m["total"] != int32(1) {
		t.Errorf("total = %v, want 1", m["total"])
	}
	artifacts, ok := m["artifacts"].([]map[string]interface{})
	if !ok || len(artifacts) != 1 {
		t.Fatalf("expected one artifact, got %T %v", m["artifacts"], m["artifacts"])
	}
	if artifacts[0]["type"] != "container_image" {
		t.Errorf("type = %v, want container_image", artifacts[0]["type"])
	}
	if artifacts[0]["state"] != "available" {
		t.Errorf("state = %v, want available", artifacts[0]["state"])
	}
	manifest, ok := artifacts[0]["manifest"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected manifest map, got %T", artifacts[0]["manifest"])
	}
	layers, ok := manifest["layers"].([]map[string]interface{})
	if !ok || len(layers) != 1 {
		t.Fatalf("expected one layer, got %v", manifest["layers"])
	}
	if layers[0]["compression"] != "gzip" {
		t.Errorf("compression = %v, want gzip", layers[0]["compression"])
	}
	if _, ok := m["pagination"].(map[string]interface{}); !ok {
		t.Errorf("expected pagination map, got %T", m["pagination"])
	}
}

// TestMCPServiceProvider_RegistryList_EmptyOptional verifies that empty
// optional filters still forward and that the response works without
// pagination (covers the nil-pagination branch).
func TestMCPServiceProvider_RegistryList_EmptyOptional(t *testing.T) {
	svc := &fakeRegistryService{
		listResp: &grpcapi.RegistryListResponse{
			Total:     0,
			Artifacts: nil,
		},
	}
	p := newProviderWithRegistry(svc)
	ctx := context.Background()

	out, err := p.RegistryList(ctx, mcp.RegistryListQuery{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := out.(map[string]interface{})
	if _, exists := m["pagination"]; exists {
		t.Errorf("pagination should be omitted when nil")
	}
	if svc.lastList.Repository != "" {
		t.Errorf("repository should be forwarded as empty, got %q", svc.lastList.Repository)
	}
	if svc.lastList.Selector != nil {
		t.Errorf("an empty label selector should forward as nil, got %+v", svc.lastList.Selector)
	}
}

// TestMCPServiceProvider_RegistryList_Error confirms upstream errors
// propagate.
func TestMCPServiceProvider_RegistryList_Error(t *testing.T) {
	want := errors.New("upstream boom")
	svc := &fakeRegistryService{listErr: want}
	p := newProviderWithRegistry(svc)
	if _, err := p.RegistryList(context.Background(), mcp.RegistryListQuery{}); !errors.Is(err, want) {
		t.Errorf("expected upstream error, got %v", err)
	}
}

// TestMCPServiceProvider_RegistryInspect_Success exercises the inspect
// happy path including signatures and scan_result blocks.
func TestMCPServiceProvider_RegistryInspect_Success(t *testing.T) {
	signedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	svc := &fakeRegistryService{
		inspectResp: &grpcapi.RegistryInspectResponse{
			Detail: &grpcapi.RegistryArtifactDetail{
				Artifact: &grpcapi.RegistryArtifact{
					ID:         "platform/gateway:v1.2.3",
					Repository: "platform/gateway",
					Tag:        "v1.2.3",
					Type:       grpcapi.ArtifactTypeContainerImage,
					State:      grpcapi.ArtifactStateAvailable,
				},
				Tags: []string{"v1.2.3", "latest"},
				Signatures: []*grpcapi.RegistryArtifactSignature{
					{
						KeyID:     "key-1",
						Algorithm: "ECDSA-P256",
						Signature: []byte("sig"),
						SignedAt:  signedAt,
						Signer:    "ci@example.com",
					},
				},
				ScanResult: &grpcapi.RegistryScanResult{
					Scanner:   "trivy",
					ScannedAt: signedAt,
					Vulnerabilities: []*grpcapi.RegistryVulnerability{
						{
							ID:          "CVE-2026-0001",
							Severity:    grpcapi.VulnerabilitySeverityHigh,
							PackageName: "openssl",
						},
					},
					HighCount: 1,
				},
			},
		},
	}
	p := newProviderWithRegistry(svc)

	out, err := p.RegistryInspect(context.Background(), "platform/gateway", "v1.2.3", "", true, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc.lastInspect == nil {
		t.Fatal("Inspect was not invoked")
	}
	if !svc.lastInspect.IncludeSignatures || !svc.lastInspect.IncludeScanResult {
		t.Error("include flags should be forwarded")
	}
	m := out.(map[string]interface{})
	sigs, ok := m["signatures"].([]map[string]interface{})
	if !ok || len(sigs) != 1 {
		t.Fatalf("expected one signature, got %v", m["signatures"])
	}
	if sigs[0]["algorithm"] != "ECDSA-P256" {
		t.Errorf("algorithm = %v", sigs[0]["algorithm"])
	}
	scan, ok := m["scan_result"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected scan_result map, got %T", m["scan_result"])
	}
	vulns, ok := scan["vulnerabilities"].([]map[string]interface{})
	if !ok || len(vulns) != 1 {
		t.Fatalf("expected one vuln, got %v", scan["vulnerabilities"])
	}
	if vulns[0]["severity"] != "high" {
		t.Errorf("severity = %v, want high", vulns[0]["severity"])
	}
}

// TestMCPServiceProvider_RegistryInspect_NilDetail verifies the nil
// detail fallback returns the supplied identifying fields.
func TestMCPServiceProvider_RegistryInspect_NilDetail(t *testing.T) {
	svc := &fakeRegistryService{
		inspectResp: &grpcapi.RegistryInspectResponse{Detail: nil},
	}
	p := newProviderWithRegistry(svc)

	out, err := p.RegistryInspect(context.Background(), "platform/gateway", "", "sha256:abc", false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := out.(map[string]interface{})
	if m["repository"] != "platform/gateway" || m["digest"] != "sha256:abc" {
		t.Errorf("expected fallback identifying fields, got %v", m)
	}
}

// TestMCPServiceProvider_RegistryInspect_Error confirms upstream errors
// propagate.
func TestMCPServiceProvider_RegistryInspect_Error(t *testing.T) {
	want := errors.New("nope")
	svc := &fakeRegistryService{inspectErr: want}
	p := newProviderWithRegistry(svc)
	if _, err := p.RegistryInspect(context.Background(), "x", "latest", "", false, false); !errors.Is(err, want) {
		t.Errorf("expected upstream error, got %v", err)
	}
}

// TestMCPServiceProvider_RegistryInspect_InvalidReference pins that a
// reference outside the OCI grammar reaches the MCP tool layer as
// InvalidArgument (JSON-RPC invalid params), not Internal.
func TestMCPServiceProvider_RegistryInspect_InvalidReference(t *testing.T) {
	cause := grpcapi.ErrInvalidArtifactReference{Reference: "MCP-1:latest", Reason: "invalid format"}
	p := newProviderWithRegistry(&fakeRegistryService{inspectErr: cause})

	_, err := p.RegistryInspect(context.Background(), "MCP-1", "latest", "", false, false)

	if code := status.Code(err); code != codes.InvalidArgument {
		t.Errorf("code = %s, want InvalidArgument (err %v)", code, err)
	}
}

// TestMCPServiceProvider_RegistryInspect_InternalFailure pins the other side
// of the classification: a service fault stays Internal.
func TestMCPServiceProvider_RegistryInspect_InternalFailure(t *testing.T) {
	p := newProviderWithRegistry(&fakeRegistryService{inspectErr: errors.New("disk full")})

	_, err := p.RegistryInspect(context.Background(), "mcp-1", "latest", "", false, false)

	if code := status.Code(err); code != codes.Internal {
		t.Errorf("code = %s, want Internal (err %v)", code, err)
	}
}

// TestMCPServiceProvider_RegistryDelete_Success verifies delete forwards
// arguments and shapes the response.
func TestMCPServiceProvider_RegistryDelete_Success(t *testing.T) {
	when := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	svc := &fakeRegistryService{
		deleteResp: &grpcapi.RegistryDeleteResponse{
			Digest:     "sha256:abc",
			BytesFreed: 1234,
			Timestamp:  when,
		},
	}
	p := newProviderWithRegistry(svc)

	out, err := p.RegistryDelete(context.Background(), "platform/gateway", "v1", "", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc.lastDelete == nil {
		t.Fatal("Delete was not invoked")
	}
	if !svc.lastDelete.Force {
		t.Error("force should be forwarded")
	}
	m := out.(map[string]interface{})
	if m["digest"] != "sha256:abc" {
		t.Errorf("digest = %v", m["digest"])
	}
	if m["bytes_freed"] != int64(1234) {
		t.Errorf("bytes_freed = %v", m["bytes_freed"])
	}
}

// TestMCPServiceProvider_RegistryDelete_Error confirms upstream errors
// propagate.
func TestMCPServiceProvider_RegistryDelete_Error(t *testing.T) {
	want := errors.New("nope")
	svc := &fakeRegistryService{deleteErr: want}
	p := newProviderWithRegistry(svc)
	if _, err := p.RegistryDelete(context.Background(), "x", "latest", "", false); !errors.Is(err, want) {
		t.Errorf("expected upstream error, got %v", err)
	}
}

// TestMCPServiceProvider_RegistryStatus_Success exercises the status
// happy path including storage stats and component health.
func TestMCPServiceProvider_RegistryStatus_Success(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	svc := &fakeRegistryService{
		statusResp: &grpcapi.RegistryStatusResponse{
			Health:    grpcapi.RegistryHealthStatusHealthy,
			Version:   "1.0.0",
			ReadOnly:  false,
			StartedAt: now,
			Timestamp: now,
			Storage: &grpcapi.RegistryStorageStats{
				TotalBytes:      1024,
				UsedBytes:       512,
				AvailableBytes:  512,
				ArtifactCount:   3,
				LayerCount:      9,
				RepositoryCount: 1,
			},
			Components: []*grpcapi.RegistryComponentHealth{
				{
					Name:      "storage",
					Status:    grpcapi.RegistryHealthStatusHealthy,
					Message:   "ok",
					LastCheck: now,
				},
				nil, // skip nil entries
			},
		},
	}
	p := newProviderWithRegistry(svc)

	out, err := p.RegistryStatus(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !svc.statusCalled {
		t.Fatal("Status was not invoked")
	}
	m := out.(map[string]interface{})
	if m["health"] != "healthy" {
		t.Errorf("health = %v", m["health"])
	}
	storage, ok := m["storage"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected storage map")
	}
	if storage["used_bytes"] != int64(512) {
		t.Errorf("used_bytes = %v", storage["used_bytes"])
	}
	comps, ok := m["components"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected components slice")
	}
	if len(comps) != 1 {
		t.Errorf("expected nil entry to be filtered, got %d components", len(comps))
	}
}

// TestMCPServiceProvider_RegistryStatus_Error confirms upstream errors
// propagate.
func TestMCPServiceProvider_RegistryStatus_Error(t *testing.T) {
	want := errors.New("nope")
	svc := &fakeRegistryService{statusErr: want}
	p := newProviderWithRegistry(svc)
	if _, err := p.RegistryStatus(context.Background()); !errors.Is(err, want) {
		t.Errorf("expected upstream error, got %v", err)
	}
}

// =============================================================================
// Tests — setter and JSON helpers
// =============================================================================

// TestMCPServiceProvider_SetRegistryService verifies post-construction
// injection works the same as constructor wiring.
func TestMCPServiceProvider_SetRegistryService(t *testing.T) {
	p := newProviderWithRegistry(nil)
	if _, err := p.RegistryStatus(context.Background()); err == nil {
		t.Fatal("expected ErrRegistryNotConfigured before injection")
	}
	svc := &fakeRegistryService{statusResp: &grpcapi.RegistryStatusResponse{Health: grpcapi.RegistryHealthStatusHealthy}}
	p.SetRegistryService(svc)
	if _, err := p.RegistryStatus(context.Background()); err != nil {
		t.Errorf("expected success after injection, got %v", err)
	}
}

// TestRegistryHelpers_StableEnumStrings covers the helper enum maps —
// every defined value must produce a non-empty stable string, and an
// out-of-range value must fall back to "unspecified".
func TestRegistryHelpers_StableEnumStrings(t *testing.T) {
	if registryArtifactTypeString(grpcapi.ArtifactTypeContainerImage) != "container_image" {
		t.Errorf("ArtifactType ContainerImage string mismatch")
	}
	if registryArtifactTypeString(grpcapi.ArtifactType(99)) != "unspecified" {
		t.Errorf("ArtifactType fallback mismatch")
	}
	if registryArtifactStateString(grpcapi.ArtifactStateAvailable) != "available" {
		t.Errorf("ArtifactState available string mismatch")
	}
	if registryArtifactStateString(grpcapi.ArtifactState(99)) != "unspecified" {
		t.Errorf("ArtifactState fallback mismatch")
	}
	if registryCompressionString(grpcapi.CompressionTypeZstd) != "zstd" {
		t.Errorf("Compression zstd string mismatch")
	}
	if registryCompressionString(grpcapi.CompressionType(99)) != "unspecified" {
		t.Errorf("Compression fallback mismatch")
	}
	if registryHealthString(grpcapi.RegistryHealthStatusUnhealthy) != "unhealthy" {
		t.Errorf("Health unhealthy string mismatch")
	}
	if registryHealthString(grpcapi.RegistryHealthStatus(99)) != "unspecified" {
		t.Errorf("Health fallback mismatch")
	}
	if registryVulnSeverityString(grpcapi.VulnerabilitySeverityCritical) != "critical" {
		t.Errorf("Vuln critical string mismatch")
	}
	if registryVulnSeverityString(grpcapi.VulnerabilitySeverity(99)) != "unspecified" {
		t.Errorf("Vuln fallback mismatch")
	}
}

// TestRegistryHelpers_TimeJSON verifies zero times serialize as 0 and
// real times serialize as millisecond-precision UNIX timestamps.
func TestRegistryHelpers_TimeJSON(t *testing.T) {
	if registryTimeJSON(time.Time{}) != 0 {
		t.Errorf("zero time should serialize as 0")
	}
	when := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	if got := registryTimeJSON(when); got != when.UnixMilli() {
		t.Errorf("time mismatch: got %d, want %d", got, when.UnixMilli())
	}
}

// TestRegistryHelpers_NilSafety verifies the JSON helper functions
// return nil when given nil input rather than panicking.
func TestRegistryHelpers_NilSafety(t *testing.T) {
	if registryArtifactJSON(nil) != nil {
		t.Errorf("nil artifact should produce nil")
	}
	if registryManifestJSON(nil) != nil {
		t.Errorf("nil manifest should produce nil")
	}
	if registryDetailJSON(nil) != nil {
		t.Errorf("nil detail should produce nil")
	}
	got := registryArtifactsJSON([]*grpcapi.RegistryArtifact{nil, nil})
	if len(got) != 0 {
		t.Errorf("nil-only slice should produce empty slice, got %v", got)
	}
}

// TestRegistryHelpers_NilLayersAndSigsFiltered verifies that nil entries
// in slices (defensive nil-skip in JSON helpers) are filtered out.
func TestRegistryHelpers_NilLayersAndSigsFiltered(t *testing.T) {
	manifest := &grpcapi.RegistryArtifactManifest{
		Digest: "sha256:m",
		Layers: []*grpcapi.RegistryArtifactLayer{nil, {Digest: "sha256:l1"}},
	}
	out := registryManifestJSON(manifest)
	layers, ok := out["layers"].([]map[string]interface{})
	if !ok || len(layers) != 1 {
		t.Errorf("expected nil layer to be filtered, got %v", out["layers"])
	}

	detail := &grpcapi.RegistryArtifactDetail{
		Artifact:   &grpcapi.RegistryArtifact{ID: "id"},
		Signatures: []*grpcapi.RegistryArtifactSignature{nil, {KeyID: "k"}},
		ScanResult: &grpcapi.RegistryScanResult{
			Vulnerabilities: []*grpcapi.RegistryVulnerability{nil, {ID: "CVE-X"}},
		},
	}
	dout := registryDetailJSON(detail)
	sigs, ok := dout["signatures"].([]map[string]interface{})
	if !ok || len(sigs) != 1 {
		t.Errorf("expected nil sig to be filtered, got %v", dout["signatures"])
	}
	scan, ok := dout["scan_result"].(map[string]interface{})
	if !ok {
		t.Fatal("expected scan_result")
	}
	vulns, ok := scan["vulnerabilities"].([]map[string]interface{})
	if !ok || len(vulns) != 1 {
		t.Errorf("expected nil vuln to be filtered, got %v", scan["vulnerabilities"])
	}
}

// TestRegistryErrorTypes_Messages verifies the typed error values produce
// stable, human-readable messages used in CLI/log output.
func TestRegistryErrorTypes_Messages(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{ErrRegistryNotConfigured{}, "registry service not configured"},
		{ErrRegistryRepositoryRequired{}, "registry: repository is required"},
		{ErrRegistryReferenceRequired{}, "registry: reference (tag) or digest is required"},
	}
	for _, tc := range cases {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("Error() = %q, want %q", got, tc.want)
		}
	}
}
