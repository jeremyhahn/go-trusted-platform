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

package registry

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewListCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewListCommand(getFlags)

	if cmd == nil {
		t.Fatal("NewListCommand returned nil")
	}

	if cmd.Use != "list" {
		t.Errorf("expected Use to be 'list', got %q", cmd.Use)
	}

	if cmd.Short != "List images in the registry" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewListCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewListCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if len(cmd.Long) < 100 {
		t.Error("Long description should be descriptive (at least 100 chars)")
	}
}

func TestNewListCommand_AcceptsNoArgs(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewListCommand(getFlags)

	// List command should not require any arguments
	if cmd.Args != nil {
		err := cmd.Args(cmd, []string{})
		if err != nil {
			t.Errorf("list command should accept no args: %v", err)
		}
	}
}

func TestNewListCommand_HasFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewListCommand(getFlags)

	tests := []struct {
		name      string
		shorthand string
	}{
		{name: "repository", shorthand: "r"},
		{name: "prefix", shorthand: "p"},
		{name: "limit", shorthand: "l"},
		{name: "cursor", shorthand: "c"},
		{name: "show-encrypted", shorthand: ""},
		{name: "sort-by", shorthand: ""},
		{name: "sort-desc", shorthand: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tt.name)
			if flag == nil {
				t.Errorf("expected flag %q to exist", tt.name)
				return
			}
			if tt.shorthand != "" && flag.Shorthand != tt.shorthand {
				t.Errorf("expected shorthand %q for flag %q, got %q",
					tt.shorthand, tt.name, flag.Shorthand)
			}
		})
	}
}

func TestNewListCommand_DefaultFlagValues(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewListCommand(getFlags)

	repositoryFlag := cmd.Flags().Lookup("repository")
	if repositoryFlag == nil {
		t.Fatal("repository flag not found")
	}
	if repositoryFlag.DefValue != "" {
		t.Errorf("expected repository default to be empty, got %q", repositoryFlag.DefValue)
	}

	prefixFlag := cmd.Flags().Lookup("prefix")
	if prefixFlag == nil {
		t.Fatal("prefix flag not found")
	}
	if prefixFlag.DefValue != "" {
		t.Errorf("expected prefix default to be empty, got %q", prefixFlag.DefValue)
	}

	limitFlag := cmd.Flags().Lookup("limit")
	if limitFlag == nil {
		t.Fatal("limit flag not found")
	}
	if limitFlag.DefValue != "50" {
		t.Errorf("expected limit default to be '50', got %q", limitFlag.DefValue)
	}

	showEncryptedFlag := cmd.Flags().Lookup("show-encrypted")
	if showEncryptedFlag == nil {
		t.Fatal("show-encrypted flag not found")
	}
	if showEncryptedFlag.DefValue != "true" {
		t.Errorf("expected show-encrypted default to be 'true', got %q", showEncryptedFlag.DefValue)
	}

	sortByFlag := cmd.Flags().Lookup("sort-by")
	if sortByFlag == nil {
		t.Fatal("sort-by flag not found")
	}
	if sortByFlag.DefValue != "name" {
		t.Errorf("expected sort-by default to be 'name', got %q", sortByFlag.DefValue)
	}

	sortDescFlag := cmd.Flags().Lookup("sort-desc")
	if sortDescFlag == nil {
		t.Fatal("sort-desc flag not found")
	}
	if sortDescFlag.DefValue != "false" {
		t.Errorf("expected sort-desc default to be 'false', got %q", sortDescFlag.DefValue)
	}
}

func TestImageListItem_Fields(t *testing.T) {
	item := ImageListItem{
		Reference:   "myrepo/myimage:v1.0",
		Digest:      "sha256:abc123",
		Size:        1024,
		Encrypted:   true,
		Signed:      true,
		CreatedAt:   1234567890,
		PushedAt:    1234567900,
		Platform:    "linux/amd64",
		LayerCount:  5,
		Annotations: map[string]string{"key": "value"},
	}

	if item.Reference != "myrepo/myimage:v1.0" {
		t.Errorf("unexpected Reference: %q", item.Reference)
	}

	if item.Digest != "sha256:abc123" {
		t.Errorf("unexpected Digest: %q", item.Digest)
	}

	if item.Size != 1024 {
		t.Errorf("unexpected Size: %d", item.Size)
	}

	if !item.Encrypted {
		t.Error("expected Encrypted to be true")
	}

	if !item.Signed {
		t.Error("expected Signed to be true")
	}

	if item.CreatedAt != 1234567890 {
		t.Errorf("unexpected CreatedAt: %d", item.CreatedAt)
	}

	if item.PushedAt != 1234567900 {
		t.Errorf("unexpected PushedAt: %d", item.PushedAt)
	}

	if item.Platform != "linux/amd64" {
		t.Errorf("unexpected Platform: %q", item.Platform)
	}

	if item.LayerCount != 5 {
		t.Errorf("unexpected LayerCount: %d", item.LayerCount)
	}

	if len(item.Annotations) != 1 || item.Annotations["key"] != "value" {
		t.Errorf("unexpected Annotations: %v", item.Annotations)
	}
}

func TestListResult_Fields(t *testing.T) {
	result := ListResult{
		Images: []*ImageListItem{
			{Reference: "image1:v1"},
			{Reference: "image2:v2"},
		},
		TotalCount: 2,
		HasMore:    true,
		NextCursor: "cursor123",
	}

	if len(result.Images) != 2 {
		t.Errorf("expected 2 images, got %d", len(result.Images))
	}

	if result.TotalCount != 2 {
		t.Errorf("expected TotalCount 2, got %d", result.TotalCount)
	}

	if !result.HasMore {
		t.Error("expected HasMore to be true")
	}

	if result.NextCursor != "cursor123" {
		t.Errorf("unexpected NextCursor: %q", result.NextCursor)
	}
}

func TestListResult_EmptyImages(t *testing.T) {
	result := ListResult{
		Images:     []*ImageListItem{},
		TotalCount: 0,
		HasMore:    false,
		NextCursor: "",
	}

	if len(result.Images) != 0 {
		t.Errorf("expected 0 images, got %d", len(result.Images))
	}

	if result.TotalCount != 0 {
		t.Errorf("expected TotalCount 0, got %d", result.TotalCount)
	}

	if result.HasMore {
		t.Error("expected HasMore to be false")
	}

	if result.NextCursor != "" {
		t.Errorf("expected empty NextCursor, got %q", result.NextCursor)
	}
}

func TestNewListCommand_FlagUsage(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewListCommand(getFlags)

	flags := []string{"repository", "prefix", "limit", "cursor", "show-encrypted", "sort-by", "sort-desc"}

	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(name)
			if flag == nil {
				t.Fatalf("flag %q not found", name)
			}
			if flag.Usage == "" {
				t.Errorf("flag %q should have usage text", name)
			}
		})
	}
}

func TestImageListItem_ZeroValues(t *testing.T) {
	var item ImageListItem

	if item.Reference != "" {
		t.Errorf("expected empty Reference, got %q", item.Reference)
	}

	if item.Digest != "" {
		t.Errorf("expected empty Digest, got %q", item.Digest)
	}

	if item.Size != 0 {
		t.Errorf("expected zero Size, got %d", item.Size)
	}

	if item.Encrypted {
		t.Error("expected Encrypted to be false")
	}

	if item.Signed {
		t.Error("expected Signed to be false")
	}

	if item.LayerCount != 0 {
		t.Errorf("expected zero LayerCount, got %d", item.LayerCount)
	}

	if item.Annotations != nil {
		t.Errorf("expected nil Annotations, got %v", item.Annotations)
	}
}

func TestNewListCommand_RunEExists(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewListCommand(getFlags)

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewListCommand_FlagTypes(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewListCommand(getFlags)

	// Verify repository is a string flag
	repoFlag := cmd.Flags().Lookup("repository")
	if repoFlag == nil {
		t.Fatal("repository flag not found")
	}
	if repoFlag.Value.Type() != "string" {
		t.Errorf("expected repository flag to be string, got %s", repoFlag.Value.Type())
	}

	// Verify prefix is a string flag
	prefixFlag := cmd.Flags().Lookup("prefix")
	if prefixFlag == nil {
		t.Fatal("prefix flag not found")
	}
	if prefixFlag.Value.Type() != "string" {
		t.Errorf("expected prefix flag to be string, got %s", prefixFlag.Value.Type())
	}

	// Verify limit is an integer flag (int or int32)
	limitFlag := cmd.Flags().Lookup("limit")
	if limitFlag == nil {
		t.Fatal("limit flag not found")
	}
	limitType := limitFlag.Value.Type()
	if !strings.HasPrefix(limitType, "int") {
		t.Errorf("expected limit flag to be int type, got %s", limitType)
	}

	// Verify cursor is a string flag
	cursorFlag := cmd.Flags().Lookup("cursor")
	if cursorFlag == nil {
		t.Fatal("cursor flag not found")
	}
	if cursorFlag.Value.Type() != "string" {
		t.Errorf("expected cursor flag to be string, got %s", cursorFlag.Value.Type())
	}

	// Verify show-encrypted is a bool flag
	showEncryptedFlag := cmd.Flags().Lookup("show-encrypted")
	if showEncryptedFlag == nil {
		t.Fatal("show-encrypted flag not found")
	}
	if showEncryptedFlag.Value.Type() != "bool" {
		t.Errorf("expected show-encrypted flag to be bool, got %s", showEncryptedFlag.Value.Type())
	}

	// Verify sort-by is a string flag
	sortByFlag := cmd.Flags().Lookup("sort-by")
	if sortByFlag == nil {
		t.Fatal("sort-by flag not found")
	}
	if sortByFlag.Value.Type() != "string" {
		t.Errorf("expected sort-by flag to be string, got %s", sortByFlag.Value.Type())
	}

	// Verify sort-desc is a bool flag
	sortDescFlag := cmd.Flags().Lookup("sort-desc")
	if sortDescFlag == nil {
		t.Fatal("sort-desc flag not found")
	}
	if sortDescFlag.Value.Type() != "bool" {
		t.Errorf("expected sort-desc flag to be bool, got %s", sortDescFlag.Value.Type())
	}
}

func TestNewListCommand_HasAliases(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewListCommand(getFlags)

	// Check if there are aliases (ls is common for list)
	if len(cmd.Aliases) > 0 {
		// Just verify they exist, don't enforce specific aliases
		t.Logf("list command has aliases: %v", cmd.Aliases)
	}
}

func TestListResult_ZeroValues(t *testing.T) {
	var result ListResult

	if result.Images != nil {
		t.Errorf("expected nil Images, got %v", result.Images)
	}

	if result.TotalCount != 0 {
		t.Errorf("expected zero TotalCount, got %d", result.TotalCount)
	}

	if result.HasMore {
		t.Error("expected HasMore to be false")
	}

	if result.NextCursor != "" {
		t.Errorf("expected empty NextCursor, got %q", result.NextCursor)
	}
}

// Tests for convertListResponse function
func TestConvertListResponse_EmptyResponse(t *testing.T) {
	resp := &platformv1.ListArtifactsResponse{
		Artifacts: []*platformv1.Artifact{},
		Total:     0,
		HasMore:   false,
	}

	result := convertListResponse(resp)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result.Images) != 0 {
		t.Errorf("expected 0 images, got %d", len(result.Images))
	}

	if result.TotalCount != 0 {
		t.Errorf("expected TotalCount 0, got %d", result.TotalCount)
	}

	if result.HasMore {
		t.Error("expected HasMore to be false")
	}
}

func TestConvertListResponse_WithArtifacts(t *testing.T) {
	createdAt := timestamppb.Now()
	pushedAt := timestamppb.Now()

	resp := &platformv1.ListArtifactsResponse{
		Artifacts: []*platformv1.Artifact{
			{
				Repository:   "myrepo",
				Tag:          "v1.0",
				Digest:       "sha256:abc123",
				Size:         1024,
				Os:           "linux",
				Architecture: "amd64",
				CreatedAt:    createdAt,
				PushedAt:     pushedAt,
				Annotations:  map[string]string{"key": "value"},
				Manifest: &platformv1.ArtifactManifest{
					Layers: []*platformv1.ArtifactLayer{
						{Digest: "sha256:layer1"},
						{Digest: "sha256:layer2"},
					},
				},
			},
		},
		Total:      1,
		HasMore:    true,
		NextCursor: "cursor123",
	}

	result := convertListResponse(resp)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result.Images) != 1 {
		t.Fatalf("expected 1 image, got %d", len(result.Images))
	}

	img := result.Images[0]
	if img.Reference != "myrepo:v1.0" {
		t.Errorf("expected reference 'myrepo:v1.0', got %q", img.Reference)
	}

	if img.Digest != "sha256:abc123" {
		t.Errorf("expected digest 'sha256:abc123', got %q", img.Digest)
	}

	if img.Size != 1024 {
		t.Errorf("expected size 1024, got %d", img.Size)
	}

	if img.Platform != "linux/amd64" {
		t.Errorf("expected platform 'linux/amd64', got %q", img.Platform)
	}

	if img.LayerCount != 2 {
		t.Errorf("expected layer count 2, got %d", img.LayerCount)
	}

	if result.TotalCount != 1 {
		t.Errorf("expected TotalCount 1, got %d", result.TotalCount)
	}

	if !result.HasMore {
		t.Error("expected HasMore to be true")
	}

	if result.NextCursor != "cursor123" {
		t.Errorf("expected NextCursor 'cursor123', got %q", result.NextCursor)
	}
}

func TestConvertListResponse_WithPartialData(t *testing.T) {
	// Test with missing optional fields
	resp := &platformv1.ListArtifactsResponse{
		Artifacts: []*platformv1.Artifact{
			{
				Repository: "myrepo",
				Tag:        "",
				Digest:     "sha256:abc123",
				Size:       2048,
			},
		},
		Total:   1,
		HasMore: false,
	}

	result := convertListResponse(resp)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result.Images) != 1 {
		t.Fatalf("expected 1 image, got %d", len(result.Images))
	}

	img := result.Images[0]
	// When tag is empty, reference should just be repository
	if img.Reference != "myrepo" {
		t.Errorf("expected reference 'myrepo', got %q", img.Reference)
	}

	// Platform should be empty if both OS and arch are empty
	if img.Platform != "" {
		t.Errorf("expected empty platform, got %q", img.Platform)
	}

	// LayerCount should be 0 if manifest is nil
	if img.LayerCount != 0 {
		t.Errorf("expected layer count 0, got %d", img.LayerCount)
	}
}

func TestConvertListResponse_NilArtifacts(t *testing.T) {
	resp := &platformv1.ListArtifactsResponse{
		Artifacts: nil,
		Total:     0,
	}

	result := convertListResponse(resp)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result.Images) != 0 {
		t.Errorf("expected 0 images, got %d", len(result.Images))
	}
}

func TestConvertListResponse_OnlyOS(t *testing.T) {
	resp := &platformv1.ListArtifactsResponse{
		Artifacts: []*platformv1.Artifact{
			{
				Repository: "myrepo",
				Tag:        "latest",
				Os:         "linux",
			},
		},
		Total: 1,
	}

	result := convertListResponse(resp)
	img := result.Images[0]

	if img.Platform != "linux/" {
		t.Errorf("expected platform 'linux/', got %q", img.Platform)
	}
}

func TestConvertListResponse_OnlyArchitecture(t *testing.T) {
	resp := &platformv1.ListArtifactsResponse{
		Artifacts: []*platformv1.Artifact{
			{
				Repository:   "myrepo",
				Tag:          "latest",
				Architecture: "arm64",
			},
		},
		Total: 1,
	}

	result := convertListResponse(resp)
	img := result.Images[0]

	if img.Platform != "/arm64" {
		t.Errorf("expected platform '/arm64', got %q", img.Platform)
	}
}

// Tests for buildReference function
func TestBuildReference_WithTag(t *testing.T) {
	ref := buildReference("myrepo/myimage", "v1.0")

	if ref != "myrepo/myimage:v1.0" {
		t.Errorf("expected 'myrepo/myimage:v1.0', got %q", ref)
	}
}

func TestBuildReference_WithoutTag(t *testing.T) {
	ref := buildReference("myrepo/myimage", "")

	if ref != "myrepo/myimage" {
		t.Errorf("expected 'myrepo/myimage', got %q", ref)
	}
}

func TestBuildReference_SimpleRepository(t *testing.T) {
	ref := buildReference("alpine", "latest")

	if ref != "alpine:latest" {
		t.Errorf("expected 'alpine:latest', got %q", ref)
	}
}

func TestBuildReference_EmptyRepository(t *testing.T) {
	ref := buildReference("", "v1.0")

	if ref != ":v1.0" {
		t.Errorf("expected ':v1.0', got %q", ref)
	}
}

func TestBuildReference_BothEmpty(t *testing.T) {
	ref := buildReference("", "")

	if ref != "" {
		t.Errorf("expected empty string, got %q", ref)
	}
}

func TestConvertListResponse_MultipleArtifacts(t *testing.T) {
	resp := &platformv1.ListArtifactsResponse{
		Artifacts: []*platformv1.Artifact{
			{
				Repository: "repo1",
				Tag:        "v1.0",
				Digest:     "sha256:abc123",
				Size:       1000,
			},
			{
				Repository: "repo2",
				Tag:        "latest",
				Digest:     "sha256:def456",
				Size:       2000,
			},
			{
				Repository: "repo3",
				Tag:        "v2.0",
				Digest:     "sha256:ghi789",
				Size:       3000,
			},
		},
		Total:      100,
		HasMore:    true,
		NextCursor: "page2",
	}

	result := convertListResponse(resp)

	if len(result.Images) != 3 {
		t.Errorf("expected 3 images, got %d", len(result.Images))
	}

	if result.TotalCount != 100 {
		t.Errorf("expected TotalCount 100, got %d", result.TotalCount)
	}

	expectedRefs := []string{"repo1:v1.0", "repo2:latest", "repo3:v2.0"}
	for i, expected := range expectedRefs {
		if result.Images[i].Reference != expected {
			t.Errorf("image %d: expected reference %q, got %q", i, expected, result.Images[i].Reference)
		}
	}
}

func TestConvertListResponse_WithNilTimestamps(t *testing.T) {
	resp := &platformv1.ListArtifactsResponse{
		Artifacts: []*platformv1.Artifact{
			{
				Repository: "myrepo",
				Tag:        "v1.0",
				Digest:     "sha256:abc123",
				CreatedAt:  nil,
				PushedAt:   nil,
			},
		},
		Total: 1,
	}

	result := convertListResponse(resp)
	img := result.Images[0]

	if img.CreatedAt != 0 {
		t.Errorf("expected CreatedAt 0, got %d", img.CreatedAt)
	}

	if img.PushedAt != 0 {
		t.Errorf("expected PushedAt 0, got %d", img.PushedAt)
	}
}

func TestConvertListResponse_WithNilManifest(t *testing.T) {
	resp := &platformv1.ListArtifactsResponse{
		Artifacts: []*platformv1.Artifact{
			{
				Repository: "myrepo",
				Tag:        "v1.0",
				Manifest:   nil,
			},
		},
		Total: 1,
	}

	result := convertListResponse(resp)
	img := result.Images[0]

	if img.LayerCount != 0 {
		t.Errorf("expected LayerCount 0, got %d", img.LayerCount)
	}
}

func TestConvertListResponse_WithAnnotations(t *testing.T) {
	resp := &platformv1.ListArtifactsResponse{
		Artifacts: []*platformv1.Artifact{
			{
				Repository: "myrepo",
				Tag:        "v1.0",
				Annotations: map[string]string{
					"author":  "test",
					"version": "1.0.0",
				},
			},
		},
		Total: 1,
	}

	result := convertListResponse(resp)
	img := result.Images[0]

	if len(img.Annotations) != 2 {
		t.Errorf("expected 2 annotations, got %d", len(img.Annotations))
	}

	if img.Annotations["author"] != "test" {
		t.Errorf("expected author 'test', got %q", img.Annotations["author"])
	}
}
