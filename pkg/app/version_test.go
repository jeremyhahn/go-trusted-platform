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

package app

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetVersion(t *testing.T) {
	// Save original values
	origName := Name
	origRepository := Repository
	origPackage := Package
	origVersion := Version
	origBuildDate := BuildDate
	origBuildUser := BuildUser
	origGitBranch := GitBranch
	origGitTag := GitTag
	origGitHash := GitHash

	// Restore original values after test
	defer func() {
		Name = origName
		Repository = origRepository
		Package = origPackage
		Version = origVersion
		BuildDate = origBuildDate
		BuildUser = origBuildUser
		GitBranch = origGitBranch
		GitTag = origGitTag
		GitHash = origGitHash
	}()

	// Set test values
	Name = "test-platform"
	Repository = "github.com/jeremyhahn/go-trusted-platform"
	Package = "platformctl"
	Version = "1.4.0"
	BuildDate = "2025-12-19T00:00:00Z"
	BuildUser = "test-user"
	GitBranch = "main"
	GitTag = "v1.4.0"
	GitHash = "abc123def456"

	version := GetVersion()

	require.NotNil(t, version)
	assert.Equal(t, "test-platform", version.Name)
	assert.Equal(t, "github.com/jeremyhahn/go-trusted-platform", version.Repository)
	assert.Equal(t, "platformctl", version.Package)
	assert.Equal(t, "1.4.0", version.Version)
	assert.Equal(t, "2025-12-19T00:00:00Z", version.BuildDate)
	assert.Equal(t, "test-user", version.BuildUser)
	assert.Equal(t, "main", version.GitBranch)
	assert.Equal(t, "v1.4.0", version.GitTag)
	assert.Equal(t, "abc123def456", version.GitHash)
}

func TestGetVersionWithEmptyFields(t *testing.T) {
	// Save original values
	origName := Name
	origRepository := Repository
	origPackage := Package
	origVersion := Version
	origBuildDate := BuildDate
	origBuildUser := BuildUser
	origGitBranch := GitBranch
	origGitTag := GitTag
	origGitHash := GitHash

	// Restore original values after test
	defer func() {
		Name = origName
		Repository = origRepository
		Package = origPackage
		Version = origVersion
		BuildDate = origBuildDate
		BuildUser = origBuildUser
		GitBranch = origGitBranch
		GitTag = origGitTag
		GitHash = origGitHash
	}()

	// Clear all values
	Name = ""
	Repository = ""
	Package = ""
	Version = ""
	BuildDate = ""
	BuildUser = ""
	GitBranch = ""
	GitTag = ""
	GitHash = ""

	version := GetVersion()

	require.NotNil(t, version)
	assert.Empty(t, version.Name)
	assert.Empty(t, version.Repository)
	assert.Empty(t, version.Package)
	assert.Empty(t, version.Version)
	assert.Empty(t, version.BuildDate)
	assert.Empty(t, version.BuildUser)
	assert.Empty(t, version.GitBranch)
	assert.Empty(t, version.GitTag)
	assert.Empty(t, version.GitHash)
}

func TestAppVersionJSONMarshal(t *testing.T) {
	version := &AppVersion{
		Name:       "test-platform",
		Repository: "github.com/jeremyhahn/go-trusted-platform",
		Package:    "platformctl",
		Version:    "1.4.0",
		GitBranch:  "main",
		GitTag:     "v1.4.0",
		GitHash:    "abc123def456",
		BuildDate:  "2025-12-19T00:00:00Z",
		BuildUser:  "test-user",
	}

	data, err := json.Marshal(version)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Verify we can unmarshal it back
	var unmarshaled AppVersion
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, version.Name, unmarshaled.Name)
	assert.Equal(t, version.Repository, unmarshaled.Repository)
	assert.Equal(t, version.Package, unmarshaled.Package)
	assert.Equal(t, version.Version, unmarshaled.Version)
	assert.Equal(t, version.GitBranch, unmarshaled.GitBranch)
	assert.Equal(t, version.GitTag, unmarshaled.GitTag)
	assert.Equal(t, version.GitHash, unmarshaled.GitHash)
	assert.Equal(t, version.BuildDate, unmarshaled.BuildDate)
	assert.Equal(t, version.BuildUser, unmarshaled.BuildUser)
}

func TestAppVersionJSONUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    *AppVersion
		wantErr bool
	}{
		{
			name: "complete version info",
			json: `{
				"name": "test-platform",
				"repository": "github.com/jeremyhahn/go-trusted-platform",
				"package": "platformctl",
				"version": "1.4.0",
				"gitBranch": "main",
				"gitTag": "v1.4.0",
				"gitHash": "abc123def456",
				"buildDate": "2025-12-19T00:00:00Z",
				"buildUser": "test-user"
			}`,
			want: &AppVersion{
				Name:       "test-platform",
				Repository: "github.com/jeremyhahn/go-trusted-platform",
				Package:    "platformctl",
				Version:    "1.4.0",
				GitBranch:  "main",
				GitTag:     "v1.4.0",
				GitHash:    "abc123def456",
				BuildDate:  "2025-12-19T00:00:00Z",
				BuildUser:  "test-user",
			},
			wantErr: false,
		},
		{
			name: "minimal version info",
			json: `{
				"name": "test-platform",
				"version": "1.0.0"
			}`,
			want: &AppVersion{
				Name:    "test-platform",
				Version: "1.0.0",
			},
			wantErr: false,
		},
		{
			name:    "empty object",
			json:    `{}`,
			want:    &AppVersion{},
			wantErr: false,
		},
		{
			name:    "invalid JSON",
			json:    `{invalid}`,
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got AppVersion
			err := json.Unmarshal([]byte(tt.json), &got)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tt.want != nil {
				assert.Equal(t, tt.want.Name, got.Name)
				assert.Equal(t, tt.want.Repository, got.Repository)
				assert.Equal(t, tt.want.Package, got.Package)
				assert.Equal(t, tt.want.Version, got.Version)
				assert.Equal(t, tt.want.GitBranch, got.GitBranch)
				assert.Equal(t, tt.want.GitTag, got.GitTag)
				assert.Equal(t, tt.want.GitHash, got.GitHash)
				assert.Equal(t, tt.want.BuildDate, got.BuildDate)
				assert.Equal(t, tt.want.BuildUser, got.BuildUser)
			}
		})
	}
}

func TestAppVersionStruct(t *testing.T) {
	version := &AppVersion{
		Name:       "platform",
		Repository: "github.com/example/repo",
		Package:    "pkg",
		Version:    "1.0.0",
		GitBranch:  "develop",
		GitTag:     "v1.0.0",
		GitHash:    "hash123",
		BuildDate:  "2025-12-19",
		BuildUser:  "builder",
	}

	assert.Equal(t, "platform", version.Name)
	assert.Equal(t, "github.com/example/repo", version.Repository)
	assert.Equal(t, "pkg", version.Package)
	assert.Equal(t, "1.0.0", version.Version)
	assert.Equal(t, "develop", version.GitBranch)
	assert.Equal(t, "v1.0.0", version.GitTag)
	assert.Equal(t, "hash123", version.GitHash)
	assert.Equal(t, "2025-12-19", version.BuildDate)
	assert.Equal(t, "builder", version.BuildUser)
}

func TestGlobalVersionVariables(t *testing.T) {
	// Save originals
	origName := Name
	origRepository := Repository
	origPackage := Package
	origVersion := Version
	origBuildDate := BuildDate
	origBuildUser := BuildUser
	origGitBranch := GitBranch
	origGitTag := GitTag
	origGitHash := GitHash
	origImage := Image

	// Restore after test
	defer func() {
		Name = origName
		Repository = origRepository
		Package = origPackage
		Version = origVersion
		BuildDate = origBuildDate
		BuildUser = origBuildUser
		GitBranch = origGitBranch
		GitTag = origGitTag
		GitHash = origGitHash
		Image = origImage
	}()

	// Test that we can modify global variables
	Name = "test-name"
	Repository = "test-repo"
	Package = "test-pkg"
	Version = "1.0.0-test"
	BuildDate = "test-date"
	BuildUser = "test-user"
	GitBranch = "test-branch"
	GitTag = "test-tag"
	GitHash = "test-hash"
	Image = "test-image"

	assert.Equal(t, "test-name", Name)
	assert.Equal(t, "test-repo", Repository)
	assert.Equal(t, "test-pkg", Package)
	assert.Equal(t, "1.0.0-test", Version)
	assert.Equal(t, "test-date", BuildDate)
	assert.Equal(t, "test-user", BuildUser)
	assert.Equal(t, "test-branch", GitBranch)
	assert.Equal(t, "test-tag", GitTag)
	assert.Equal(t, "test-hash", GitHash)
	assert.Equal(t, "test-image", Image)
}

func TestGetVersionReflectsGlobalVariables(t *testing.T) {
	// Save originals
	origName := Name
	origVersion := Version

	// Restore after test
	defer func() {
		Name = origName
		Version = origVersion
	}()

	// Set specific values
	Name = "dynamic-test"
	Version = "2.0.0"

	version := GetVersion()

	assert.Equal(t, "dynamic-test", version.Name)
	assert.Equal(t, "2.0.0", version.Version)

	// Change values again
	Name = "changed-test"
	Version = "3.0.0"

	version2 := GetVersion()

	assert.Equal(t, "changed-test", version2.Name)
	assert.Equal(t, "3.0.0", version2.Version)

	// First version object should still have old values
	assert.Equal(t, "dynamic-test", version.Name)
	assert.Equal(t, "2.0.0", version.Version)
}
