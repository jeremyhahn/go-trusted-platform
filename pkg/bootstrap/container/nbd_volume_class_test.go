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

package container

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/nbd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/volume"
)

// The local NBD store is a block provider of the storage-class seam.
var _ volume.Provider = (*nbd.LocalVolumes)(nil)

// assertLocalFiles creates and attaches one device's volume and checks it
// is the local file under dir.
func assertLocalFiles(t *testing.T, volumes nbd.VolumeProvider, dir string) {
	t.Helper()
	require.NoError(t, volumes.Create("nbd-01", 4096))
	path, err := volumes.Attach("nbd-01")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "nbd-01.img"), path)
}

// requireStorageClassError checks err is the server config error naming
// nbd.storage_class and that it wraps want.
func requireStorageClassError(t *testing.T, err, want error) {
	t.Helper()
	require.Error(t, err)
	assert.True(t, errors.Is(err, want), "errors.Is(%v, %v)", err, want)
	var invalid ErrInvalidServerConfig
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "nbd.storage_class", invalid.Field)
}

func TestNBDVolumes_DefaultClassIsLocalFiles(t *testing.T) {
	dir := t.TempDir()
	volumes, err := nbdVolumes(&ServerConfig{NBD: NBDConfig{VolumeDir: dir}})
	require.NoError(t, err)
	assertLocalFiles(t, volumes, dir)
}

func TestNBDVolumes_GeneralClassIsLocalFiles(t *testing.T) {
	dir := t.TempDir()
	volumes, err := nbdVolumes(&ServerConfig{NBD: NBDConfig{VolumeDir: dir, StorageClass: volume.ClassGeneral}})
	require.NoError(t, err)
	assertLocalFiles(t, volumes, dir)
}

func TestNBDVolumes_ReplicatedClassHasNoProviderYet(t *testing.T) {
	volumes, err := nbdVolumes(&ServerConfig{NBD: NBDConfig{VolumeDir: t.TempDir(), StorageClass: volume.ClassReplicated}})
	requireStorageClassError(t, err, volume.ErrNoProviderFactory)
	assert.Contains(t, err.Error(), volume.ProviderDRBD)
	assert.Nil(t, volumes)
}

func TestNBDVolumes_ObjectClassIsNotBlock(t *testing.T) {
	volumes, err := nbdVolumes(&ServerConfig{NBD: NBDConfig{VolumeDir: t.TempDir(), StorageClass: volume.ClassObject}})
	requireStorageClassError(t, err, volume.ErrObjectClassNotBlock)
	assert.Nil(t, volumes)
}

func TestNBDVolumes_UnknownClass(t *testing.T) {
	volumes, err := nbdVolumes(&ServerConfig{NBD: NBDConfig{VolumeDir: t.TempDir(), StorageClass: "nope"}})
	requireStorageClassError(t, err, volume.ErrUnknownClass)
	assert.Nil(t, volumes)
}

func TestNBDVolumes_ConfiguredClassesReplaceTheDefaults(t *testing.T) {
	dir := t.TempDir()
	config := &ServerConfig{
		NBD: NBDConfig{VolumeDir: dir},
		Volume: &volume.Config{
			DefaultClass: "fast",
			Classes:      []volume.StorageClass{{Name: "fast", Provider: volume.ProviderLocal}},
		},
	}
	volumes, err := nbdVolumes(config)
	require.NoError(t, err)
	assertLocalFiles(t, volumes, dir)

	// The built-in classes are gone once the config names its own.
	config.NBD.StorageClass = volume.ClassGeneral
	_, err = nbdVolumes(config)
	requireStorageClassError(t, err, volume.ErrUnknownClass)
}

func TestServerConfig_ApplyDefaults_VolumeConfig(t *testing.T) {
	unset := &ServerConfig{}
	unset.ApplyDefaults()
	assert.Equal(t, volume.DefaultConfig(), unset.Volume)

	own := &volume.Config{
		DefaultClass: "fast",
		Classes:      []volume.StorageClass{{Name: "fast", Provider: volume.ProviderLocal}},
	}
	set := &ServerConfig{Volume: own}
	set.ApplyDefaults()
	assert.Same(t, own, set.Volume)
	assert.Equal(t, "fast", set.Volume.DefaultClass)
	assert.Len(t, set.Volume.Classes, 1)
}

func TestServerConfig_Validate_VolumeConfig(t *testing.T) {
	config := validServerConfig()
	require.NoError(t, config.Validate())

	config.Volume = volume.DefaultConfig()
	require.NoError(t, config.Validate())

	config.Volume = &volume.Config{
		Classes: []volume.StorageClass{
			{Name: "fast", Provider: volume.ProviderLocal},
			{Name: "fast", Provider: volume.ProviderLocal},
		},
	}
	err := config.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, volume.ErrDuplicateClass), "errors.Is(%v, ErrDuplicateClass)", err)
	var invalid ErrInvalidServerConfig
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "volume", invalid.Field)
}
