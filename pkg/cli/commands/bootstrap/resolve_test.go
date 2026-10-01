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

package bootstrap

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgbootstrap "github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
)

// writeResolveDeployment writes a two-node bootstrap.yaml whose netboot
// media build does not exist, which resolve must not need.
func writeResolveDeployment(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	tpl := filepath.Join(dir, "templates")
	require.NoError(t, os.MkdirAll(tpl, 0o700))
	for _, role := range []string{"control-plane", "worker"} {
		require.NoError(t, os.WriteFile(filepath.Join(tpl, role+".yaml"), []byte("os:\n    hostname: template-host\n"), 0o600))
	}
	cfg := `deployer:
  host: deploy-host
  netboot_media_dir: not-built
environment:
  id: 4
platform:
  domain: example.com
templates:
  control-plane: templates/control-plane.yaml
  worker: templates/worker.yaml
nodes:
  - hostname: cp1
    role: control-plane
    macs: ["02:00:00:00:00:01"]
    interfaces:
      - name: eth0
        address: 192.0.2.10/24
        gateway: 192.0.2.1
  - hostname: w1
    role: worker
    macs: ["02:00:00:00:00:02"]
`
	path := filepath.Join(dir, "bootstrap.yaml")
	require.NoError(t, os.WriteFile(path, []byte(cfg), 0o600))
	return path
}

func TestRunResolve_PrintsEveryNode(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, runResolve(writeResolveDeployment(t), nil, "", nil, &out))

	docs := strings.Split(out.String(), "\n---\n")
	require.Len(t, docs, 2, "one YAML document per node")
	assert.True(t, strings.HasPrefix(docs[0], "# cp1 (control-plane)\n"))
	assert.Contains(t, docs[0], "hostname: cp1")
	assert.True(t, strings.HasPrefix(docs[1], "# w1 (worker)\n"))
	assert.Contains(t, docs[1], "hostname: w1")
}

func TestRunResolve_DumpWritesOneFilePerNode(t *testing.T) {
	dump := filepath.Join(t.TempDir(), "resolved")
	var out bytes.Buffer
	require.NoError(t, runResolve(writeResolveDeployment(t), []string{"w1"}, dump, nil, &out))

	assert.Equal(t, filepath.Join(dump, "w1.yaml")+"\n", out.String())
	data, err := os.ReadFile(filepath.Join(dump, "w1.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "hostname: w1")
	info, err := os.Stat(filepath.Join(dump, "w1.yaml"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "resolved configs carry credential references")
	_, err = os.Stat(filepath.Join(dump, "cp1.yaml"))
	assert.True(t, os.IsNotExist(err), "only the named node is written")
}

func TestRunResolve_Errors(t *testing.T) {
	var out bytes.Buffer

	assert.ErrorAs(t, runResolve("", nil, "", nil, &out), &ErrPXEConfigRequired{})

	var load ErrPXEConfigLoadFailed
	assert.ErrorAs(t, runResolve(filepath.Join(t.TempDir(), "missing.yaml"), nil, "", nil, &out), &load)

	var unknown pkgbootstrap.ErrUnknownNode
	assert.ErrorAs(t, runResolve(writeResolveDeployment(t), []string{"nope"}, "", nil, &out), &unknown)

	// A file where the dump directory should be.
	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	var dump ErrResolveDumpFailed
	assert.ErrorAs(t, runResolve(writeResolveDeployment(t), nil, blocker, nil, &out), &dump)
}

func TestRunResolve_InvalidDefinition(t *testing.T) {
	path := writeResolveDeployment(t)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, bytes.Replace(data, []byte("  host: deploy-host\n"), nil, 1), 0o600))

	var invalid ErrPXEConfigValidationFailed
	assert.ErrorAs(t, runResolve(path, nil, "", nil, &bytes.Buffer{}), &invalid)
}
