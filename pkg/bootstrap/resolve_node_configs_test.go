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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// newResolveOrchestrator builds an orchestrator over minimalConfig plus a
// worker, with one template per role written to a temp dir.
func newResolveOrchestrator(t *testing.T) *Orchestrator {
	t.Helper()
	dir := t.TempDir()
	cfg := minimalConfig()
	cfg.Nodes = append(cfg.Nodes, NodeConfig{Hostname: "w1", Role: RoleWorker, MACs: []string{"aa:bb:cc:dd:ee:02"}})
	cfg.Templates = map[string]string{}
	for _, role := range []string{RoleControlPlane, RoleWorker} {
		path := filepath.Join(dir, role+".yaml")
		require.NoError(t, os.WriteFile(path, []byte("os:\n    hostname: template-host\n"), 0o600))
		cfg.Templates[role] = path
	}
	o, err := NewOrchestrator(OrchestratorParams{
		Config:     cfg,
		BMCFactory: &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:     orchTestLogger(),
	})
	require.NoError(t, err)
	return o
}

func TestResolveNodeConfigs_AllNodesInConfigOrder(t *testing.T) {
	resolved, err := newResolveOrchestrator(t).ResolveNodeConfigs()
	require.NoError(t, err)
	require.Len(t, resolved, 2)

	assert.Equal(t, "cp1", resolved[0].Hostname)
	assert.Equal(t, RoleControlPlane, resolved[0].Role)
	assert.Equal(t, "w1", resolved[1].Hostname)
	assert.Equal(t, RoleWorker, resolved[1].Role)
	// The node identity replaces the template's hostname.
	assert.Contains(t, resolved[0].Config, "hostname: cp1")
	assert.Contains(t, resolved[1].Config, "hostname: w1")
	assert.NotContains(t, resolved[1].Config, "template-host")
}

func TestResolveNodeConfigs_NamedHostsOnly(t *testing.T) {
	resolved, err := newResolveOrchestrator(t).ResolveNodeConfigs("w1")
	require.NoError(t, err)
	require.Len(t, resolved, 1)
	assert.Equal(t, "w1", resolved[0].Hostname)
}

func TestResolveNodeConfigs_UnknownHost(t *testing.T) {
	_, err := newResolveOrchestrator(t).ResolveNodeConfigs("cp1", "nope")
	var unknown ErrUnknownNode
	require.ErrorAs(t, err, &unknown)
	assert.Equal(t, "nope", unknown.Hostname)
}

func TestResolveNodeConfigs_MissingTemplate(t *testing.T) {
	o := newResolveOrchestrator(t)
	delete(o.config.Templates, RoleWorker)

	_, err := o.ResolveNodeConfigs()
	var failed ErrNodeConfigResolveFailed
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, "w1", failed.Hostname)
	var noTemplate ErrTemplateNotFoundForRole
	assert.ErrorAs(t, err, &noTemplate, "the cause stays reachable")
}

// ValidateDefinition is the check for read-only work: it passes a config
// whose netboot media build does not exist, which Validate refuses.
func TestValidateDefinition_IgnoresNetbootMedia(t *testing.T) {
	cfg := minimalConfig()
	cfg.Deployer.NetbootMediaDir = filepath.Join(t.TempDir(), "not-built")

	require.NoError(t, cfg.ValidateDefinition())
	var media ErrNetbootMediaRequired
	assert.ErrorAs(t, cfg.Validate(), &media)
}

func TestValidateDefinition_StillChecksTheDefinition(t *testing.T) {
	cfg := minimalConfig()
	cfg.Deployer.Host = ""

	var missing ErrMissingRequiredField
	require.ErrorAs(t, cfg.ValidateDefinition(), &missing)
	assert.Equal(t, "deployer.host", missing.Field)
}
