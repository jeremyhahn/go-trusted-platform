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
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// deployOrchestrator is minimalConfig's orchestrator driving dep (nil for
// none) with a serving container.
func deployOrchestrator(t *testing.T, dep Deployer) *Orchestrator {
	t.Helper()
	params := OrchestratorParams{
		Config:                minimalConfig(),
		BMCFactory:            &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:                orchTestLogger(),
		HealthChecker:         &mockHealthChecker{},
		ConfigServerReadiness: readyConfigServer{},
	}
	if dep != nil {
		params.Deployer = dep
	}
	o, err := NewOrchestrator(params)
	require.NoError(t, err)
	return o
}

// TestOrchestratorDeploy_IsRunsFirstThreePhases: bootstrap deploy is Run's
// Phases 0-2 — discovery feeds the manifest the container is deployed with,
// and the phase ends once it is serving.
func TestOrchestratorDeploy_IsRunsFirstThreePhases(t *testing.T) {
	dep := &mockDeployer{}
	result, err := deployOrchestrator(t, dep).Deploy(context.Background())
	require.NoError(t, err)

	assert.True(t, result.ContainerDeployed)
	assert.Equal(t, phaseDeploy, result.Phase)
	assert.Len(t, result.Nodes, 1)
	assert.Equal(t, int64(1), dep.deployCalls.Load())
	require.NotNil(t, dep.manifest, "the manifest comes from discovery")
	require.Len(t, dep.manifest.Nodes, 1)
	assert.Equal(t, "cp1", dep.manifest.Nodes[0].Hostname)
}

// TestOrchestratorDeploy_Errors: no deployer is refused before discovery;
// a failed deploy is reported as the deploy phase.
func TestOrchestratorDeploy_Errors(t *testing.T) {
	var none ErrDeployerNotConfigured
	_, err := deployOrchestrator(t, nil).Deploy(context.Background())
	require.ErrorAs(t, err, &none)
	assert.Contains(t, err.Error(), "container_image")

	boom := errors.New("docker run failed")
	result, err := deployOrchestrator(t, &mockDeployer{deployErr: boom}).Deploy(context.Background())
	var failed ErrBootstrapFailed
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, phaseDeploy, failed.Phase)
	assert.ErrorIs(t, err, boom)
	assert.False(t, result.ContainerDeployed)
}

// TestOrchestratorTeardown: teardown goes to the deployer, its failure is
// typed, and with no deployer there is nothing to tear down.
func TestOrchestratorTeardown(t *testing.T) {
	require.NoError(t, deployOrchestrator(t, &mockDeployer{}).Teardown(context.Background()))

	boom := errors.New("docker rm failed")
	var failed ErrContainerTeardownFailed
	err := deployOrchestrator(t, &mockDeployer{teardownErr: boom}).Teardown(context.Background())
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, "deploy-host", failed.Host)
	assert.ErrorIs(t, err, boom)

	var none ErrDeployerNotConfigured
	assert.ErrorAs(t, deployOrchestrator(t, nil).Teardown(context.Background()), &none)
}
