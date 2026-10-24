package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/deployer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// recordingDeployer is a deployer.Deployer that records the calls the
// adapter makes and returns scripted errors.
type recordingDeployer struct {
	verifyErr   error
	deployErr   error
	teardownErr error

	verifyCalls   int
	deployCalls   int
	teardownCalls int

	// deployedManifest is the manifest file content read while Deploy
	// runs, and deployedPath its path: the adapter removes the file
	// once Deploy returns.
	deployedManifest container.Manifest
	deployedPath     string
	teardownConfig   *deployer.DeployConfig
}

func (r *recordingDeployer) Deploy(_ context.Context, dc *deployer.DeployConfig) (*deployer.DeployResult, error) {
	r.deployCalls++
	r.deployedPath = dc.ManifestPath
	data, err := os.ReadFile(dc.ManifestPath)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, &r.deployedManifest); err != nil {
		return nil, err
	}
	if r.deployErr != nil {
		return nil, r.deployErr
	}
	return &deployer.DeployResult{}, nil
}

func (r *recordingDeployer) Verify(_ context.Context, _ *deployer.DeployConfig) error {
	r.verifyCalls++
	return r.verifyErr
}

func (r *recordingDeployer) Teardown(_ context.Context, dc *deployer.DeployConfig) error {
	r.teardownCalls++
	r.teardownConfig = dc
	return r.teardownErr
}

func testManifest() *container.Manifest {
	return &container.Manifest{Nodes: []container.ManifestEntry{
		{MAC: "aa:bb:cc:dd:ee:ff", Role: "control-plane", Hostname: "node-01"},
	}}
}

func TestLinuxDeployerAdapter_Deploy_RedeployModes(t *testing.T) {
	errStale := errors.New("image mismatch")
	notRunning := deployer.ErrContainerNotRunning{ContainerID: "bootstrap", Host: "10.0.0.1"}

	tests := []struct {
		name        string
		mode        string
		verifyErr   error
		wantVerify  int
		wantDeploy  int
		wantErrCaus error
	}{
		{name: "always skips verify and deploys", mode: "always", wantVerify: 0, wantDeploy: 1},
		{name: "if-stale with matching container skips deploy", mode: "if-stale", wantVerify: 1, wantDeploy: 0},
		{name: "if-stale with stale container redeploys", mode: "if-stale", verifyErr: errStale, wantVerify: 1, wantDeploy: 1},
		{name: "empty mode behaves as if-stale", mode: "", wantVerify: 1, wantDeploy: 0},
		{name: "unknown mode behaves as if-stale", mode: "sometimes", verifyErr: errStale, wantVerify: 1, wantDeploy: 1},
		{name: "never with matching container skips deploy", mode: "never", wantVerify: 1, wantDeploy: 0},
		{name: "never with no container permits first deploy", mode: "never", verifyErr: notRunning, wantVerify: 1, wantDeploy: 1},
		{name: "never with mismatched container fails", mode: "never", verifyErr: errStale, wantVerify: 1, wantDeploy: 0, wantErrCaus: errStale},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &recordingDeployer{verifyErr: tt.verifyErr}
			cfg := &DeployerConfig{Host: "10.0.0.1", RedeployMode: tt.mode}
			adapter := newLinuxDeployerAdapter(cfg, backend, nil)

			err := adapter.Deploy(context.Background(), testManifest())

			assert.Equal(t, tt.wantVerify, backend.verifyCalls, "verify calls")
			assert.Equal(t, tt.wantDeploy, backend.deployCalls, "deploy calls")
			if tt.wantErrCaus != nil {
				var deployErr ErrContainerDeployFailed
				require.ErrorAs(t, err, &deployErr)
				assert.Equal(t, "10.0.0.1", deployErr.Host)
				assert.ErrorIs(t, err, tt.wantErrCaus)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestLinuxDeployerAdapter_Deploy_StagesManifestAndRemovesIt(t *testing.T) {
	backend := &recordingDeployer{}
	adapter := newLinuxDeployerAdapter(&DeployerConfig{Host: "10.0.0.1", RedeployMode: "always"}, backend, nil)

	require.NoError(t, adapter.Deploy(context.Background(), testManifest()))

	assert.Equal(t, *testManifest(), backend.deployedManifest)
	_, err := os.Stat(backend.deployedPath)
	assert.True(t, os.IsNotExist(err), "manifest tempfile must be removed after deploy, stat err = %v", err)
}

func TestLinuxDeployerAdapter_Deploy_Errors(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		backend := &recordingDeployer{}
		err := newLinuxDeployerAdapter(nil, backend, nil).Deploy(context.Background(), testManifest())

		var cfgErr ErrInvalidConfig
		require.ErrorAs(t, err, &cfgErr)
		assert.Equal(t, "deployer", cfgErr.Field)
		assert.Zero(t, backend.deployCalls)
	})

	t.Run("nil manifest", func(t *testing.T) {
		backend := &recordingDeployer{}
		err := newLinuxDeployerAdapter(&DeployerConfig{Host: "10.0.0.1"}, backend, nil).Deploy(context.Background(), nil)

		var deployErr ErrContainerDeployFailed
		require.ErrorAs(t, err, &deployErr)
		var msgErr *MessageError
		require.ErrorAs(t, err, &msgErr)
		assert.Equal(t, "manifest is nil", msgErr.Msg)
		assert.Zero(t, backend.verifyCalls)
		assert.Zero(t, backend.deployCalls)
	})

	t.Run("backend deploy failure", func(t *testing.T) {
		cause := errors.New("ssh: connection refused")
		backend := &recordingDeployer{deployErr: cause}
		err := newLinuxDeployerAdapter(&DeployerConfig{Host: "10.0.0.1", RedeployMode: "always"}, backend, nil).
			Deploy(context.Background(), testManifest())

		var deployErr ErrContainerDeployFailed
		require.ErrorAs(t, err, &deployErr)
		assert.Equal(t, "10.0.0.1", deployErr.Host)
		assert.ErrorIs(t, err, cause)
	})
}

func TestLinuxDeployerAdapter_Teardown(t *testing.T) {
	t.Run("success passes no manifest", func(t *testing.T) {
		backend := &recordingDeployer{}
		cfg := &DeployerConfig{Host: "10.0.0.1", DataDir: "/srv/bootstrap"}

		require.NoError(t, newLinuxDeployerAdapter(cfg, backend, nil).Teardown(context.Background()))

		assert.Equal(t, 1, backend.teardownCalls)
		require.NotNil(t, backend.teardownConfig)
		assert.Empty(t, backend.teardownConfig.ManifestPath)
		assert.Equal(t, "/srv/bootstrap", backend.teardownConfig.DataDir)
	})

	t.Run("nil config", func(t *testing.T) {
		backend := &recordingDeployer{}
		err := newLinuxDeployerAdapter(nil, backend, nil).Teardown(context.Background())

		var cfgErr ErrInvalidConfig
		require.ErrorAs(t, err, &cfgErr)
		assert.Zero(t, backend.teardownCalls)
	})

	t.Run("backend failure", func(t *testing.T) {
		cause := errors.New("docker rm failed")
		backend := &recordingDeployer{teardownErr: cause}
		err := newLinuxDeployerAdapter(&DeployerConfig{Host: "10.0.0.1"}, backend, nil).Teardown(context.Background())

		var tdErr ErrContainerTeardownFailed
		require.ErrorAs(t, err, &tdErr)
		assert.Equal(t, "10.0.0.1", tdErr.Host)
		assert.ErrorIs(t, err, cause)
	})
}

func TestNewLinuxDeployerAdapter(t *testing.T) {
	valid := func() *DeployerConfig {
		return &DeployerConfig{
			Host:           "10.0.0.1",
			User:           "ops",
			SSHKey:         "/keys/id_ed25519",
			ContainerImage: "registry/bootstrap:1",
		}
	}

	t.Run("valid config", func(t *testing.T) {
		d, err := NewLinuxDeployerAdapter(valid(), nil)
		require.NoError(t, err)
		adapter, ok := d.(*linuxDeployerAdapter)
		require.True(t, ok)
		assert.NotNil(t, adapter.backend)
		assert.NotNil(t, adapter.logger)
	})

	t.Run("nil config", func(t *testing.T) {
		_, err := NewLinuxDeployerAdapter(nil, nil)
		var cfgErr ErrInvalidConfig
		require.ErrorAs(t, err, &cfgErr)
	})

	missing := []struct {
		field string
		clear func(*DeployerConfig)
	}{
		{"deployer.host", func(c *DeployerConfig) { c.Host = "" }},
		{"deployer.user", func(c *DeployerConfig) { c.User = "" }},
		{"deployer.ssh_key", func(c *DeployerConfig) { c.SSHKey = "" }},
		{"deployer.container_image", func(c *DeployerConfig) { c.ContainerImage = "" }},
	}
	for _, tt := range missing {
		t.Run("missing "+tt.field, func(t *testing.T) {
			cfg := valid()
			tt.clear(cfg)
			_, err := NewLinuxDeployerAdapter(cfg, nil)
			var fieldErr ErrMissingRequiredField
			require.ErrorAs(t, err, &fieldErr)
			assert.Equal(t, tt.field, fieldErr.Field)
		})
	}
}

func TestExpandUserHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"/etc/ssh/key", "/etc/ssh/key"},
		{"relative/key", "relative/key"},
		{"~", home},
		{"~/.ssh/id_ed25519", filepath.Join(home, ".ssh", "id_ed25519")},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, expandUserHome(tt.in), "expandUserHome(%q)", tt.in)
	}
}

func TestExpandUserHome_NoHomeLeavesPathUnchanged(t *testing.T) {
	t.Setenv("HOME", "")
	assert.Equal(t, "~/.ssh/id_ed25519", expandUserHome("~/.ssh/id_ed25519"))
}
