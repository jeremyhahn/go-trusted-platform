package bootstrap

import (
	"context"
	"crypto/tls"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sharedBMCTLSProvider stands in for the run-shared provider so a test can
// tell whether nodeBMCTLSProvider fell back to it.
type sharedBMCTLSProvider struct{}

func (sharedBMCTLSProvider) TLSConfig(context.Context, string) (*tls.Config, error) {
	return &tls.Config{ServerName: "shared"}, nil
}

func TestOrchestrator_NodeBMCTLSProvider(t *testing.T) {
	shared := sharedBMCTLSProvider{}
	o := &Orchestrator{logger: quietTestLogger(), bmcTLSProvider: shared, trustConfig: &trust.Config{}}

	t.Run("node without bmc trust uses the shared provider", func(t *testing.T) {
		assert.Equal(t, shared, o.nodeBMCTLSProvider(&NodeConfig{Hostname: "node-01"}))
	})

	t.Run("node with an spki pin gets its own provider", func(t *testing.T) {
		bmc := newFakeBMC(t)
		provider := o.nodeBMCTLSProvider(&NodeConfig{Hostname: "node-07", BMCSPKIPin: bmc.spkiPin})
		require.NotNil(t, provider)
		assert.NotEqual(t, shared, provider)

		tlsCfg, err := provider.TLSConfig(context.Background(), bmc.endpoint)
		require.NoError(t, err)
		conn, err := tls.Dial("tcp", bmc.endpoint, tlsCfg)
		require.NoError(t, err, "the per-node provider must verify the pinned BMC")
		require.NoError(t, conn.Close())
	})

	t.Run("unbuildable node trust falls back to the shared provider", func(t *testing.T) {
		node := &NodeConfig{Hostname: "node-09", BMCTrust: []trust.Strategy{"nonsense"}}
		assert.Equal(t, shared, o.nodeBMCTLSProvider(node))
	})
}

func TestStrategiesStr(t *testing.T) {
	assert.Equal(t, "(none)", strategiesStr(nil))
	assert.Equal(t, "spki", strategiesStr([]trust.Strategy{trust.StrategySPKI}))
	assert.Equal(t, "spki,tofu", strategiesStr([]trust.Strategy{trust.StrategySPKI, trust.StrategyTOFU}))
}

func TestPlaintextSecretFields_FollowsSequenceMergeKeys(t *testing.T) {
	doc := []byte(`
base: &base
  user: admin
creds: &creds
  password: merged-literal
bmc:
  <<: [*base, *creds]
`)
	got, err := PlaintextSecretFields(doc, reflect.TypeFor[secretFieldsSchema]())
	require.NoError(t, err)
	assert.Equal(t, []string{"bmc.password"}, got)
}

func TestConfigWriter_AtomicWriteFailures(t *testing.T) {
	t.Run("missing directory fails before a temp file exists", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "absent", "bootstrap.yaml")
		w, err := NewConfigWriter(path, quietTestLogger())
		require.NoError(t, err)

		err = w.atomicWrite([]byte("data"))

		var writeErr ErrAtomicWriteFailed
		require.ErrorAs(t, err, &writeErr)
		assert.Empty(t, writeErr.TempPath)
		assert.Equal(t, path, writeErr.TargetPath)
		assert.ErrorIs(t, err, fs.ErrNotExist)
	})

	t.Run("failed rename removes the temp file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bootstrap.yaml")
		require.NoError(t, os.Mkdir(path, 0o750))
		w, err := NewConfigWriter(path, quietTestLogger())
		require.NoError(t, err)

		err = w.atomicWrite([]byte("data"))

		var writeErr ErrAtomicWriteFailed
		require.ErrorAs(t, err, &writeErr)
		assert.NotEmpty(t, writeErr.TempPath)
		_, statErr := os.Stat(writeErr.TempPath)
		assert.ErrorIs(t, statErr, fs.ErrNotExist, "the temp file must not be left behind")
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Len(t, entries, 1, "only the target directory may remain")
	})
}

func TestExpandShortKMSPath(t *testing.T) {
	tests := []struct {
		name, path, tenant, node, want string
	}{
		{"short path expands", "bmc-password", "acme", "node-01", "tenants/acme/nodes/node-01/secrets/bmc-password"},
		{"full path unchanged", "tenants/other/nodes/n/secrets/x", "acme", "node-01", "tenants/other/nodes/n/secrets/x"},
		{"no tenant unchanged", "bmc-password", "", "node-01", "bmc-password"},
		{"no node unchanged", "bmc-password", "acme", "", "bmc-password"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ExpandShortKMSPath(tt.path, tt.tenant, tt.node))
		})
	}
}

func TestNodeConfig_PrimaryMAC(t *testing.T) {
	assert.Equal(t, "aa:bb:cc:dd:ee:01", (&NodeConfig{MACs: []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}}).PrimaryMAC())
	assert.Empty(t, (&NodeConfig{}).PrimaryMAC())
}

func TestDefaultConfig_NoiseServerDisabledWithBoundedDefaults(t *testing.T) {
	cfg := DefaultConfig()
	require.NotNil(t, cfg.Noise)
	assert.Equal(t, NoiseServerConfig{
		Enabled:        false,
		ListenAddr:     ":9999",
		MaxConnections: 100,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
	}, *cfg.Noise)
}
