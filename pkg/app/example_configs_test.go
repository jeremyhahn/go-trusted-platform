package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// exampleDirs are the directories under configs/platform whose
// *.example.com.yaml files the docker-compose and qemu flows beside them
// start. platformd loads the server and client examples; gatewayd loads
// the gateway examples, which carry the platformd sections too.
var exampleDirs = []string{"cluster", "standalone"}

// shippedExamples lists every example config the compose and qemu flows
// start.
func shippedExamples(t *testing.T) []string {
	t.Helper()
	var paths []string
	for _, dir := range exampleDirs {
		found, err := filepath.Glob(filepath.Join(configRoot, "platform", dir, "*.example.com.yaml"))
		require.NoError(t, err)
		paths = append(paths, found...)
	}
	require.Len(t, paths, 11, "the example set changed; review this test")
	return paths
}

// TestShippedExamples_LoadOnTheCurrentSchema holds every example to the
// checks platformd runs on its configuration file before it opens a
// store: the strict network/sdn key check and the full decode, the
// required quicbaas identity and section, the host network and the
// provisioning web services. It also proves no example carries a literal
// secret: every secret is a kms:// reference, and the secrets section that
// resolves those references is on.
func TestShippedExamples_LoadOnTheCurrentSchema(t *testing.T) {
	for _, path := range shippedExamples(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			a := loadTemplate(t, path)
			require.NoError(t, checkRequiredConfig(path, a.QuicBaaSConfig))
			require.NoError(t, a.QuicBaaSConfig.Validate())
			require.NoError(t, a.validateHostNetwork())
			require.NoError(t, a.validateWebServices())

			require.NotNil(t, a.SecretsConfig, "the secrets section resolves the kms:// references")
			assert.True(t, a.SecretsConfig.Enabled, "secrets.enabled")
			assert.True(t, a.SecretsConfig.LocalKMS, "secrets.local-kms")

			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			var doc map[string]any
			require.NoError(t, yaml.Unmarshal(raw, &doc))
			var kms int
			walkSecrets(doc, "", func(key, value string) {
				assert.True(t, strings.HasPrefix(value, "kms://"), "%s is not a kms:// reference", key)
				kms++
			})
			assert.Positive(t, kms, "the example sets its secrets")
		})
	}
}

// TestWalkSecrets_ReportsUnquotedLiteral proves the secret walk can fail
// on the literal the examples used to carry: an unquoted number decodes as
// an int, and it is reported like a quoted string. An empty value is not.
func TestWalkSecrets_ReportsUnquotedLiteral(t *testing.T) {
	var doc map[string]any
	require.NoError(t, yaml.Unmarshal([]byte("acme:\n  password: 123456\ntpm:\n  ek:\n    password: \"\"\n  srk-auth:\n"), &doc))
	found := map[string]string{}
	walkSecrets(doc, "", func(key, value string) { found[key] = value })
	assert.Equal(t, map[string]string{".acme.password": "123456"}, found)
}
