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

package firstboot

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	tpconfig "github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/secrets"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

const gatewayPlatformConfig = `domain: gw.example.com
platform:
  name: node-01
sdn:
  enabled: true
  bridge: br-fabric
platform-ca-file: /etc/gatewayd/cp-ca.pem
trust:
  bmc:
    strategies: [spki, tofu]
secret-store:
  quicbaas-addr: cp.example.internal:9443
  quicbaas-transport: grpc
  timeout: 10s
gateway:
  enabled: true
  id: node-01-gateway
  node-id: 1
  tier: datacenter
  firewall:
    enabled: true
    default-policy: deny
control-plane:
  enabled: true
  base-url: https://cp.example.internal:8443
  gateway-id: node-01-gateway
  interval: 30s
  cert-file: /etc/gatewayd/client.pem
  key-file: /etc/gatewayd/client-key.pem
  ca-file: /etc/gatewayd/cp-ca.pem
tpm:
  device: /dev/tpmrm0
webservices:
  - name: public
    port: 8080
`

func allPresent(string) bool  { return true }
func nonePresent(string) bool { return false }

func decodeYAML(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	require.NoError(t, yaml.Unmarshal(data, &doc))
	return doc
}

func TestRenderGatewaydConfig_ProjectsOnlyGatewaydSections(t *testing.T) {
	rendered, err := renderGatewaydConfig([]byte(gatewayPlatformConfig), allPresent)
	require.NoError(t, err)

	doc := decodeYAML(t, rendered)
	for _, section := range []string{"gateway", "sdn", "trust", "platform-ca-file", "secret-store", "control-plane"} {
		assert.Contains(t, doc, section)
	}
	assert.NotContains(t, doc, "proxy", "a section the platform config lacks is not invented")
	for section := range doc {
		assert.Contains(t, tpconfig.GatewaydConfigSections, section, "only gatewayd sections are rendered")
	}
	assert.NotContains(t, doc, "tpm", "platformd-only sections must not leak into gatewayd")
	assert.NotContains(t, doc, "webservices")
	assert.NotContains(t, doc, "platform")

	cp := doc["control-plane"].(map[string]any)
	assert.Equal(t, true, cp["enabled"])
	assert.Equal(t, "node-01-gateway", cp["gateway-id"])
	gw := doc["gateway"].(map[string]any)
	assert.Equal(t, "node-01-gateway", gw["id"])
	assert.True(t, strings.HasPrefix(string(rendered), "# gatewayd configuration rendered by platformd firstboot"))

	// The section is projected with its CONTENT, not merely present, and
	// the content is decoded against the schema gatewayd actually reads —
	// secrets.Config and trust.Config. Asserting projected keys against a
	// shape invented here would pass for a section gatewayd then rejects,
	// which resolves no kms:// reference at all: the same failure as
	// dropping the section.
	var projected struct {
		Secrets        *secrets.Config `yaml:"secret-store"`
		Trust          *trust.Config   `yaml:"trust"`
		PlatformCAFile string          `yaml:"platform-ca-file"`
	}
	require.NoError(t, yaml.Unmarshal(rendered, &projected))

	require.NotNil(t, projected.Secrets, "the secret store section must survive projection")
	assert.Equal(t, "cp.example.internal:9443", projected.Secrets.QuicBaaSAddr,
		"the gateway dials the store at this address")
	assert.Equal(t, "grpc", projected.Secrets.QuicBaaSTransport)
	assert.Equal(t, 10*time.Second, projected.Secrets.Timeout)
	require.NoError(t, projected.Secrets.Validate(),
		"gatewayd validates this section at load; a projection it rejects resolves nothing")

	// The platform anchor is the secret store's precondition: it
	// authenticates the session, and gatewayd runs no CA, so on a gateway
	// node the anchor is this projected bundle. Dropping the key would leave
	// every kms:// reference unresolvable.
	assert.Equal(t, "/etc/gatewayd/cp-ca.pem", projected.PlatformCAFile,
		"gatewayd runs no CA; its platform anchor is this bundle")
	require.NotNil(t, projected.Trust, "the trust section must survive projection")
	require.NotNil(t, projected.Trust.Scope(trust.ClassBMC))
	require.NoError(t, projected.Trust.Validate())
}

func TestRenderGatewaydConfig_MissingIdentityDisablesTheReporter(t *testing.T) {
	present := func(path string) bool { return path == "/etc/gatewayd/cp-ca.pem" }
	rendered, err := renderGatewaydConfig([]byte(gatewayPlatformConfig), present)

	var missing *ErrGatewaydIdentityMissing
	require.True(t, errors.As(err, &missing), "got %v", err)
	assert.ElementsMatch(t, []string{"/etc/gatewayd/client.pem", "/etc/gatewayd/client-key.pem"}, missing.Missing)
	assert.Contains(t, err.Error(), "control-plane.enabled: true")

	doc := decodeYAML(t, rendered)
	cp := doc["control-plane"].(map[string]any)
	assert.Equal(t, false, cp["enabled"], "the reporter must not crash-loop on a missing identity")
	assert.Equal(t, "https://cp.example.internal:8443", cp["base-url"], "the rest of the section is kept for the operator")
}

func TestRenderGatewaydConfig_UnconfiguredIdentityIsNamed(t *testing.T) {
	cfg := "gateway:\n  enabled: true\ncontrol-plane:\n  enabled: true\n  base-url: https://cp\n"
	_, err := renderGatewaydConfig([]byte(cfg), allPresent)
	var missing *ErrGatewaydIdentityMissing
	require.True(t, errors.As(err, &missing))
	assert.ElementsMatch(t, []string{"cert-file (not configured)", "key-file (not configured)", "ca-file (not configured)"}, missing.Missing)
}

func TestRenderGatewaydConfig_DisabledReporterIsNotChecked(t *testing.T) {
	cfg := "gateway:\n  enabled: true\ncontrol-plane:\n  enabled: false\n  base-url: https://cp\n"
	rendered, err := renderGatewaydConfig([]byte(cfg), nonePresent)
	require.NoError(t, err)
	cp := decodeYAML(t, rendered)["control-plane"].(map[string]any)
	assert.Equal(t, false, cp["enabled"])
}

func TestRenderGatewaydConfig_NoControlPlaneSection(t *testing.T) {
	rendered, err := renderGatewaydConfig([]byte("gateway:\n  enabled: true\n  id: g\n"), nonePresent)
	require.NoError(t, err)
	doc := decodeYAML(t, rendered)
	assert.NotContains(t, doc, "control-plane")
	assert.Contains(t, doc, "gateway")
}

func TestRenderGatewaydConfig_UnparseableConfig(t *testing.T) {
	_, err := renderGatewaydConfig([]byte("gateway: [oops"), allPresent)
	var want *tpconfig.ErrPlatformConfigUnreadable
	require.True(t, errors.As(err, &want), "got %v", err)
}

// TestGatewaydOpenRCScript_MatchesTheFleet pins the script shape the fleet
// runs: the binary path, the config path, the log, and the ordering after
// platformd. A change here changes how every gateway boots.
func TestGatewaydOpenRCScript_MatchesTheFleet(t *testing.T) {
	script := renderGatewaydInitScript(false)
	assert.True(t, strings.HasPrefix(script, "#!/sbin/openrc-run\n"))
	for _, want := range []string{
		`command="/usr/sbin/gatewayd"`,
		`command_args="serve --config /etc/gatewayd/config.yaml"`,
		`command_background=true`,
		`output_log="/var/log/trusted-platform/gatewayd.log"`,
		"need localmount networking",
		"after platformd",
		"keyword -shutdown",
	} {
		assert.Contains(t, script, want)
	}
}

// gatewayNAT64PlatformConfig enables the gateway's nat64: section (#603).
const gatewayNAT64PlatformConfig = `gateway:
  enabled: true
  id: node-01-gateway
  nat64:
    enabled: true
    translator-port: nat640
    pool4:
      addresses: ["203.0.113.64/29"]
`

// TestRenderGatewaydInitScript_NAT64LoadsJool pins the module load: an
// enabled nat64: section needs the Jool kernel module before gatewayd
// starts, and a module that will not load must not stop the daemon — the
// section is refused with ErrNAT64ModuleUnavailable instead (#603).
func TestRenderGatewaydInitScript_NAT64LoadsJool(t *testing.T) {
	loadJool, err := gatewaydNAT64Enabled([]byte(gatewayNAT64PlatformConfig))
	require.NoError(t, err)
	require.True(t, loadJool)

	script := renderGatewaydInitScript(loadJool)
	startPreAt := strings.Index(script, "start_pre() {")
	require.NotEqual(t, -1, startPreAt, "the init script defines start_pre")
	startPre := script[startPreAt:]
	assert.Contains(t, startPre, "if ! modprobe jool; then",
		"a failed modprobe is guarded so start_pre still succeeds")
	assert.Contains(t, startPre, "ewarn ")
	assert.True(t, strings.HasSuffix(script, "    fi\n}\n"), "the module load ends start_pre")
}

func TestRenderGatewaydInitScript_NoNAT64LoadsNothing(t *testing.T) {
	disabled := strings.Replace(gatewayNAT64PlatformConfig, "    enabled: true\n    translator-port", "    enabled: false\n    translator-port", 1)
	for name, config := range map[string]string{
		"no nat64 section":       gatewayPlatformConfig,
		"disabled nat64 section": disabled,
		"null nat64 section":     "gateway:\n  enabled: true\n  nat64:\n",
	} {
		t.Run(name, func(t *testing.T) {
			loadJool, err := gatewaydNAT64Enabled([]byte(config))
			require.NoError(t, err)
			assert.False(t, loadJool)
			assert.NotContains(t, renderGatewaydInitScript(loadJool), "modprobe")
		})
	}
}

func TestGatewaydNAT64Enabled_UnparseableConfig(t *testing.T) {
	_, err := gatewaydNAT64Enabled([]byte("gateway: [x"))
	var unreadable *tpconfig.ErrPlatformConfigUnreadable
	assert.ErrorAs(t, err, &unreadable)
}

func TestInstallGatewaydService_NAT64ScriptLoadsJool(t *testing.T) {
	paths := testPaths(t)
	rc := &rcRecorder{}
	err := installGatewaydServiceAt([]byte(gatewayNAT64PlatformConfig), paths, allPresent, rc.run, noLog, noLog)
	require.NoError(t, err)

	script, err := os.ReadFile(paths.initScript)
	require.NoError(t, err)
	assert.Equal(t, renderGatewaydInitScript(true), string(script))
	assert.Contains(t, string(script), "modprobe jool", "modprobe runs on the node, never in the generator")
	assert.Equal(t, [][]string{
		{"rc-update", "add", "gatewayd", "default"},
		{"rc-service", "gatewayd", "start"},
	}, rc.calls)
}

type rcRecorder struct {
	calls [][]string
	fail  map[string]error
}

func (r *rcRecorder) run(name string, args ...string) ([]byte, error) {
	call := append([]string{name}, args...)
	r.calls = append(r.calls, call)
	if err, ok := r.fail[strings.Join(call, " ")]; ok {
		return []byte("simulated failure"), err
	}
	return nil, nil
}

func noLog(string, ...any) {}

func testPaths(t *testing.T) gatewaydInstallPaths {
	t.Helper()
	root := t.TempDir()
	return gatewaydInstallPaths{
		configDir:  filepath.Join(root, "etc", "gatewayd"),
		initScript: filepath.Join(root, "etc", "init.d", "gatewayd"),
	}
}

func TestInstallGatewaydService_GatewayRoleInstallsEverything(t *testing.T) {
	paths := testPaths(t)
	rc := &rcRecorder{}
	err := installGatewaydServiceAt([]byte(gatewayPlatformConfig), paths, allPresent, rc.run, noLog, noLog)
	require.NoError(t, err)

	script, err := os.ReadFile(paths.initScript)
	require.NoError(t, err)
	assert.Equal(t, renderGatewaydInitScript(false), string(script))
	assert.NotContains(t, string(script), "modprobe", "no nat64: section, no module load")
	stat, err := os.Stat(paths.initScript)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), stat.Mode().Perm())

	cfgPath := filepath.Join(paths.configDir, "config.yaml")
	stat, err = os.Stat(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), stat.Mode().Perm(), "the config names the reporter's private key")
	dirStat, err := os.Stat(paths.configDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), dirStat.Mode().Perm())

	assert.Equal(t, [][]string{
		{"rc-update", "add", "gatewayd", "default"},
		{"rc-service", "gatewayd", "start"},
	}, rc.calls)
}

func TestInstallGatewaydService_OtherRolesDoNothing(t *testing.T) {
	paths := testPaths(t)
	rc := &rcRecorder{}
	for _, cfg := range []string{"sdn:\n  enabled: true\n", "gateway:\n  enabled: false\n"} {
		require.NoError(t, installGatewaydServiceAt([]byte(cfg), paths, allPresent, rc.run, noLog, noLog))
	}
	assert.Empty(t, rc.calls)
	_, err := os.Stat(paths.initScript)
	assert.True(t, os.IsNotExist(err))
}

func TestInstallGatewaydService_MissingIdentityStillInstalls(t *testing.T) {
	paths := testPaths(t)
	rc := &rcRecorder{}
	present := func(path string) bool { return path == "/usr/sbin/gatewayd" }
	var warned []string
	warn := func(msg string, kv ...any) { warned = append(warned, msg) }

	err := installGatewaydServiceAt([]byte(gatewayPlatformConfig), paths, present, rc.run, noLog, warn)
	var missing *ErrGatewaydIdentityMissing
	require.True(t, errors.As(err, &missing), "got %v", err)

	// Installed and enabled regardless, with the reporter off.
	_, statErr := os.Stat(paths.initScript)
	require.NoError(t, statErr)
	rendered, readErr := os.ReadFile(filepath.Join(paths.configDir, "config.yaml"))
	require.NoError(t, readErr)
	cp := decodeYAML(t, rendered)["control-plane"].(map[string]any)
	assert.Equal(t, false, cp["enabled"])
	assert.Len(t, rc.calls, 2)
	assert.NotEmpty(t, warned)
}

func TestInstallGatewaydService_BinaryAbsentIsAnError(t *testing.T) {
	paths := testPaths(t)
	rc := &rcRecorder{}
	err := installGatewaydServiceAt([]byte(gatewayPlatformConfig), paths, nonePresent, rc.run, noLog, noLog)
	var want *ErrGatewaydBinaryAbsent
	require.True(t, errors.As(err, &want), "got %v", err)
	assert.Empty(t, rc.calls)
}

func TestInstallGatewaydService_EnableFailureIsAnError(t *testing.T) {
	paths := testPaths(t)
	rc := &rcRecorder{fail: map[string]error{"rc-update add gatewayd default": errors.New("rc-update: not found")}}
	err := installGatewaydServiceAt([]byte(gatewayPlatformConfig), paths, allPresent, rc.run, noLog, noLog)
	var want *CommandOutputError
	require.True(t, errors.As(err, &want), "got %v", err)
	assert.Contains(t, err.Error(), "simulated failure")
}

func TestInstallGatewaydService_StartFailureOnlyWarns(t *testing.T) {
	paths := testPaths(t)
	rc := &rcRecorder{fail: map[string]error{"rc-service gatewayd start": errors.New("exit 1")}}
	var warned []string
	warn := func(msg string, kv ...any) { warned = append(warned, msg) }
	err := installGatewaydServiceAt([]byte(gatewayPlatformConfig), paths, allPresent, rc.run, noLog, warn)
	require.NoError(t, err)
	assert.Contains(t, warned, "Failed to start gatewayd service")
}

func TestInstallGatewaydService_UnparseableConfig(t *testing.T) {
	rc := &rcRecorder{}
	err := installGatewaydServiceAt([]byte("gateway: [x"), testPaths(t), allPresent, rc.run, noLog, noLog)
	require.Error(t, err)
	assert.Empty(t, rc.calls)
}

func TestInstallGatewaydService_UnwritableConfigDir(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "etc")
	require.NoError(t, os.WriteFile(blocker, []byte("not a dir"), 0644))
	paths := gatewaydInstallPaths{
		configDir:  filepath.Join(blocker, "gatewayd"),
		initScript: filepath.Join(blocker, "init.d", "gatewayd"),
	}
	rc := &rcRecorder{}
	err := installGatewaydServiceAt([]byte(gatewayPlatformConfig), paths, allPresent, rc.run, noLog, noLog)
	var want *WrappedError
	require.True(t, errors.As(err, &want), "got %v", err)
	assert.Empty(t, rc.calls)
}

func TestErrGatewaydBinaryAbsent_Message(t *testing.T) {
	assert.Contains(t, (&ErrGatewaydBinaryAbsent{}).Error(), "/usr/sbin")
}
