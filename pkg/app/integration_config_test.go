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
	"bytes"
	"errors"
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ntp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

// integrationConfig is the platformd config run-integration-tests.sh starts
// the shared daemon on.
const integrationConfig = "../../test/integration/config.yaml"

// barrierGateConfig is the platformd config the barrier-gate suite starts its
// own daemon on, with the shared daemon stopped.
const barrierGateConfig = "../../test/integration/barrier_gate/config.yaml"

// integrationRunner is the script that starts swtpm and both daemons.
const integrationRunner = "../../build/docker/devcontainer/run-integration-tests.sh"

// swtpmServerSocket matches the Unix socket start_swtpm serves the TPM on.
var swtpmServerSocket = regexp.MustCompile(`--server type=unixio,path=(\S+)`)

// harnessSwtpmSocket returns the socket a runner script serves swtpm on, and
// false when the script serves it on no Unix socket.
func harnessSwtpmSocket(script []byte) (string, bool) {
	match := swtpmServerSocket.FindSubmatch(script)
	if match == nil {
		return "", false
	}
	return string(match[1]), true
}

// TestIntegrationConfig_TPMIsHarnessSwtpm holds both integration daemons to
// the swtpm the runner starts. The integration container is privileged, so it
// sees the host's /dev/tpmrm0: a config naming that device runs platformd on
// the CI host's own TPM, which on a host with no active SHA-256 PCR bank stops
// the daemon at "PCR 23 is not present in bank 0x000b" (main c2e37b5e, CI run
// 54912) and in any case provisions a TPM the suite does not own.
func TestIntegrationConfig_TPMIsHarnessSwtpm(t *testing.T) {
	script, err := os.ReadFile(integrationRunner)
	require.NoError(t, err)
	socket, ok := harnessSwtpmSocket(script)
	require.True(t, ok, "start_swtpm serves swtpm on a Unix socket")

	for _, path := range []string{integrationConfig, barrierGateConfig} {
		a := loadTemplate(t, path)
		assert.False(t, a.TPMConfig.UseSimulator, "%s: tpm.simulator", path)
		assert.Equal(t, socket, a.TPMConfig.Device, "%s: tpm.device is the harness swtpm socket", path)

		// The embedded quicbaas server's TPM probe and tpm2 seal strategy
		// open the same socket, never the runner's /dev/tpmrm0.
		require.NotNil(t, a.QuicBaaSConfig, "%s: quicbaas section", path)
		a.mirrorTPMDevice()
		assert.Equal(t, socket, a.QuicBaaSConfig.ToQuicBaaSConfig().Seal.TPM2.Device,
			"%s: the embedded server's seal.tpm2.device is the harness swtpm socket", path)

		resolved, err := vtpm.ResolveTPMTarget(&a.TPMConfig, nil)
		if err != nil {
			var swtpmErr vtpm.ErrSwtpmSocketUnavailable
			assert.True(t, errors.As(err, &swtpmErr), "%s: resolves to swtpm, got %v", path, err)
			continue
		}
		assert.Equal(t, vtpm.TPMTargetSwtpm, resolved.Target, "%s: resolves to swtpm", path)
	}
}

// TestIntegrationConfig_EKCertIsTheSwtpmNVIndex holds both daemon configs to
// the NV index provision_swtpm_state writes the harness EK certificate to.
// With no tpm.ek.cert-handle, go-xkms looks for the EK certificate only in
// the platform's certificate store, which these configs never fill, so every
// transport's EK certificate call answered "not found".
func TestIntegrationConfig_EKCertIsTheSwtpmNVIndex(t *testing.T) {
	// TCG EK Credential Profile 2.1 §2.2.1.4: RSA 2048 EK certificate index.
	const rsa2048EKCertIndex = 0x01C00002

	for _, path := range []string{integrationConfig, barrierGateConfig} {
		a := loadTemplate(t, path)
		require.NotNil(t, a.TPMConfig.EK, "%s: tpm.ek", path)
		assert.Equal(t, uint32(rsa2048EKCertIndex), a.TPMConfig.EK.CertHandle,
			"%s: tpm.ek.cert-handle is the swtpm EK certificate index", path)
	}
}

// webserviceTLSPorts returns the TLS port of every webservice a config
// declares. None means daemon-only: `platformd serve` takes runDaemonOnly.
func webserviceTLSPorts(a *App) []string {
	var ports []string
	for _, ws := range a.WebServices {
		ports = append(ports, strconv.Itoa(ws.TLSPort))
	}
	return ports
}

// adminClaimServed reports whether platformd registers /api/v1/admin/claim
// for a: only the webservice registry mounts it, and only with an
// admin-email (pkg/webservice/v1/registry.go AdminClaimRestHandler). The
// address must also pass the IAM pattern the claim's passkey enrolment and
// the platform-local admin user are held to (pkg/platform/service/email.go).
func adminClaimServed(a *App) bool {
	if len(a.WebServices) == 0 || a.AdminEmail == "" {
		return false
	}
	return service.ValidateEmail(a.AdminEmail) == nil
}

// TestIntegrationConfig_RunMode pins the serve path each integration config
// takes. A webservices entry sends `platformd serve` into runWithWebservices
// (pkg/daemon/commands/serve.go), the path production runs.
// leaveRESTToWebservice sets RESTRoutesOnly: the daemon builds its REST route
// table but opens no REST listener, and the webservice mounts that table
// (daemonRESTRoutes) beside the webservice routers and the gatewayd-facing
// control plane. The Unix socket binds in platformDaemon.Start, after
// LoadOrInitCA and InitWebServer and before any webservice listener runs.
//
// The harness config serves REST from one webservice on the port the runner
// rewrites to its per-job PLATFORMD_REST_PORT, where PLATFORM_REST_ENDPOINT
// points. The barrier-gate
// config stays daemon-only: its suite starts its own platformd on its own
// ports and reaches REST on the daemon listener
// (test/integration/barrier_gate/helpers.go).
func TestIntegrationConfig_RunMode(t *testing.T) {
	script, err := os.ReadFile(integrationRunner)
	require.NoError(t, err)
	restPort, ok := harnessRESTPort(script)
	require.True(t, ok, "the runner rewrites the config's REST port to PLATFORMD_REST_PORT")

	tests := []struct {
		path  string
		ports []string
		claim bool
		mode  string
	}{
		{integrationConfig, []string{restPort}, true, "runWithWebservices, REST and /api/v1/admin/claim on the webservice"},
		{barrierGateConfig, nil, false, "daemon-only, REST on the daemon listener"},
	}
	for _, tt := range tests {
		a := loadTemplate(t, tt.path)
		assert.Equal(t, tt.ports, webserviceTLSPorts(a), "%s: %s", tt.path, tt.mode)
		assert.Equal(t, tt.claim, adminClaimServed(a), "%s: %s (admin-email %q)", tt.path, tt.mode, a.AdminEmail)
	}
}

// TestIntegrationConfig_RunModeMismatch proves the run-mode pin can fail: a
// daemon-only config, or a webservice on another port, does not serve REST
// where the runner's adapters dial.
func TestIntegrationConfig_RunModeMismatch(t *testing.T) {
	daemonOnly := &App{}
	assert.NotEqual(t, []string{"8443"}, webserviceTLSPorts(daemonOnly), "no webservice serves no REST port")

	otherPort := &App{WebServices: []*v1.Config{{TLSPort: 9443}}}
	assert.NotEqual(t, []string{"8443"}, webserviceTLSPorts(otherPort), "a webservice on 9443 is not the runner's 8443")

	twoServices := &App{WebServices: []*v1.Config{{TLSPort: 8443}, {TLSPort: 9443}}}
	assert.NotEqual(t, []string{"8443"}, webserviceTLSPorts(twoServices), "a second webservice changes the mode the pin names")

	webservice := []*v1.Config{{TLSPort: 8443}}
	assert.False(t, adminClaimServed(&App{WebServices: webservice}),
		"no admin-email: the registry leaves /api/v1/admin/claim unregistered")
	assert.False(t, adminClaimServed(&App{WebServices: webservice, AdminEmail: "admin@localhost"}),
		"an address IAM refuses (no dotted domain) cannot back the claim")
	assert.False(t, adminClaimServed(&App{AdminEmail: "admin@integration.internal"}),
		"daemon-only: no webservice mounts the admin-claim routes, whatever the email")
	assert.True(t, adminClaimServed(&App{WebServices: webservice, AdminEmail: "admin@integration.internal"}),
		"a webservice with an IAM-valid admin-email serves the claim")
}

// TestIntegrationConfig_TCPSwtpmNotASocket proves the socket check above can
// fail: a runner that serves swtpm over TCP gives the daemon no socket path.
func TestIntegrationConfig_TCPSwtpmNotASocket(t *testing.T) {
	script := []byte("swtpm socket --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322")
	socket, ok := harnessSwtpmSocket(script)
	assert.False(t, ok)
	assert.Empty(t, socket)
}

// swtpmProvisionScript provisions the harness swtpm's EK and EK certificate.
const swtpmProvisionScript = "../../build/docker/devcontainer/swtpm-provision.sh"

// The EK certificate NV indices swtpm_setup writes, from the Low Range of
// the TCG EK Credential Profile v2.1 §2.2.1.4 (0x01C00002 - 0x01C0000C).
const (
	ekCertIndexRSA2048 uint32 = 0x01C00002
	ekCertIndexECCP256 uint32 = 0x01C0000A
)

// harnessEKCertIndex returns the NV index swtpm_setup writes the EK
// certificate to, as the provisioning script invokes it: the RSA 2048 index,
// or the ECC P256 index under --ecc. It returns false when the script does
// not ask for an EK certificate.
func harnessEKCertIndex(script []byte) (uint32, bool) {
	if !bytes.Contains(script, []byte("--create-ek-cert")) {
		return 0, false
	}
	if bytes.Contains(script, []byte("--ecc")) {
		return ekCertIndexECCP256, true
	}
	return ekCertIndexRSA2048, true
}

// The harness swtpm carries a manufacturer-style EK certificate in NV. With
// no tpm.ek.cert-handle, go-xkms looks the certificate up in the platform
// certificate store instead, never reads NV, and `tpm ek certificate`
// answers NotFound on every transport.
func TestIntegrationConfig_EKCertificateAtHarnessIndex(t *testing.T) {
	script, err := os.ReadFile(swtpmProvisionScript)
	require.NoError(t, err)
	index, ok := harnessEKCertIndex(script)
	require.True(t, ok, "swtpm-provision.sh creates the EK certificate")

	for _, path := range []string{integrationConfig, barrierGateConfig} {
		a := loadTemplate(t, path)
		require.NotNil(t, a.TPMConfig.EK, "%s: tpm.ek", path)
		assert.Equal(t, index, a.TPMConfig.EK.CertHandle,
			"%s: tpm.ek.cert-handle is the NV index swtpm_setup writes the EK certificate to", path)
	}
}

func TestIntegrationConfig_EKCertIndexFollowsSwtpmSetup(t *testing.T) {
	index, ok := harnessEKCertIndex([]byte("swtpm_setup --tpm2 --createek --create-ek-cert --ecc"))
	assert.True(t, ok)
	assert.Equal(t, ekCertIndexECCP256, index)

	index, ok = harnessEKCertIndex([]byte("swtpm_setup --tpm2 --createek"))
	assert.False(t, ok, "no EK certificate without --create-ek-cert")
	assert.Zero(t, index)
}

// TestIntegrationConfig_LoadsWithDNSServer loads the integration config the
// way platformd does (strict network/sdn check, full decode) and checks the
// dns section strictly too: every key decodes, and it configures a server,
// so StartDNS and newDNSService give the daemon a DNS backend.
func TestIntegrationConfig_LoadsWithDNSServer(t *testing.T) {
	a := loadTemplate(t, integrationConfig)

	raw, err := os.ReadFile(integrationConfig)
	require.NoError(t, err)
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewReader(raw)))
	require.NoError(t, config.CheckViperSection(v, "dns", &dns.Config{}))

	require.NotNil(t, a.DNSConfig, "dns section")
	assert.True(t, a.DNSConfig.HasServer(), "dns section configures a server")
	require.NotNil(t, a.DNSConfig.InternalServer)
	assert.Equal(t, "integration.internal.", a.DNSConfig.InternalServer.Zone.Name)
	assert.Equal(t, uint32(300), a.DNSConfig.InternalServer.Zone.RecordSet.SOARecord.MinimumTTL,
		"the SOA minimum TTL decodes (its key is min_ttl)")
	assert.Nil(t, a.DNSConfig.DNSSEC, "DNSSEC stays off")
}

// TestIntegrationConfig_DNSTypoRefused proves the dns check above can fail:
// the shipped-example spelling minimum_ttl is not a key the SOA decodes.
func TestIntegrationConfig_DNSTypoRefused(t *testing.T) {
	raw, err := os.ReadFile(integrationConfig)
	require.NoError(t, err)
	typo := bytes.Replace(raw, []byte("min_ttl:"), []byte("minimum_ttl:"), 1)
	require.NotEqual(t, raw, typo, "the config carries an SOA min_ttl")

	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewReader(typo)))
	err = config.CheckViperSection(v, "dns", &dns.Config{})

	var unknown *config.ErrUnknownConfigKeys
	require.True(t, errors.As(err, &unknown), "got %v", err)
	assert.Equal(t, "dns", unknown.Section)
}

// TestIntegrationConfig_NTPConsumesFromLoopbackOnly pins the ntp section the
// ntp suite needs: without one every NTP call answers "not configured". The
// only upstream is the loopback, where nothing serves NTP, so no source is
// ever reachable and a step the suite sends is always refused: the
// devcontainer shares the CI host's clock.
func TestIntegrationConfig_NTPConsumesFromLoopbackOnly(t *testing.T) {
	a := loadTemplate(t, integrationConfig)

	raw, err := os.ReadFile(integrationConfig)
	require.NoError(t, err)
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewReader(raw)))
	require.NoError(t, config.CheckViperSection(v, "ntp", &ntp.Config{}))

	require.NotNil(t, a.NTPConfig, "ntp section")
	assert.True(t, a.NTPConfig.Active(), "the ntp service is enabled")
	require.NoError(t, a.NTPConfig.Validate())
	assert.Equal(t, ntp.ModeConsume, a.NTPConfig.Mode, "consume only: the node serves no time")
	require.NotNil(t, a.NTPConfig.Consume)
	require.Len(t, a.NTPConfig.Consume.Upstream, 1)
	assert.Equal(t, "127.0.0.1", a.NTPConfig.Consume.Upstream[0].Address,
		"the only upstream is the loopback, which never answers")
	require.NotNil(t, a.NTPConfig.Consume.StartupGate)
	assert.False(t, a.NTPConfig.Consume.StartupGate.BlockUntilSynced,
		"no startup gate: nothing will ever synchronize")
}

// TestIntegrationConfig_NTPTypoRefused proves the ntp section is checked
// strictly: a misspelt gate key is refused rather than silently enabling the
// default gate.
func TestIntegrationConfig_NTPTypoRefused(t *testing.T) {
	raw, err := os.ReadFile(integrationConfig)
	require.NoError(t, err)
	typo := bytes.Replace(raw, []byte("block-until-synced:"), []byte("block-until-sync:"), 1)
	require.NotEqual(t, raw, typo, "the config carries a startup gate")

	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewReader(typo)))
	err = config.CheckViperSection(v, "ntp", &ntp.Config{})

	var unknown *config.ErrUnknownConfigKeys
	require.True(t, errors.As(err, &unknown), "got %v", err)
	assert.Equal(t, "ntp", unknown.Section)
}

// restPortVariable is the REST port the harness config carries, which the
// runner rewrites to its per-job PLATFORMD_REST_PORT.
var restPortVariable = regexp.MustCompile(`(?m)^HARNESS_CONFIG_REST_PORT="(\d+)"$`)

// restPortRewrites are the sed expressions start_platformd applies to the
// config it starts platformd on: the webservice tls-port and the WebAuthn
// relying-party origin move to PLATFORMD_REST_PORT, where
// PLATFORM_REST_ENDPOINT points. With a webservice configured the daemon
// opens no REST listener (leaveRESTToWebservice), so --rest-port alone
// would leave REST on the config's port.
var restPortRewrites = [][]byte{
	[]byte(`"s|^\( *tls-port: \)${HARNESS_CONFIG_REST_PORT}\$|\1${PLATFORMD_REST_PORT}|"`),
	[]byte(`"s|https://localhost:${HARNESS_CONFIG_REST_PORT}\$|https://localhost:${PLATFORMD_REST_PORT}|"`),
}

// harnessRESTPort returns the REST port the harness config must carry: the
// one run-integration-tests.sh rewrites to the per-job port the adapters
// dial. It reports false unless the runner names that port and makes both
// rewrites.
func harnessRESTPort(script []byte) (string, bool) {
	match := restPortVariable.FindSubmatch(script)
	if match == nil {
		return "", false
	}
	for _, rewrite := range restPortRewrites {
		if !bytes.Contains(script, rewrite) {
			return "", false
		}
	}
	return string(match[1]), true
}

// TestIntegrationConfig_ServesRESTThroughWebservice guards the harness mode:
// without a webservice platformd runs daemon-only, whose REST lacks the
// webservice routers, and every REST adapter answers 404
// (docs/daemon/architecture.md).
func TestIntegrationConfig_ServesRESTThroughWebservice(t *testing.T) {
	a := loadTemplate(t, integrationConfig)

	require.Len(t, a.WebServices, 1, "one webservice serves the harness REST")
	ws := a.WebServices[0]

	script, err := os.ReadFile(integrationRunner)
	require.NoError(t, err)
	port, ok := harnessRESTPort(script)
	require.True(t, ok, "the runner rewrites the config's REST port to PLATFORMD_REST_PORT")
	assert.Equal(t, port, strconv.Itoa(ws.TLSPort), "the runner moves this port to PLATFORMD_REST_PORT, where PLATFORM_REST_ENDPOINT points")
	assert.Zero(t, ws.Port, "no plaintext listener")

	assert.Equal(t, "localhost", ws.Certificate.Subject.CommonName)
	require.NotNil(t, ws.Certificate.SANS)
	assert.Contains(t, ws.Certificate.SANS.DNS, "localhost", "the adapters dial https://localhost")
	require.NotNil(t, ws.Key, "the TLS key is required (ErrWebServiceKeyRequired)")
	assert.True(t, ws.Key.PlatformPolicy, "the key is sealed with the swtpm platform policy")
}

// TestIntegrationConfig_WebAuthnRelyingPartyIsHarnessOrigin pins the relying
// party the harness admin session registers its passkey against: the
// helper's origin is PLATFORM_REST_ENDPOINT, https://localhost:<REST port>,
// which the runner writes over the config's origin port.
func TestIntegrationConfig_WebAuthnRelyingPartyIsHarnessOrigin(t *testing.T) {
	a := loadTemplate(t, integrationConfig)

	require.Len(t, a.WebServices, 1, "one webservice serves the harness REST")
	ws := a.WebServices[0]
	require.NotNil(t, ws.WebAuthn, "the admin claim registers a passkey, so a relying party is required")

	script, err := os.ReadFile(integrationRunner)
	require.NoError(t, err)
	port, ok := harnessRESTPort(script)
	require.True(t, ok, "the runner rewrites the config's REST port to PLATFORMD_REST_PORT")
	assert.Equal(t, "localhost", ws.WebAuthn.RPID, "the RP id is the host the adapters dial")
	assert.Equal(t, []string{"https://localhost:" + port}, ws.WebAuthn.RPOrigins)
}

func TestIntegrationConfig_HarnessRESTPortMissing(t *testing.T) {
	rewrites := string(bytes.Join(restPortRewrites, []byte("\n")))
	tests := []struct {
		name   string
		script string
	}{
		{"commented port", "PLATFORMD_GRPC_PORT=\"10443\"\n# HARNESS_CONFIG_REST_PORT=\"8443\"\n" + rewrites + "\n"},
		{"no rewrite", "HARNESS_CONFIG_REST_PORT=\"8443\"\n"},
		{"tls-port rewrite only", "HARNESS_CONFIG_REST_PORT=\"8443\"\n" + string(restPortRewrites[0]) + "\n"},
		{"origin rewrite only", "HARNESS_CONFIG_REST_PORT=\"8443\"\n" + string(restPortRewrites[1]) + "\n"},
	}
	for _, tt := range tests {
		port, ok := harnessRESTPort([]byte(tt.script))
		assert.False(t, ok, "%s: the webservice stays off the runner's per-job port", tt.name)
		assert.Empty(t, port, tt.name)
	}

	port, ok := harnessRESTPort([]byte("HARNESS_CONFIG_REST_PORT=\"8443\"\n" + rewrites + "\n"))
	assert.True(t, ok, "the port and both rewrites")
	assert.Equal(t, "8443", port)
}
