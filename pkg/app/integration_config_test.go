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
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ntp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
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

// TestIntegrationConfig_TCPSwtpmNotASocket proves the socket check above can
// fail: a runner that serves swtpm over TCP gives the daemon no socket path.
func TestIntegrationConfig_TCPSwtpmNotASocket(t *testing.T) {
	script := []byte("swtpm socket --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322")
	socket, ok := harnessSwtpmSocket(script)
	assert.False(t, ok)
	assert.Empty(t, socket)
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
