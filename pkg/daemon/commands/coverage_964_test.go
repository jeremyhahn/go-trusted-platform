// Copyright (c) 2024 Jeremy Hahn
// Copyright (c) 2024 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed under the GNU Affero General Public
// License v3.0 and a Commercial License. See LICENSE file in the root
// directory.

package commands

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

// bufferLogger returns a platform logger whose records land in the returned
// buffer, so a test can assert which branch a void wiring helper took.
func bufferLogger() (*logging.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return logging.NewLogger(logging.LevelTrace, &buf), &buf
}

// regularFile returns the path of a regular file, used where a helper expects
// a directory so that creating anything beneath it fails.
func regularFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
	return path
}

// dialerCA is the collector's platform CA: the anchor CA of the reporting
// tests plus the client certificate the dialer presents.
type dialerCA struct {
	collectorAnchorCA
	leaf    *x509.Certificate
	certErr error
}

func (c *dialerCA) TLSCertificate(context.Context, *xkmssdk.KeyAttributes) (tls.Certificate, error) {
	if c.certErr != nil {
		return tls.Certificate{}, c.certErr
	}
	return tls.Certificate{Certificate: [][]byte{c.leaf.Raw}}, nil
}

func (c *dialerCA) TrustedIntermediate() (*x509.Certificate, error) { return nil, nil }

// collectorApp is a control plane whose collector identity can be built: a
// TPM IDevID and a CA for the platform anchor, and a key for "default".
func collectorApp(t *testing.T, certErr error) *app.App {
	t.Helper()
	root, key := controlPlaneTestRoot(t)
	a := &app.App{
		TPM: &collectorAnchorTPM{idevid: issueCollectorIdentity(t, root, key, "cp.example.internal")},
		CA: &dialerCA{
			collectorAnchorCA: collectorAnchorCA{root: root},
			leaf:              issueCollectorIdentity(t, root, key, "collector.example.internal"),
			certErr:           certErr,
		},
		WebServiceKeyAttributes: map[string]*xkmssdk.KeyAttributes{"default": {}},
	}
	a.AttestationConfig.Reporting = &config.ReportingConfig{Enabled: true}
	return a
}

func TestCollectorTLSDialer_BuildsTheClientConfig(t *testing.T) {
	dial, err := collectorTLSDialer(collectorApp(t, nil), nil, quietLogger())
	require.NoError(t, err)

	cfg, err := dial(context.Background(), reporting.Endpoint{Address: "192.0.2.5:9443", ServerName: "host-05.example.internal"})
	require.NoError(t, err)
	assert.Equal(t, "host-05.example.internal", cfg.ServerName)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	assert.NotNil(t, cfg.RootCAs, "the node certificate must be verified against the platform anchor")
	require.Len(t, cfg.Certificates, 1)
}

func TestCollectorTLSDialer_FailsClosed(t *testing.T) {
	t.Run("no key for the identity", func(t *testing.T) {
		a := collectorApp(t, nil)
		a.WebServiceKeyAttributes = nil
		_, err := collectorTLSDialer(a, &config.CollectorConfig{Identity: "collector"}, quietLogger())
		var ident ErrCollectorIdentity
		require.ErrorAs(t, err, &ident)
		assert.Contains(t, ident.Error(), `"collector"`)
	})
	t.Run("no anchor source", func(t *testing.T) {
		a := collectorApp(t, nil)
		a.TPM = nil
		_, err := collectorTLSDialer(a, nil, quietLogger())
		var ident ErrCollectorIdentity
		require.ErrorAs(t, err, &ident)
	})
	t.Run("client certificate unavailable", func(t *testing.T) {
		dial, err := collectorTLSDialer(collectorApp(t, &MessageError{Msg: "key sealed"}), nil, quietLogger())
		require.NoError(t, err)
		_, err = dial(context.Background(), reporting.Endpoint{Address: "192.0.2.5:9443"})
		var ident ErrCollectorIdentity
		require.ErrorAs(t, err, &ident)
		assert.Contains(t, ident.Error(), "key sealed")
	})
}

func TestInitReportingCollector_StartsAndStops(t *testing.T) {
	a := collectorApp(t, nil)
	// No device is enrolled, so no cycle ever resolves a profile: the profile
	// service only has to exist for the verifier to be built.
	cfg := &daemon.Config{
		DeviceService:        &fakeDevices{byID: map[uint64]*entities.Device{}},
		DeviceProfileService: struct{ device.DeviceProfileService }{},
	}

	var logs bytes.Buffer
	rep := initReportingCollector(context.Background(), slog.New(slog.NewTextHandler(&logs, nil)), a, cfg, nil, nil)
	require.NotNil(t, rep, "an enabled collector with an identity must start: %s", logs.String())
	t.Cleanup(rep.Stop)
	require.NotNil(t, rep.Handles)
	assert.NotNil(t, rep.Handles.Reports)
	assert.NotNil(t, rep.Handles.Refresher)
	require.NotNil(t, rep.Rest)
	assert.NotNil(t, rep.Rest.Reports)
	assert.NotNil(t, rep.AttestedPeers)

	// The REST surface keeps the collector's cache and refresher whichever
	// caller policy it ends up with.
	out := withCollectorSurface(quietLogger(), nil, rep, nil, nil)
	assert.Equal(t, rep.Rest.Reports, out.Reports)
	assert.Equal(t, rep.Rest.Refresher, out.Refresher)
	assert.Nil(t, out.Policy, "no app and no prior surface: no caller policy")

	prior := initCallerPolicyWithPeers(quietLogger(), &app.App{}, nil, nil)
	require.NotNil(t, prior)
	kept := withCollectorSurface(quietLogger(), prior, rep, nil, nil)
	assert.Equal(t, prior.Clock, kept.Clock, "without an app the prior surface's clock is kept")
	assert.Equal(t, prior.Policy, kept.Policy)

	rebuilt := withCollectorSurface(quietLogger(), nil, rep, &app.App{}, nil)
	assert.Equal(t, rep.Rest.Reports, rebuilt.Reports)
}

func TestInitReportingCollector_NoIdentityNoCollector(t *testing.T) {
	a := collectorApp(t, nil)
	a.WebServiceKeyAttributes = map[string]*xkmssdk.KeyAttributes{}
	cfg := &daemon.Config{DeviceService: &fakeDevices{}, DeviceProfileService: struct{ device.DeviceProfileService }{}}
	var logs bytes.Buffer
	assert.Nil(t, initReportingCollector(context.Background(), slog.New(slog.NewTextHandler(&logs, nil)), a, cfg, nil, nil))
	assert.Contains(t, logs.String(), "collector identity unavailable")
}

func TestBuildChallengeMap_FollowsTheConfiguredChallenges(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "none", in: nil, want: []string{}},
		{name: "all four", in: []string{"http-01", "dns-01", "enroll-01", "endorse-01"}, want: []string{"dns-01", "endorse-01", "enroll-01", "http-01"}},
		{name: "unknown types are ignored", in: []string{"tls-alpn-01", "dns-01"}, want: []string{"dns-01"}},
		{name: "duplicates collapse", in: []string{"http-01", "http-01"}, want: []string{"http-01"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildChallengeMap(tc.in, nil)
			keys := make([]string, 0, len(got))
			for k, verify := range got {
				assert.NotNil(t, verify, k)
				keys = append(keys, k)
			}
			sort.Strings(keys)
			assert.Equal(t, tc.want, keys)
		})
	}
}

func TestDaemonServerSANs_CollectsAndDeduplicatesNames(t *testing.T) {
	assert.Equal(t, daemonSANs{}, daemonServerSANs(nil))

	primary := &v1.Config{}
	primary.Certificate.Subject.CommonName = "node1.example.internal"
	primary.Certificate.SANS = &trustedca.CASubjectAlternativeNames{DNS: []string{"api.example.internal", "node1"}}
	legacy := &v1.Config{}
	legacy.Certificate.Subject.CommonName = " legacy.example.internal "
	legacy.Certificate.SANS = &trustedca.CASubjectAlternativeNames{DNS: []string{"", "api.example.internal"}}

	a := &app.App{
		Hostname:         "node1",
		Domain:           "example.internal",
		WebServices:      []*v1.Config{nil, primary},
		WebServiceConfig: legacy,
	}
	sans := daemonServerSANs(a)
	assert.Equal(t, []string{
		"node1",
		"node1.example.internal",
		"example.internal",
		"api.example.internal",
		"legacy.example.internal",
	}, sans.DNS)
	for _, ip := range sans.IPs {
		assert.NotEqual(t, "127.0.0.1", ip, "loopback is never a server SAN")
		assert.NotEqual(t, "::1", ip, "loopback is never a server SAN")
	}
}

func TestDaemonServerSANs_HostnameOnly(t *testing.T) {
	sans := daemonServerSANs(&app.App{Hostname: "solo"})
	assert.Equal(t, []string{"solo"}, sans.DNS, "no domain: no FQDN is invented")
}

func TestInitVTPMServiceOnConfig(t *testing.T) {
	t.Run("nil app or config is a no-op", func(t *testing.T) {
		cfg := &daemon.Config{}
		initVTPMServiceOnConfig(newTestLogger(), nil, cfg)
		assert.Nil(t, cfg.VTPMService)
		initVTPMServiceOnConfig(newTestLogger(), &app.App{}, nil)
	})
	t.Run("an injected service is kept", func(t *testing.T) {
		injected, err := vtpm.NewService(&vtpm.Config{BaseDir: t.TempDir()}, newTestLogger(), nil)
		require.NoError(t, err)
		cfg := &daemon.Config{VTPMService: injected}
		initVTPMServiceOnConfig(newTestLogger(), &app.App{VTPMConfig: &vtpm.Config{BaseDir: t.TempDir()}}, cfg)
		assert.Same(t, injected, cfg.VTPMService)
	})
	t.Run("wires the service under the configured base dir", func(t *testing.T) {
		base := t.TempDir()
		logger, logs := bufferLogger()
		cfg := &daemon.Config{}
		initVTPMServiceOnConfig(logger, &app.App{VTPMConfig: &vtpm.Config{BaseDir: base}, CA: newFakeKeystoreCA(t)}, cfg)
		require.NotNil(t, cfg.VTPMService)
		assert.DirExists(t, filepath.Join(base, "bundles"))
		assert.DirExists(t, filepath.Join(base, "templates"))
		assert.Contains(t, logs.String(), "vTPM service initialized")
	})
	t.Run("an invalid config leaves the service unset", func(t *testing.T) {
		logger, logs := bufferLogger()
		cfg := &daemon.Config{}
		initVTPMServiceOnConfig(logger, &app.App{VTPMConfig: &vtpm.Config{BaseDir: t.TempDir(), PCRBanks: []string{"md5"}}}, cfg)
		assert.Nil(t, cfg.VTPMService)
		assert.Contains(t, logs.String(), "vTPM service creation failed")
	})
}

func TestInitRegistryServiceOnConfig_GuardsAndFailures(t *testing.T) {
	t.Run("nil inputs are a no-op", func(t *testing.T) {
		cfg := &daemon.Config{}
		initRegistryServiceOnConfig(newTestLogger(), nil, cfg)
		initRegistryServiceOnConfig(newTestLogger(), &app.App{}, nil)
		assert.Nil(t, cfg.RegistryService)
		assert.Nil(t, registryDistBackend(cfg))
	})
	t.Run("a preconfigured service is kept", func(t *testing.T) {
		first := &daemon.Config{}
		initRegistryServiceOnConfig(newTestLogger(), &app.App{PlatformDir: t.TempDir()}, first)
		t.Cleanup(func() { delete(registryBackends, first) })
		require.NotNil(t, first.RegistryService)
		assert.NotNil(t, registryDistBackend(first), "the wired registry is the distribution backend")

		cfg := &daemon.Config{RegistryService: first.RegistryService}
		initRegistryServiceOnConfig(newTestLogger(), &app.App{PlatformDir: t.TempDir()}, cfg)
		assert.Equal(t, first.RegistryService, cfg.RegistryService)
		assert.Nil(t, registryDistBackend(cfg), "no second registry is built")
	})
	t.Run("unusable storage leaves the surface dark", func(t *testing.T) {
		logger, logs := bufferLogger()
		cfg := &daemon.Config{}
		initRegistryServiceOnConfig(logger, &app.App{PlatformDir: regularFile(t)}, cfg)
		assert.Nil(t, cfg.RegistryService)
		assert.Nil(t, registryDistBackend(cfg))
		assert.Contains(t, logs.String(), "registry:")
	})
}

func TestInitSnapshotStore(t *testing.T) {
	assert.Nil(t, initSnapshotStore(newTestLogger(), nil))

	dir := t.TempDir()
	store := initSnapshotStore(newTestLogger(), &app.App{PlatformDir: dir})
	require.NotNil(t, store)
	assert.DirExists(t, filepath.Join(dir, "config-snapshots"))

	logger, logs := bufferLogger()
	assert.Nil(t, initSnapshotStore(logger, &app.App{PlatformDir: regularFile(t)}))
	assert.Contains(t, logs.String(), "config snapshot store unavailable")
}

func TestInitGatewayControlPlane(t *testing.T) {
	assert.Nil(t, initGatewayControlPlane(newTestLogger(), nil))

	dir := t.TempDir()
	cp := initGatewayControlPlane(newTestLogger(), &app.App{PlatformDir: dir})
	require.NotNil(t, cp)
	assert.NotNil(t, cp.Store)
	assert.NotNil(t, cp.DesiredCfg)
	assert.DirExists(t, filepath.Join(dir, "gateway", "state"))

	logger, logs := bufferLogger()
	assert.Nil(t, initGatewayControlPlane(logger, &app.App{PlatformDir: regularFile(t)}))
	assert.Contains(t, logs.String(), "gateway control plane: store unavailable")
}

func TestInitACMEClientForCertManagement_Guards(t *testing.T) {
	// Every case returns before any network, so the client stays unset. Only
	// a BMC that asks for ACME on a node with no ACME client warns about it.
	const noClient = "BMC is configured for ACME issuance but no ACME client"
	acmeBMC := func() *bmc.Config {
		return &bmc.Config{Certificate: &common.Identity{ACME: &common.ACMEIdentityConfig{Challenge: "http-01"}}}
	}
	cases := []struct {
		name     string
		app      *app.App
		wantWarn bool
	}{
		{name: "nil app", app: nil},
		{name: "no bmc", app: &app.App{}},
		{name: "bmc without a certificate", app: &app.App{BMCConfig: &bmc.Config{}}},
		{name: "certificate without acme", app: &app.App{BMCConfig: &bmc.Config{Certificate: &common.Identity{}}}},
		{name: "acme without a challenge", app: &app.App{BMCConfig: &bmc.Config{Certificate: &common.Identity{ACME: &common.ACMEIdentityConfig{}}}}},
		{name: "no acme client configured", app: &app.App{BMCConfig: acmeBMC()}, wantWarn: true},
		{name: "acme config without a client", app: &app.App{BMCConfig: acmeBMC(), ACMEConfig: &trustedca.ACMEConfig{}}, wantWarn: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger, logs := bufferLogger()
			initACMEClientForCertManagement(context.Background(), logger, tc.app)
			if tc.app != nil {
				assert.Nil(t, tc.app.ACMEClient)
			}
			assert.Equal(t, tc.wantWarn, bytes.Contains(logs.Bytes(), []byte(noClient)), logs.String())
		})
	}
}

func TestRunInitOnlyMode_RequiresApp(t *testing.T) {
	err := runInitOnlyMode(context.Background(), nil, newTestLogger(), defaultBarrierGateConfig())
	assert.ErrorAs(t, err, &ErrBarrierGateRequiresApp{})
}

func TestNewComputeOrchestrator_UncompiledProviderFailsClosed(t *testing.T) {
	vtpmSvc, err := vtpm.NewService(&vtpm.Config{BaseDir: t.TempDir()}, newTestLogger(), nil)
	require.NoError(t, err)

	cases := []struct {
		name string
		vtpm vtpm.VTPMService
	}{
		{name: "without a vTPM service"},
		{name: "with a vTPM service", vtpm: vtpmSvc},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &app.App{ComputeConfig: &compute.OrchestratorConfig{Provider: compute.ProviderKind("no-such-provider")}}
			orch, err := newComputeOrchestrator(newTestLogger(), a, "", tc.vtpm)
			assert.Nil(t, orch)
			var notCompiled *compute.ErrComputeProviderNotCompiled
			require.ErrorAs(t, err, &notCompiled)
			assert.Equal(t, compute.ProviderKind("no-such-provider"), notCompiled.Provider)
		})
	}
}

func TestWireQuarantineObserver_RegistersWithAPolicyEngine(t *testing.T) {
	zones := zone.Defaults()
	eng, err := policy.NewEngine(policy.Config{
		BridgeName:     "br-fabric",
		FlowController: nullOVSPort{},
		PortController: nullOVSPort{},
		Zones:          zones,
		Logger:         quietLogger(),
	})
	require.NoError(t, err)

	svcs := &attestationServices{Service: buildRealAttestationService(t)}
	devices := &stubSaveGetSvc{devices: make(map[uint64]*entities.Device)}
	mgr := wireQuarantineObserver(svcs, &sdnPolicyComponents{Engine: eng, ResolvedZones: zones}, devices, newTestLogger())
	assert.NotNil(t, mgr, "an attestation service, a policy engine and a device store make a quarantine manager")
}

func TestInitSDNPolicy_Guards(t *testing.T) {
	assert.Nil(t, initSDNPolicy(nil, quietLogger()))
	assert.Nil(t, initSDNPolicy(&app.App{}, quietLogger()), "SDN not configured")
}

func TestInitSDNEnrollmentHook_NeedsEveryCollaborator(t *testing.T) {
	eng, err := policy.NewEngine(policy.Config{
		BridgeName:     "br-fabric",
		FlowController: nullOVSPort{},
		PortController: nullOVSPort{},
		Zones:          zone.Defaults(),
		Logger:         quietLogger(),
	})
	require.NoError(t, err)

	assert.Nil(t, initSDNEnrollmentHook(nil, &fakeDevices{}, &device.ProfileService{}, nil, newTestLogger()), "no policy engine")
	assert.Nil(t, initSDNEnrollmentHook(eng, nil, &device.ProfileService{}, nil, newTestLogger()), "no device service")
	assert.Nil(t, initSDNEnrollmentHook(eng, &fakeDevices{}, nil, nil, newTestLogger()), "no profile service")
}

func TestInitCallerPolicyWithPeers_ReadsThePlatformAnchor(t *testing.T) {
	var logs bytes.Buffer
	surface := initCallerPolicyWithPeers(slog.New(slog.NewTextHandler(&logs, nil)), collectorApp(t, nil), nil, nil)
	require.NotNil(t, surface)
	assert.NotNil(t, surface.Policy, "a node with a TPM and a CA builds a caller policy")
	assert.Contains(t, logs.String(), "anchor_source=platform-anchor", "callers are verified against the platform anchor")
	assert.NotContains(t, logs.String(), "platform anchor unavailable")
}

// serveGlobals sets the serve command's package state for one test and puts
// the previous values back afterwards.
func serveGlobals(t *testing.T, a *app.App, grpc, quic bool) {
	t.Helper()
	prevApp, prevSocket := App, serveSocketPath
	prevREST, prevGRPC, prevQUIC, prevMCP := serveEnableREST, serveEnableGRPC, serveEnableQUIC, serveEnableMCP
	prevSkipIAM, prevMTLS := serveSkipIAM, serveEnableMTLS
	t.Cleanup(func() {
		App, serveSocketPath = prevApp, prevSocket
		serveEnableREST, serveEnableGRPC, serveEnableQUIC, serveEnableMCP = prevREST, prevGRPC, prevQUIC, prevMCP
		serveSkipIAM, serveEnableMTLS = prevSkipIAM, prevMTLS
	})
	App = a
	serveSocketPath = filepath.Join(t.TempDir(), "platformd.sock")
	serveEnableREST, serveEnableGRPC, serveEnableQUIC, serveEnableMCP = false, grpc, quic, false
	serveSkipIAM, serveEnableMTLS = true, false
}

func quietCommand() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	return cmd
}

func TestRunDaemonOnly_TLSTransportWithoutAppRefusesToStart(t *testing.T) {
	cases := []struct {
		name       string
		grpc, quic bool
	}{
		{name: "gRPC TCP", grpc: true},
		{name: "QUIC", quic: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			serveGlobals(t, nil, tc.grpc, tc.quic)
			err := runDaemonOnly(quietCommand(), context.Background(), make(chan os.Signal, 1), newTestLogger(), nil)
			var startup ErrServeStartup
			require.ErrorAs(t, err, &startup)
			assert.Equal(t, "daemon TLS identity provisioning", startup.Phase)
			assert.ErrorAs(t, err, &ErrTLSIdentityRequiresApp{})
			_, statErr := os.Stat(serveSocketPath)
			assert.True(t, errors.Is(statErr, os.ErrNotExist), "nothing is bound when startup is refused")
		})
	}
}

func TestRunWithWebservices_EarlyStartupFailures(t *testing.T) {
	cases := []struct {
		name      string
		app       *app.App
		wantPhase string
		wantCause error
	}{
		{
			name:      "no CA configured",
			app:       &app.App{},
			wantPhase: "CA initialization",
			wantCause: app.ErrCANotConfigured{},
		},
		{
			name: "no storage for the ACME DAO",
			app: &app.App{
				CA:                      newFakeKeystoreCA(t),
				WebServiceKeyAttributes: map[string]*xkmssdk.KeyAttributes{},
			},
			wantPhase: "ACME DAO factory",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			serveGlobals(t, tc.app, false, false)
			err := runWithWebservices(quietCommand(), context.Background(), make(chan os.Signal, 1), newTestLogger(), nil)
			var startup ErrServeStartup
			require.ErrorAs(t, err, &startup)
			assert.Equal(t, tc.wantPhase, startup.Phase)
			if tc.wantCause != nil {
				assert.ErrorIs(t, err, tc.wantCause)
			}
		})
	}
}

func TestTypedErrors_SayWhatFailedAndKeepTheirCause(t *testing.T) {
	cause := &MessageError{Msg: "boom"}
	cases := []struct {
		name  string
		err   error
		want  string
		wraps bool
	}{
		{name: "provision missing SDK", err: ErrProvisionMissingSDK{}, want: "quicbaas SDK client is required"},
		{name: "provision missing CA", err: ErrProvisionMissingCA{}, want: "CA trust pool provider is required"},
		{name: "provision issue", err: ErrProvisionIssue{Role: "server", Cause: cause}, want: "server certificate issuance failed: boom", wraps: true},
		{name: "provision persist", err: ErrProvisionPersist{Path: "/x/cert.pem", Cause: cause}, want: "failed to persist /x/cert.pem: boom", wraps: true},
		{name: "TLS requires app", err: ErrTLSIdentityRequiresApp{}, want: "requires an initialized app"},
		{name: "TLS requires config", err: ErrTLSIdentityRequiresConfig{}, want: "requires a daemon config"},
		{name: "TLS requires platform dir", err: ErrTLSIdentityRequiresPlatformDir{}, want: "requires a platform directory"},
		{name: "TLS not provisioned", err: ErrTLSIdentityNotProvisioned{}, want: "was not provisioned"},
		{name: "TLS keystore", err: ErrTLSIdentityKeystore{Op: "load", Cause: cause}, want: "keystore load failed: boom", wraps: true},
		{name: "migration TLS no CA", err: ErrMigrationTLSNoCA{}, want: "certificate authority is not configured"},
		{name: "migration TLS issue", err: ErrMigrationTLSIssue{Role: "client", Cause: cause}, want: "client certificate issuance failed: boom", wraps: true},
		{name: "migration TLS write", err: ErrMigrationTLSWrite{Path: "/x/key.pem", Cause: cause}, want: "failed to write /x/key.pem: boom", wraps: true},
		{name: "migration peer", err: ErrMigrationPeer{Op: "prepare", Cause: cause}, want: "prepare failed: boom", wraps: true},
		{name: "migration peer rejected", err: ErrMigrationPeerRejected{Op: "finalize", Message: "no room"}, want: "finalize rejected by destination: no room"},
		{name: "desired config decode", err: &ErrDesiredConfigDecode{Key: "gateway.desired", Cause: cause}, want: "gateway.desired does not decode as a desired config: boom"},
		{name: "desired VPN configured", err: &ErrDesiredVPNConfigured{Key: "gateway.vpn"}, want: "gateway.vpn is managed through VPNService"},
		{name: "vTPM CA", err: ErrNilVTPMCA{}, want: "certificate authority is not configured"},
		{name: "caller anchors empty", err: ErrCallerAnchorsEmpty{Path: "/x/ca.pem"}, want: "/x/ca.pem contains no CA certificate"},
		{name: "caller anchors unreadable", err: ErrCallerAnchorsUnreadable{Path: "/x/ca.pem", Cause: cause}, want: "/x/ca.pem is unusable: boom", wraps: true},
		{name: "message", err: &MessageError{Msg: "plain"}, want: "plain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Contains(t, tc.err.Error(), tc.want)
			if tc.wraps {
				assert.ErrorIs(t, tc.err, cause)
			}
		})
	}
}
