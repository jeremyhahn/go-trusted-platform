package iso

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCoverage964_TypedErrorMessages pins the message each typed error
// renders, so a caller matching on the text sees the field values.
func TestCoverage964_TypedErrorMessages(t *testing.T) {
	cause := errors.New("cause")
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"bootstrap client", ErrBootstrapClientCreate{Reason: "r"}, "iso: failed to create bootstrap client: r"},
		{"bundle fetch", ErrCABundleFetch{Reason: "r"}, "iso: failed to fetch CA bundle: r"},
		{"bundle empty", ErrCABundleEmpty{}, "iso: CA bundle response is empty"},
		{"bundle write", ErrCABundleWrite{Path: "/p", Reason: "r"}, "iso: failed to write CA bundle to /p: r"},
		{"config read", ErrPlatformConfigRead{Path: "/p", Reason: "r"}, "iso: failed to read platform config /p: r"},
		{"config marshal", ErrPlatformConfigMarshal{Reason: "r"}, "iso: failed to marshal platform config: r"},
		{"config write", ErrPlatformConfigWrite{Path: "/p", Reason: "r"}, "iso: failed to write platform config to /p: r"},
		{"overrides without template", ErrOverridesWithoutTemplate{}, "iso: --overrides requires --platform-config to specify the base template"},
		{"overrides merge", ErrOverridesMergeFailed{Reason: "r"}, "iso: failed to merge overrides onto template: r"},
		{"overrides temp", ErrOverridesTempFile{Reason: "r"}, "iso: failed to create temp file for merged config: r"},
		{"overrides temp write", ErrOverridesTempFileWrite{Path: "/p", Reason: "r"}, "iso: failed to write merged config to /p: r"},
		{"command output", &CommandOutputError{Msg: "m", Err: cause, Detail: " d"}, "m: cause d"},
		{"pxe and qemu", &PXEServerQEMUError{PXEErr: errors.New("pxe"), QEMUErr: errors.New("qemu")}, "PXE server error: pxe (QEMU error: qemu)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.err.Error())
		})
	}
}

// TestCoverage964_ErrorUnwrap checks the wrapping errors expose their causes
// to errors.Is.
func TestCoverage964_ErrorUnwrap(t *testing.T) {
	cause := errors.New("cause")
	assert.ErrorIs(t, &CommandOutputError{Msg: "m", Err: cause}, cause)

	pxeErr := errors.New("pxe")
	qemuErr := errors.New("qemu")
	both := &PXEServerQEMUError{PXEErr: pxeErr, QEMUErr: qemuErr}
	assert.ErrorIs(t, both, pxeErr)
	assert.ErrorIs(t, both, qemuErr)
}

func TestCoverage964_ApplyOverrides(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.yaml")
	over := filepath.Join(dir, "over.yaml")
	require.NoError(t, os.WriteFile(base, []byte("domain: base.example\nhostname: node\n"), 0o600))
	require.NoError(t, os.WriteFile(over, []byte("domain: over.example\n"), 0o600))

	t.Run("no overrides leaves the template", func(t *testing.T) {
		flags := &createFlags{platformConfig: base}
		require.NoError(t, applyOverrides(flags))
		assert.Equal(t, base, flags.platformConfig)
	})

	t.Run("overrides without template", func(t *testing.T) {
		err := applyOverrides(&createFlags{overrides: over})
		assert.ErrorAs(t, err, &ErrOverridesWithoutTemplate{})
	})

	t.Run("missing overrides file", func(t *testing.T) {
		err := applyOverrides(&createFlags{platformConfig: base, overrides: filepath.Join(dir, "absent.yaml")})
		assert.ErrorAs(t, err, &ErrOverridesMergeFailed{})
	})

	t.Run("merged file replaces the template", func(t *testing.T) {
		flags := &createFlags{platformConfig: base, overrides: over}
		require.NoError(t, applyOverrides(flags))
		t.Cleanup(func() { os.Remove(flags.platformConfig) })

		assert.NotEqual(t, base, flags.platformConfig)
		merged, err := os.ReadFile(flags.platformConfig)
		require.NoError(t, err)
		assert.Contains(t, string(merged), "over.example")
		assert.Contains(t, string(merged), "hostname: node")
	})
}

// withSiblingPlatformd places a platformd file beside the test binary, where
// siblingPlatformdBinary looks, and removes it when the test ends.
func withSiblingPlatformd(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	require.NoError(t, err)
	self, err = filepath.EvalSymlinks(self)
	require.NoError(t, err)
	path := filepath.Join(filepath.Dir(self), "platformd")
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/true\n"), 0o700))
	t.Cleanup(func() { os.Remove(path) })
	return path
}

func TestCoverage964_SiblingPlatformdBinary(t *testing.T) {
	_, err := siblingPlatformdBinary()
	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr, "no platformd beside the binary")
	assert.Contains(t, msgErr.Msg, "platformd binary not found")

	want := withSiblingPlatformd(t)
	got, err := siblingPlatformdBinary()
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestCoverage964_BuildISOBuildConfig(t *testing.T) {
	t.Run("no platformd is an error", func(t *testing.T) {
		_, err := buildISOBuildConfig(&createFlags{platformType: "server"})
		var msgErr *MessageError
		assert.ErrorAs(t, err, &msgErr)
	})

	platformd := withSiblingPlatformd(t)

	t.Run("flags override the defaults", func(t *testing.T) {
		flags := &createFlags{
			alpineVersion:     "3.99",
			mirror:            "https://mirror.example",
			apkMirror:         "https://apk.example",
			platformAPKDir:    "/apks",
			arch:              "aarch64",
			platformVersion:   "1.2.3",
			platformType:      "client",
			platformConfig:    "/cfg/platform.yaml",
			workDir:           "/work",
			keysDir:           "/keys",
			webUI:             "/ui.tar.gz",
			secureBoot:        true,
			fips:              true,
			configServer:      "https://config.example",
			bootstrapStrategy: "spki",
			bootstrapDNS:      "10.0.0.53:53",
			bootstrapNoiseKey: "noise",
			bootstrapSPKIPin:  "pin",
			caBundle:          "/ca.pem",
			caKeyAlgorithm:    "ecdsa-p384",
		}
		cfg, err := buildISOBuildConfig(flags)
		require.NoError(t, err)

		assert.Equal(t, platformd, cfg.PlatformdBinary)
		assert.Equal(t, "3.99", cfg.AlpineVersion)
		assert.Equal(t, "https://mirror.example", cfg.AlpineMirror)
		assert.Equal(t, "https://apk.example", cfg.APKMirror)
		assert.Equal(t, "/apks", cfg.PlatformAPKDir)
		assert.Equal(t, "aarch64", cfg.Architecture)
		assert.Equal(t, "1.2.3", cfg.PlatformVersion)
		assert.Equal(t, "client", string(cfg.PlatformType))
		assert.Equal(t, "/cfg/platform.yaml", cfg.PlatformConfigFile)
		assert.Equal(t, "/work", cfg.WorkDir)
		assert.Equal(t, "/keys", cfg.KeysDir)
		assert.Equal(t, "/ui.tar.gz", cfg.WebUIPath)
		assert.True(t, cfg.SecureBoot)
		assert.True(t, cfg.FIPS)
		assert.Equal(t, "https://config.example", cfg.ConfigServerURL)
		assert.Equal(t, "spki", cfg.BootstrapStrategy)
		assert.Equal(t, "10.0.0.53:53", cfg.BootstrapDNS)
		assert.Equal(t, "noise", cfg.BootstrapNoiseKey)
		assert.Equal(t, "pin", cfg.BootstrapSPKIPin)
		assert.Equal(t, "/ca.pem", cfg.CABundlePath)
		assert.Equal(t, "ecdsa-p384", cfg.CAKeyAlgorithm)
		assert.Equal(t, "trusted-alpine-1.2.3-aarch64-fips.iso", cfg.OutputISO,
			"the generated name carries version, architecture and the FIPS suffix")
	})

	t.Run("explicit output and auto strategy", func(t *testing.T) {
		cfg, err := buildISOBuildConfig(&createFlags{
			platformType:      "server",
			platformVersion:   "1.0.0",
			output:            "/out/custom.iso",
			bootstrapStrategy: "auto",
		})
		require.NoError(t, err)
		assert.Equal(t, "/out/custom.iso", cfg.OutputISO)
		assert.NotEqual(t, "auto", cfg.BootstrapStrategy, "auto keeps the default strategy")
	})

	t.Run("missing config file", func(t *testing.T) {
		_, err := buildISOBuildConfig(&createFlags{
			platformType: "server",
			configFile:   filepath.Join(t.TempDir(), "absent.yaml"),
		})
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to load config file", wrapped.Msg)
	})
}

func TestCoverage964_RunCreateRejectsBadInput(t *testing.T) {
	t.Run("invalid platform type", func(t *testing.T) {
		err := runCreate(nil, &createFlags{arch: "x86_64", platformType: "router"}, nil)
		var typed ErrInvalidPlatformType
		require.ErrorAs(t, err, &typed)
		assert.Equal(t, "router", typed.PlatformType)
	})

	t.Run("overrides without template", func(t *testing.T) {
		err := runCreate(nil, &createFlags{arch: "x86_64", platformType: "server", overrides: "o.yaml"}, nil)
		assert.ErrorAs(t, err, &ErrOverridesWithoutTemplate{})
	})

	t.Run("no platformd fails configuration", func(t *testing.T) {
		err := runCreate(nil, &createFlags{arch: "x86_64", platformType: "server"}, nil)
		assert.ErrorAs(t, err, &ErrConfigValidationFailed{})
	})
}

func TestCoverage964_ResolveWebUIPath(t *testing.T) {
	logger := createTestLogger(false)
	ctx := context.Background()

	t.Run("explicit path that exists", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ui.tar.gz")
		require.NoError(t, os.WriteFile(path, []byte("ui"), 0o600))
		got, err := resolveWebUIPath(ctx, logger, path)
		require.NoError(t, err)
		assert.Equal(t, path, got)
	})

	t.Run("explicit path that is missing", func(t *testing.T) {
		_, err := resolveWebUIPath(ctx, logger, filepath.Join(t.TempDir(), "absent"))
		var msgErr *MessageError
		require.ErrorAs(t, err, &msgErr)
		assert.Contains(t, msgErr.Msg, "specified WebUI path not found")
	})

	t.Run("tarball in the working directory", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "public_html.tar.gz"), []byte("ui"), 0o600))
		t.Chdir(dir)
		got, err := resolveWebUIPath(ctx, logger, "")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(dir, "public_html.tar.gz"), got)
	})

	t.Run("non-empty directory in the working directory", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "public_html"), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "public_html", "index.html"), []byte("ui"), 0o600))
		t.Chdir(dir)
		got, err := resolveWebUIPath(ctx, logger, "")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(dir, "public_html"), got)
	})
}

func TestCoverage964_BuildCustomISORejectsBadInput(t *testing.T) {
	logger := createTestLogger(false)
	ctx := context.Background()
	dir := t.TempDir()

	t.Run("work directory under a file", func(t *testing.T) {
		file := filepath.Join(dir, "file")
		require.NoError(t, os.WriteFile(file, nil, 0o600))
		err := BuildCustomISO(ctx, logger, &ISOBuilderConfig{WorkDir: filepath.Join(file, "work")})
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to create work directory", wrapped.Msg)
	})

	t.Run("missing platformd binary", func(t *testing.T) {
		err := BuildCustomISO(ctx, logger, &ISOBuilderConfig{
			WorkDir:         filepath.Join(dir, "work"),
			PlatformdBinary: filepath.Join(dir, "absent", "platformd"),
		})
		var msgErr *MessageError
		require.ErrorAs(t, err, &msgErr)
		assert.Contains(t, msgErr.Msg, "platformd binary not found")
	})

	t.Run("platformctl is not platformd", func(t *testing.T) {
		ctl := filepath.Join(dir, "platformctl")
		require.NoError(t, os.WriteFile(ctl, nil, 0o700))
		err := BuildCustomISO(ctx, logger, &ISOBuilderConfig{
			WorkDir:         filepath.Join(dir, "work"),
			PlatformdBinary: ctl,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "platformctl")
	})

	t.Run("missing WebUI path", func(t *testing.T) {
		platformd := filepath.Join(dir, "platformd")
		require.NoError(t, os.WriteFile(platformd, nil, 0o700))
		err := BuildCustomISO(ctx, logger, &ISOBuilderConfig{
			WorkDir:         filepath.Join(dir, "work"),
			PlatformdBinary: platformd,
			PlatformType:    "server",
			WebUIPath:       filepath.Join(dir, "absent-ui"),
		})
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to resolve WebUI", wrapped.Msg)
	})
}

func TestCoverage964_ResolveBootstrapDNSServer(t *testing.T) {
	dir := t.TempDir()
	withDANE := filepath.Join(dir, "client.yaml")
	require.NoError(t, os.WriteFile(withDANE, []byte("trust:\n  bootstrap:\n    dane:\n      dns-server: \"10.0.0.53:53\"\n"), 0o600))
	withoutDNS := filepath.Join(dir, "bare.yaml")
	require.NoError(t, os.WriteFile(withoutDNS, []byte("domain: example.com\n"), 0o600))
	fallback := "192.0.2.1:" + strconv.Itoa(dns.DefaultPublicPort)

	tests := []struct {
		name string
		path string
		want string
	}{
		{"configured DANE server", withDANE, "10.0.0.53:53"},
		{"config without DNS falls back", withoutDNS, fallback},
		{"unreadable config falls back", filepath.Join(dir, "absent.yaml"), fallback},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, resolveBootstrapDNSServer(tt.path, "192.0.2.1"))
		})
	}
}

func TestCoverage964_ResolveServerHostname(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "server.yaml")
	require.NoError(t, os.WriteFile(good, []byte("domain: server.example.com\n"), 0o600))
	bad := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(bad, []byte("domain: [unclosed\n"), 0o600))

	tests := []struct {
		name string
		path string
		want string
	}{
		{"domain from config", good, "server.example.com"},
		{"unparseable config", bad, ""},
		{"unreadable config", filepath.Join(dir, "absent.yaml"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, resolveServerHostname(tt.path))
		})
	}
}

func TestCoverage964_LoadCSDeviceProfile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "profile.yaml")
	require.NoError(t, os.WriteFile(good, []byte("name: edge-01\nmodel: x10\nzone: lab\n"), 0o600))
	bad := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(bad, []byte("name: [unclosed\n"), 0o600))

	profile, err := loadCSDeviceProfile(good)
	require.NoError(t, err)
	assert.Equal(t, "edge-01", profile.Name)
	assert.Equal(t, "x10", profile.Model)
	assert.Equal(t, "lab", profile.Zone)

	tests := []struct {
		name string
		path string
		msg  string
	}{
		{"unreadable", filepath.Join(dir, "absent.yaml"), "failed to read profile"},
		{"unparseable", bad, "failed to parse profile"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadCSDeviceProfile(tt.path)
			var wrapped *WrappedError
			require.ErrorAs(t, err, &wrapped)
			assert.Equal(t, tt.msg, wrapped.Msg)
		})
	}
}

func TestCoverage964_CSQEMUConfigs(t *testing.T) {
	flags := &clientServerFlags{
		diskSize:       "8G",
		diskCache:      "none",
		memory:         2048,
		cpus:           2,
		secureBoot:     true,
		serverHostPort: 18443,
		dnsHostPort:    18053,
		fido2Enable:    true,
		fido2Mode:      "virtual",
	}

	t.Run("tap networking", func(t *testing.T) {
		cfg := createCSQEMUConfig("/d.qcow2", "/w", "tap-c", "52:54:00:00:00:02", flags)
		assert.Equal(t, "/d.qcow2", cfg.DiskPath)
		assert.Equal(t, "8G", cfg.DiskSize)
		assert.Equal(t, "none", cfg.DiskCache)
		assert.Equal(t, 2048, cfg.Memory)
		assert.Equal(t, 2, cfg.CPUs)
		assert.Equal(t, "/w", cfg.WorkDir)
		assert.True(t, cfg.SecureBoot)
		assert.Equal(t, "tap-c", cfg.TapDevice)
		assert.Equal(t, "52:54:00:00:00:02", cfg.MACAddress)
		require.NotNil(t, cfg.FIDO2)
		assert.Equal(t, "virtual", cfg.FIDO2.Mode)
	})

	t.Run("user networking forwards the service ports", func(t *testing.T) {
		cfg := createCSUserNetworkQEMUConfig("/d.qcow2", "/w", flags)
		assert.Equal(t, "user", cfg.NetworkMode)
		assert.Empty(t, cfg.TapDevice)
		require.NotNil(t, cfg.FIDO2)

		forwards := map[string]int{}
		for _, pf := range cfg.PortForwards {
			forwards[fmt.Sprintf("%s/%d", pf.Protocol, pf.HostPort)] = pf.GuestPort
		}
		assert.Equal(t, 8443, forwards["tcp/18443"])
		assert.Equal(t, dns.DefaultPublicPort, forwards["tcp/18053"])
		assert.Equal(t, dns.DefaultPublicPort, forwards["udp/18053"])
		assert.Equal(t, 22, forwards["tcp/2222"])
	})

	t.Run("no FIDO2 when disabled", func(t *testing.T) {
		plain := &clientServerFlags{diskSize: "4G"}
		assert.Nil(t, createCSQEMUConfig("/d", "/w", "tap", "mac", plain).FIDO2)
		assert.Nil(t, createCSUserNetworkQEMUConfig("/d", "/w", plain).FIDO2)
	})
}

func TestCoverage964_CSClientCABundlePath(t *testing.T) {
	tests := []struct {
		strategy string
		want     string
	}{
		{"", "/ca.pem"},
		{string(trust.StrategyEmbedded), "/ca.pem"},
		{string(trust.StrategyDANE), ""},
		{string(trust.StrategySPKI), ""},
	}
	for _, tt := range tests {
		t.Run("strategy="+tt.strategy, func(t *testing.T) {
			got := csClientCABundlePath("/ca.pem", &clientServerFlags{bootstrapStrategy: tt.strategy})
			assert.Equal(t, tt.want, got)
		})
	}
}

// withCABundlePath points the package's fetched-bundle path at path for the
// test and restores it afterwards.
func withCABundlePath(t *testing.T, path string) {
	t.Helper()
	saved := csServerCABundlePath
	csServerCABundlePath = path
	t.Cleanup(func() { csServerCABundlePath = saved })
}

func TestCoverage964_VerifyCSPlatformdStatus(t *testing.T) {
	logger := createTestLogger(false)
	ctx := context.Background()

	newServer := func(t *testing.T, status int, body string) (*httptest.Server, int) {
		t.Helper()
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/status" {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(status)
			fmt.Fprint(w, body)
		}))
		t.Cleanup(srv.Close)

		bundle := filepath.Join(t.TempDir(), "ca.pem")
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
		require.NoError(t, os.WriteFile(bundle, certPEM, 0o600))
		withCABundlePath(t, bundle)

		u, err := url.Parse(srv.URL)
		require.NoError(t, err)
		port, err := strconv.Atoi(u.Port())
		require.NoError(t, err)
		return srv, port
	}

	t.Run("status OK trusts the fetched bundle", func(t *testing.T) {
		_, port := newServer(t, http.StatusOK, `{"tpm":"ready"}`)
		assert.NoError(t, verifyCSPlatformdStatus(ctx, logger, &clientServerFlags{serverHostPort: port}))
	})

	t.Run("status OK without TPM info still passes", func(t *testing.T) {
		_, port := newServer(t, http.StatusOK, `{}`)
		assert.NoError(t, verifyCSPlatformdStatus(ctx, logger, &clientServerFlags{serverHostPort: port}))
	})

	t.Run("non-200 status", func(t *testing.T) {
		_, port := newServer(t, http.StatusServiceUnavailable, "")
		err := verifyCSPlatformdStatus(ctx, logger, &clientServerFlags{serverHostPort: port})
		var msgErr *MessageError
		require.ErrorAs(t, err, &msgErr)
		assert.Equal(t, "unexpected status code: 503", msgErr.Msg)
	})

	t.Run("nothing listening", func(t *testing.T) {
		srv, port := newServer(t, http.StatusOK, "")
		srv.Close()
		err := verifyCSPlatformdStatus(ctx, logger, &clientServerFlags{serverHostPort: port})
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to connect", wrapped.Msg)
	})
}

func TestCoverage964_ServerReadyWaitsStopOnCancel(t *testing.T) {
	logger := createTestLogger(false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	assert.ErrorIs(t, waitForCSServerReady(ctx, logger, "192.0.2.1", time.Minute), context.Canceled)
	assert.ErrorIs(t, waitForCSServerReadyUserNetwork(ctx, logger, &clientServerFlags{}, time.Minute), context.Canceled)
}

func TestCoverage964_FetchCSCABundle(t *testing.T) {
	logger := createTestLogger(false)
	out := filepath.Join(t.TempDir(), "ca.pem")

	t.Run("unknown strategy", func(t *testing.T) {
		err := fetchCSCABundle(context.Background(), logger, "127.0.0.1", out,
			&clientServerFlags{bootstrapStrategy: "no-such-strategy"})
		assert.ErrorAs(t, err, &ErrBootstrapClientCreate{})
		assert.NoFileExists(t, out)
	})

	t.Run("fetch fails when the context is done", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := fetchCSCABundle(ctx, logger, "127.0.0.1", out, &clientServerFlags{
			bootstrapStrategy: string(trust.StrategySPKI),
			bootstrapSPKIPin:  "00",
			bootstrapNoiseKey: "00",
		})
		assert.ErrorAs(t, err, &ErrCABundleFetch{})
		assert.NoFileExists(t, out)
	})
}

func TestCoverage964_CSServerUserNetworkStopsOnBadSetup(t *testing.T) {
	logger := createTestLogger(false)
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))

	tests := []struct {
		name  string
		flags *clientServerFlags
		msg   string
	}{
		{
			name:  "work directory under a file",
			flags: &clientServerFlags{serverWorkDir: filepath.Join(file, "w")},
			msg:   "failed to create server work directory",
		},
		{
			name: "missing platform config",
			flags: &clientServerFlags{
				serverWorkDir:    filepath.Join(dir, "w"),
				serverConfigPath: filepath.Join(dir, "absent.yaml"),
			},
			msg: "failed to read server platform config",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runCSServerVMUserNetwork(context.Background(), logger, tt.flags)
			var wrapped *WrappedError
			require.ErrorAs(t, err, &wrapped)
			assert.Equal(t, tt.msg, wrapped.Msg)
		})
	}
}

func TestCoverage964_RunClientServerTestRejectsBadFlags(t *testing.T) {
	tests := []struct {
		name  string
		flags *clientServerFlags
		msg   string
	}{
		{
			name:  "user network needs server-only",
			flags: &clientServerFlags{userNetwork: true},
			msg:   "--user-network only supports --server-only mode (single VM testing)",
		},
		{
			name:  "OVS and user network",
			flags: &clientServerFlags{userNetwork: true, serverOnly: true, useOVS: true},
			msg:   "--use-ovs and --user-network are mutually exclusive",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runClientServerTest(nil, tt.flags)
			var msgErr *MessageError
			require.ErrorAs(t, err, &msgErr)
			assert.Equal(t, tt.msg, msgErr.Msg)
		})
	}

	t.Run("invalid disk cache", func(t *testing.T) {
		assert.Error(t, runClientServerTest(nil, &clientServerFlags{diskCache: "bogus"}))
	})

	t.Run("user network runs the server leg", func(t *testing.T) {
		dir := t.TempDir()
		err := runClientServerTest(nil, &clientServerFlags{
			userNetwork:      true,
			serverOnly:       true,
			serverWorkDir:    filepath.Join(dir, "w"),
			serverConfigPath: filepath.Join(dir, "absent.yaml"),
		})
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to read server platform config", wrapped.Msg)
	})
}

// withPXEFlags sets the PXE command's package-level flags for one test and
// restores them afterwards.
func withPXEFlags(t *testing.T, kernel, initrd, args, iso, workDir string) {
	t.Helper()
	k, i, a, s, w := pxeKernel, pxeInitrd, pxeArgs, pxeISO, pxeWorkDir
	pxeKernel, pxeInitrd, pxeArgs, pxeISO, pxeWorkDir = kernel, initrd, args, iso, workDir
	t.Cleanup(func() { pxeKernel, pxeInitrd, pxeArgs, pxeISO, pxeWorkDir = k, i, a, s, w })
}

func TestCoverage964_ResolveBootEntry(t *testing.T) {
	logger := createTestLogger(false)

	t.Run("kernel and initrd with explicit args", func(t *testing.T) {
		withPXEFlags(t, "http://k", "http://i", "console=ttyS0", "", "")
		entry, err := resolveBootEntry(logger)
		require.NoError(t, err)
		assert.Equal(t, "custom", entry.Name)
		assert.Equal(t, "http://k", entry.Kernel)
		assert.Equal(t, "http://i", entry.Initrd)
		assert.Equal(t, "console=ttyS0", entry.Args)
	})

	t.Run("kernel and initrd take default args", func(t *testing.T) {
		withPXEFlags(t, "http://k", "http://i", "", "", "")
		entry, err := resolveBootEntry(logger)
		require.NoError(t, err)
		assert.Contains(t, entry.Args, "console=ttyS0,115200")
	})

	tests := []struct {
		name               string
		kernel, initrd, is string
		msg                string
	}{
		{"kernel without initrd", "http://k", "", "", "both --kernel and --initrd must be specified together"},
		{"initrd without kernel", "", "http://i", "", "both --kernel and --initrd must be specified together"},
		{"nothing to boot", "", "", "", "must specify either --iso or (--kernel and --initrd)"},
		{"missing ISO", "", "", "/nonexistent/alpine.iso", "ISO file not found: /nonexistent/alpine.iso"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withPXEFlags(t, tt.kernel, tt.initrd, "", tt.is, t.TempDir())
			_, err := resolveBootEntry(logger)
			var msgErr *MessageError
			require.ErrorAs(t, err, &msgErr)
			assert.Equal(t, tt.msg, msgErr.Msg)
		})
	}

	t.Run("work directory under a file", func(t *testing.T) {
		dir := t.TempDir()
		iso := filepath.Join(dir, "alpine.iso")
		require.NoError(t, os.WriteFile(iso, []byte("not an iso"), 0o600))
		withPXEFlags(t, "", "", "", iso, filepath.Join(iso, "work"))
		_, err := resolveBootEntry(logger)
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to create extraction directory", wrapped.Msg)
	})
}

func TestCoverage964_ExtractISOContentsRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	iso := filepath.Join(dir, "garbage.iso")
	require.NoError(t, os.WriteFile(iso, []byte("not an iso"), 0o600))

	err := extractISOContents(iso, filepath.Join(dir, "out"))
	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.Equal(t, "failed to extract ISO (tried 7z, bsdtar)", wrapped.Msg)

	err = extractISOContents(iso, filepath.Join(iso, "out"))
	require.ErrorAs(t, err, &wrapped)
	assert.Equal(t, "failed to create destination directory", wrapped.Msg)
}

func TestCoverage964_TestCommandsRejectBadInput(t *testing.T) {
	dir := t.TempDir()
	absentISO := filepath.Join(dir, "absent.iso")

	t.Run("install with invalid disk cache", func(t *testing.T) {
		assert.Error(t, runTestInstall(nil, &testFlags{diskCache: "bogus", iso: absentISO}))
	})

	t.Run("install with missing ISO", func(t *testing.T) {
		err := runTestInstall(nil, &testFlags{iso: absentISO})
		var typed ErrISONotFound
		require.ErrorAs(t, err, &typed)
		assert.Equal(t, absentISO, typed.Path)
	})

	t.Run("all stops at the install step", func(t *testing.T) {
		err := runTestAll(nil, &testFlags{iso: absentISO})
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "installation test failed", wrapped.Msg)
		assert.ErrorAs(t, err, &ErrISONotFound{})
	})

	t.Run("first boot with missing disk", func(t *testing.T) {
		disk := filepath.Join(dir, "absent.qcow2")
		err := runTestFirstBoot(nil, &testFlags{disk: disk}, "First Boot Test")
		var msgErr *MessageError
		require.ErrorAs(t, err, &msgErr)
		assert.Equal(t, fmt.Sprintf("disk not found: %s. Run 'install' first", disk), msgErr.Msg)
	})

	t.Run("boot with invalid disk cache", func(t *testing.T) {
		assert.Error(t, runTestFirstBoot(nil, &testFlags{diskCache: "bogus"}, "First Boot Test"))
	})
}
