// Copyright (c) 2024 Jeremy Hahn
// Copyright (c) 2024 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed under the GNU Affero General Public
// License v3.0 and a Commercial License. See LICENSE file in the root
// directory.

// Unit coverage for issue #964 step d, slice b: the failure and wiring
// branches of initReportingCollector and initRegistryServiceOnConfig.

package commands

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
	attestationsvc "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/service"
	attestationstore "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// reportingConfigWithProfiles is the daemon config an enabled collector
// needs: a device service with no enrolled device, and a profile service.
func reportingConfigWithProfiles() *daemon.Config {
	return &daemon.Config{
		DeviceService:        &fakeDevices{byID: map[uint64]*entities.Device{}},
		DeviceProfileService: struct{ device.DeviceProfileService }{},
	}
}

func TestInitReportingCollector_RefusesToStart(t *testing.T) {
	tests := []struct {
		name    string
		cfg     func() *daemon.Config
		port    int
		wantLog []string
	}{
		{
			name:    "no profile service, no verifier",
			cfg:     func() *daemon.Config { return &daemon.Config{DeviceService: &fakeDevices{}} },
			wantLog: []string{"verifier unavailable", daemon.ErrServiceNotAvailable{Service: "device_profile"}.Error()},
		},
		{
			name:    "a port outside 1..65535, no address resolver",
			cfg:     reportingConfigWithProfiles,
			port:    70000,
			wantLog: []string{"address resolver unavailable", reporting.ErrInvalidPort{Port: 70000}.Error()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := collectorApp(t, nil)
			a.AttestationConfig.Reporting.Collector = &config.CollectorConfig{Port: tt.port}
			var logs bytes.Buffer
			rep := initReportingCollector(context.Background(), slog.New(slog.NewTextHandler(&logs, nil)), a, tt.cfg(), nil, nil)
			assert.Nil(t, rep)
			for _, want := range tt.wantLog {
				assert.Contains(t, logs.String(), want)
			}
			assert.NotContains(t, logs.String(), "collector started")
		})
	}
}

// fileStoreService builds a real attestation service on a file store rooted
// at root, and returns its report store.
func fileStoreService(t *testing.T, root string) (*attestationsvc.Service, reporting.Store) {
	t.Helper()
	store, err := attestationstore.NewFileStore(root)
	require.NoError(t, err)
	svc := attestationsvc.NewService(store)
	st, ok := svc.Store().(reporting.Store)
	require.True(t, ok, "the attestation file store persists reports")
	return svc, st
}

func TestInitReportingCollector_ServesPersistedReports(t *testing.T) {
	svc, st := fileStoreService(t, t.TempDir())
	at := time.Now().Add(-time.Minute)
	require.NoError(t, st.PutReport(&reporting.Report{
		DeviceID: "42", Serial: "SN-42", Verified: true, Status: "verified",
		AttestedAt: at, CollectedAt: at,
	}))

	// The control plane's own endpoint rides along: it must not stop the start.
	self := &controlPlaneSelfDevice{DeviceID: "1", Endpoint: reporting.SelfEndpoint{DeviceID: "1"}}
	var logs bytes.Buffer
	rep := initReportingCollector(context.Background(), slog.New(slog.NewTextHandler(&logs, nil)),
		collectorApp(t, nil), reportingConfigWithProfiles(), &attestationServices{Service: svc}, self)
	require.NotNil(t, rep, "collector must start: %s", logs.String())
	t.Cleanup(rep.Stop)

	got, ok := rep.Handles.Reports.Report("42")
	require.True(t, ok, "the report persisted before startup is served")
	assert.Equal(t, "SN-42", got.Serial)
	assert.True(t, got.Verified)
	assert.Contains(t, logs.String(), "persisted_reports=1")
}

func TestInitReportingCollector_UnreadableStoreStartsEmpty(t *testing.T) {
	root := t.TempDir()
	svc, _ := fileStoreService(t, root)
	// The reports directory is a regular file, so loading it fails.
	require.NoError(t, os.WriteFile(filepath.Join(root, "reports"), []byte("x"), 0o600))

	var logs bytes.Buffer
	rep := initReportingCollector(context.Background(), slog.New(slog.NewTextHandler(&logs, nil)),
		collectorApp(t, nil), reportingConfigWithProfiles(), &attestationServices{Service: svc}, nil)
	require.NotNil(t, rep, "an unreadable store must not stop the collector: %s", logs.String())
	t.Cleanup(rep.Stop)

	assert.Contains(t, logs.String(), "persisted reports unavailable")
	assert.Contains(t, logs.String(), "could not load persisted reports")
	assert.Empty(t, rep.Handles.Reports.Reports())
	assert.Contains(t, logs.String(), "persisted_reports=0")
}

func TestInitRegistryServiceOnConfig_KMSRootUnusableLeavesSurfaceDark(t *testing.T) {
	platformDir := t.TempDir()
	registryRoot := filepath.Join(platformDir, "registry")
	require.NoError(t, os.MkdirAll(registryRoot, 0o700))
	// The key directory is a regular file, so the local KMS cannot use it.
	require.NoError(t, os.WriteFile(filepath.Join(registryRoot, "keys"), []byte("x"), 0o600))

	logger, logs := bufferLogger()
	cfg := &daemon.Config{}
	initRegistryServiceOnConfig(logger, &app.App{PlatformDir: platformDir}, cfg)
	t.Cleanup(func() { delete(registryBackends, cfg) })

	assert.Nil(t, cfg.RegistryService)
	assert.Nil(t, registryDistBackend(cfg))
	assert.Contains(t, logs.String(), "registry: local KMS unavailable")
	assert.NotContains(t, logs.String(), "registry service wired")
}

func TestInitRegistryServiceOnConfig_WithoutSDKWiresUnsigned(t *testing.T) {
	logger, logs := bufferLogger()
	cfg := &daemon.Config{}
	platformDir := t.TempDir()
	initRegistryServiceOnConfig(logger, &app.App{PlatformDir: platformDir}, cfg)
	t.Cleanup(func() { delete(registryBackends, cfg) })

	require.NotNil(t, cfg.RegistryService)
	assert.NotNil(t, registryDistBackend(cfg))
	assert.Contains(t, logs.String(), "no QuicBaaS SDK client, signed pushes are refused")
	info, err := os.Stat(filepath.Join(platformDir, "registry", "keys"))
	require.NoError(t, err, "the local KMS keeps its keys under <PlatformDir>/registry/keys")
	assert.True(t, info.IsDir())
}
