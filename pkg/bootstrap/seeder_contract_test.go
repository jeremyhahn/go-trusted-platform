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
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/device"
)

// seederContractServer is the real control-plane seeding surface: the real
// template and profile services over in-memory storage, mounted through the
// real seeder router under /api/v1 on a TLS test server. Nothing on the
// server side is faked, so the seeder client and the handlers are tested
// against each other rather than against each side's assumptions.
type seederContractServer struct {
	server   *httptest.Server
	profiles *device.ProfileService
}

func newSeederContractServer(t *testing.T) *seederContractServer {
	t.Helper()

	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(context.Background()))
	logger := logging.NewLogger(slog.LevelDebug, nil)
	ds := device.NewDatastore(storage, logger)

	templates, err := device.NewTemplateService(ds)
	require.NoError(t, err)
	profiles, err := device.NewProfileService(ds)
	require.NoError(t, err)

	root := mux.NewRouter()
	restdevice.NewDeviceRouter(logger, response.NewResponseWriter(logger, nil), templates, profiles).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	server := httptest.NewTLSServer(root)
	t.Cleanup(server.Close)

	return &seederContractServer{server: server, profiles: profiles}
}

// seeder returns a Seeder whose HTTP client trusts the test server's
// certificate by its TLS name, exactly as the orchestrator builds it from
// the captured CA bundle.
func (c *seederContractServer) seeder(cfg *BootstrapConfig, discovered []DiscoveredNode) *Seeder {
	pool := x509.NewCertPool()
	pool.AddCert(c.server.Certificate())
	return NewSeeder(SeederParams{
		ControlPlaneAddr: c.server.Listener.Addr().String(),
		Config:           cfg,
		Discovered:       discovered,
		Logger:           orchTestLogger(),
		CPCAPool:         pool,
		ServerName:       "example.com",
	})
}

func writeSeederTemplate(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte("domain: template.local\n"), 0o644))
	return path
}

// TestSeederContract_CreateProfile drives the real seeder against the real
// create-profile handler and asserts the seeder recovers the deterministic
// profile id from the 201 envelope and that the control plane stored the
// profile the seeder described.
func TestSeederContract_CreateProfile(t *testing.T) {
	cp := newSeederContractServer(t)

	cfg := minimalConfig()
	cfg.Templates = map[string]string{
		RoleControlPlane: writeSeederTemplate(t, "control-plane.yaml"),
	}
	discovered := []DiscoveredNode{
		{
			NodeConfig:     NodeConfig{Hostname: "lab-node-2", Role: RoleControlPlane, MACs: []string{"00:25:90:5e:02:aa"}},
			DiscoveredMACs: []string{"00:25:90:5e:02:aa"},
		},
	}

	s := cp.seeder(cfg, discovered)
	require.NoError(t, s.Seed(context.Background()))

	wantID := util.NewID([]byte("lab-node-2"))
	assert.Equal(t, map[string]uint64{"lab-node-2": wantID}, s.ProfileIDs())

	stored, err := cp.profiles.Get(context.Background(), wantID)
	require.NoError(t, err)
	assert.Equal(t, "lab-node-2", stored.Name)
	assert.Equal(t, entities.DeviceRole(RoleControlPlane), stored.Role)
	require.NotNil(t, stored.MatchRules)
	assert.Equal(t, "00:25:90:5e:02:aa", stored.MatchRules.MACPrefix)
	assert.Empty(t, stored.EKCert)

	// The stored config is the seeder's merged config, not the bare
	// template: node identity and the platform domain are applied.
	storedConfig, ok := stored.Config.(map[string]interface{})
	require.True(t, ok, "stored config should be a map, got %T", stored.Config)
	osSection, ok := storedConfig["os"].(map[string]interface{})
	require.True(t, ok, "merged config should carry the os section")
	assert.Equal(t, "lab-node-2", osSection["hostname"])
	assert.Equal(t, cfg.Platform.Domain, storedConfig["domain"], "platform global identity must overwrite the template placeholder")
	require.NotNil(t, stored.PlatformdConfig)
	assert.Equal(t, storedConfig, stored.PlatformdConfig.Inline)
}

// TestSeederContract_CreateProfile_Idempotent verifies that seeding the same
// host twice yields the same profile id both times and leaves one profile.
func TestSeederContract_CreateProfile_Idempotent(t *testing.T) {
	cp := newSeederContractServer(t)

	cfg := minimalConfig()
	cfg.Templates = map[string]string{
		RoleControlPlane: writeSeederTemplate(t, "control-plane.yaml"),
	}
	discovered := []DiscoveredNode{
		{
			NodeConfig:     NodeConfig{Hostname: "lab-node-2", Role: RoleControlPlane, MACs: []string{"00:25:90:5e:02:aa"}},
			DiscoveredMACs: []string{"00:25:90:5e:02:aa"},
		},
	}

	first := cp.seeder(cfg, discovered)
	require.NoError(t, first.Seed(context.Background()))
	second := cp.seeder(cfg, discovered)
	require.NoError(t, second.Seed(context.Background()))

	assert.Equal(t, first.ProfileIDs(), second.ProfileIDs())
	count, err := cp.profiles.Count(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

// TestSeederContract_CreateProfile_EKCertRefused verifies that a node
// carrying a prestaged EK certificate fails seeding loudly: the
// unauthenticated route refuses the certificate with 400 and no profile is
// created, rather than binding hardware identity without a credential.
func TestSeederContract_CreateProfile_EKCertRefused(t *testing.T) {
	cp := newSeederContractServer(t)

	cfg := minimalConfig()
	cfg.Templates = map[string]string{
		RoleControlPlane: writeSeederTemplate(t, "control-plane.yaml"),
	}
	// Any PEM certificate stands in for the EK certificate; the test
	// server's own certificate avoids generating a second key pair.
	ekCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cp.server.Certificate().Raw}))
	s := cp.seeder(cfg, []DiscoveredNode{
		{
			NodeConfig:     NodeConfig{Hostname: "lab-node-2", Role: RoleControlPlane, MACs: []string{"00:25:90:5e:02:aa"}},
			DiscoveredMACs: []string{"00:25:90:5e:02:aa"},
			EKCert:         ekCert,
		},
	})

	err := s.Seed(context.Background())

	var createErr ErrProfileCreateFailed
	require.ErrorAs(t, err, &createErr)
	assert.Equal(t, "lab-node-2", createErr.Hostname)
	assert.Equal(t, http.StatusBadRequest, createErr.StatusCode)
	assert.Empty(t, s.ProfileIDs())
	count, countErr := cp.profiles.Count(context.Background())
	require.NoError(t, countErr)
	assert.Equal(t, 0, count)
}

// TestSeederContract_CreateProfile_NullConfig verifies that an explicit
// JSON null config is refused with 400 by the real mounted router and
// services and that nothing is stored — the handler-level unit test alone
// cannot prove the route wiring.
func TestSeederContract_CreateProfile_NullConfig(t *testing.T) {
	cp := newSeederContractServer(t)

	cfg := minimalConfig()
	cfg.Templates = map[string]string{
		RoleControlPlane: writeSeederTemplate(t, "control-plane.yaml"),
	}
	s := cp.seeder(cfg, nil)
	ids, err := s.uploadTemplates(context.Background())
	require.NoError(t, err)
	templateID := ids[RoleControlPlane]
	require.NotEmpty(t, templateID)

	url := "https://" + cp.server.Listener.Addr().String() +
		"/api/v1/devices/templates/" + templateID + "/create-profile"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url,
		strings.NewReader(`{"hostname":"lab-node-2","config":null}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := cp.server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "config is null")
	count, countErr := cp.profiles.Count(context.Background())
	require.NoError(t, countErr)
	assert.Equal(t, 0, count)
}

// TestSeederContract_CreateProfile_UnknownTemplate verifies the seeder
// surfaces the handler's error when the template id does not exist on the
// control plane, rather than recording a profile id.
func TestSeederContract_CreateProfile_UnknownTemplate(t *testing.T) {
	cp := newSeederContractServer(t)

	s := cp.seeder(minimalConfig(), []DiscoveredNode{
		{
			NodeConfig:     NodeConfig{Hostname: "lab-node-2", Role: RoleControlPlane},
			DiscoveredMACs: []string{"00:25:90:5e:02:aa"},
		},
	})

	err := s.createProfiles(context.Background(), map[string]string{RoleControlPlane: "12345"})

	var createErr ErrProfileCreateFailed
	require.ErrorAs(t, err, &createErr)
	assert.Equal(t, "lab-node-2", createErr.Hostname)
	assert.Empty(t, s.ProfileIDs())
}
