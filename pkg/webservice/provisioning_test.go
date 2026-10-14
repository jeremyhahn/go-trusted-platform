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

package webservice

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	devicepkg "github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// provisioningRegistry supplies only what a provisioning surface mounts: the
// device profile service and a response writer. Any other registry method
// reached is a test failure by panic.
type provisioningRegistry struct {
	v1.RestHandlerRegistry
	profiles devicepkg.DeviceProfileService
}

func (r *provisioningRegistry) DeviceProfileService() devicepkg.DeviceProfileService {
	return r.profiles
}

func (r *provisioningRegistry) ResponseWriter() response.HttpWriter {
	return response.NewResponseWriter(newTestLogger(), nil)
}

// profileByMAC answers every FindByMACAddress with its one profile; any
// other lookup panics through the nil embedding.
type profileByMAC struct {
	devicepkg.DeviceProfileService
	profile *entities.DeviceProfile
}

func (p *profileByMAC) FindByMACAddress(context.Context, string) (*entities.DeviceProfile, error) {
	return p.profile, nil
}

const bootMAC = "52:54:00:aa:bb:cc"

func provisioningRegistryFor(t *testing.T) *provisioningRegistry {
	t.Helper()
	return &provisioningRegistry{profiles: &profileByMAC{
		profile: &entities.DeviceProfile{ID: 7, Name: "node-01", Config: map[string]interface{}{"hostname": "node-01"}},
	}}
}

// testPlan numbers the default zones for environment 4 with a ULA, so the
// provisioning zone has both an IPv4 and an IPv6 subnet.
func testPlan(t *testing.T) *netplan.Plan {
	t.Helper()
	plan, err := netplan.New(netplan.Environment{ID: 4, ULA: netip.MustParsePrefix("fd12:3456:789a::/48")}, zone.Defaults())
	require.NoError(t, err)
	return plan
}

// provisioningConfig binds the provisioning listener to the zone's gateway
// address, the address the node holds on the provisioning VLAN.
func provisioningConfig(t *testing.T, plan *netplan.Plan) *v1.Config {
	t.Helper()
	numbering, err := plan.MustZone(zone.ZoneProvisioning)
	require.NoError(t, err)
	return &v1.Config{
		Name: "provisioning", Port: 8080, TLSPort: 8081, Surface: v1.SurfaceProvisioning,
		BindHost: numbering.Gateway.String(),
	}
}

// TestProvisioningSurface_AnswersTheConfigRoute is the provisioning
// listener's side of #177: the boot-time config fetch answers there.
func TestProvisioningSurface_AnswersTheConfigRoute(t *testing.T) {
	server := newSurfaceServer(t, provisioningConfig(t, testPlan(t)), provisioningRegistryFor(t))
	server.buildRoutes()

	rec := get(server.router, "10.0.0.1", "/api/v1/devices/config?mac="+bootMAC)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/x-yaml", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "hostname: node-01")
}

// TestProvisioningSurface_RouteSetIsTheConfigRouteAlone is the audit: the
// listener mounts the config route and the catch-all, so a route added to
// the platform later cannot appear on the provisioning VLAN.
func TestProvisioningSurface_RouteSetIsTheConfigRouteAlone(t *testing.T) {
	server := newSurfaceServer(t, provisioningConfig(t, testPlan(t)), provisioningRegistryFor(t))
	server.buildRoutes()

	for _, tmpl := range walk(t, server.router) {
		allowed := tmpl == "/api/v1/devices/config" || tmpl == "/api/v1" || tmpl == "/"
		assert.True(t, allowed, "provisioning surface mounted %q", tmpl)
	}
	unknown := get(server.router, "10.0.0.1", "/api/v1/no-such-route")
	assert.Equal(t, http.StatusNotFound, unknown.Code)
	for _, path := range []string{"/api/v1/devices", "/api/v1/devices/templates", "/api/v1/login", "/v2/", "/"} {
		rec := get(server.router, "10.0.0.1", path)
		assert.Equal(t, http.StatusNotFound, rec.Code, path)
		assert.NotContains(t, rec.Body.String(), "<html", path)
	}
}

// TestFullSurface_ConfigRouteIsAnUnknownRoute is the general listener's side
// of #177: the full surface's catch-all answers GET /api/v1/devices/config
// exactly as it answers a route that never existed. That the full route
// table does not match the path is TestRegisterRoutes_ConfigRouteIsNotMounted
// in package v1.
func TestFullSurface_ConfigRouteIsAnUnknownRoute(t *testing.T) {
	server := newSurfaceServer(t, &v1.Config{Name: "internal", Port: 9080, TLSPort: 9443}, nil)
	fallback := server.serveStaticFiles(t.TempDir(), "index.html", nil)

	unknown := get(fallback, "cp.example.com", "/api/v1/no-such-route?mac="+bootMAC)
	config := get(fallback, "cp.example.com", "/api/v1/devices/config?mac="+bootMAC)
	assert.Equal(t, http.StatusNotFound, config.Code)
	assert.Equal(t, unknown.Code, config.Code)
	assert.Equal(t, unknown.Header().Get("Content-Type"), config.Header().Get("Content-Type"))
	// The body names the requested path; apart from that it is the same.
	assert.Equal(t, strings.Replace(unknown.Body.String(), "/api/v1/no-such-route", "/api/v1/devices/config", 1), config.Body.String())
}

func TestProvisioningSurface_LimitsAreTheEdgeDefaults(t *testing.T) {
	limits := resolveLimits(&v1.Config{}, v1.SurfaceProvisioning)
	assert.Equal(t, EdgeMaxHeaderBytes, limits.MaxHeaderBytes)
	assert.Equal(t, EdgeMaxConnections, limits.MaxConnections)
	require.NotNil(t, limits.RateLimit)
	assert.Equal(t, float64(EdgeRateLimitPerSecond), limits.RateLimit.RequestsPerSecond)
}

func TestErrProvisioningSurfaceEmpty_NamesTheListener(t *testing.T) {
	// buildRoutes FatalErrors with this when RegisterProvisioningRoutes
	// mounts nothing; that refusal is TestRegisterProvisioningRoutes_
	// NoProfileServiceMountsNothing in package v1.
	assert.Contains(t, (&ErrProvisioningSurfaceEmpty{Name: "prov-vlan"}).Error(), "prov-vlan")
}

func TestValidateProvisioningSurface_Accepts(t *testing.T) {
	plan := testPlan(t)
	numbering, err := plan.MustZone(zone.ZoneProvisioning)
	require.NoError(t, err)

	// The zone's gateway, another IPv4 address in it, and an IPv6 address
	// in its ULA subnet.
	for _, host := range []string{numbering.Gateway.String(), numbering.Subnet4.Addr().Next().Next().String(), numbering.Subnet6.Addr().Next().String()} {
		cfg := provisioningConfig(t, plan)
		cfg.BindHost = host
		assert.NoError(t, ValidateProvisioningSurface(cfg, plan), host)
	}

	// Other surfaces are not this validator's concern, with or without a plan.
	assert.NoError(t, ValidateProvisioningSurface(&v1.Config{Surface: v1.SurfaceFull}, nil))
	assert.NoError(t, ValidateProvisioningSurface(&v1.Config{}, nil))
	assert.NoError(t, ValidateProvisioningSurface(nil, nil))
}

func TestValidateProvisioningSurface_Refuses(t *testing.T) {
	plan := testPlan(t)
	management, err := plan.MustZone(zone.ZoneManagement)
	require.NoError(t, err)
	vhosts := []v1.VirtualHost{{Hosts: []string{"app.example.com"}}}

	cases := map[string]struct {
		mutate func(*v1.Config)
		noPlan bool
		check  func(error) bool
	}{
		"no network plan": {
			noPlan: true,
			check:  func(err error) bool { var e *ErrProvisioningNetworkPlanRequired; return errors.As(err, &e) },
		},
		"empty bind-host": {
			mutate: func(c *v1.Config) { c.BindHost = "" },
			check:  func(err error) bool { var e *ErrProvisioningBindHostRequired; return errors.As(err, &e) },
		},
		"hostname bind-host": {
			mutate: func(c *v1.Config) { c.BindHost = "cp.example.internal" },
			check:  func(err error) bool { var e *ErrProvisioningBindHostInvalid; return errors.As(err, &e) },
		},
		"unspecified IPv4": {
			mutate: func(c *v1.Config) { c.BindHost = "0.0.0.0" },
			check:  func(err error) bool { var e *ErrProvisioningBindHostInvalid; return errors.As(err, &e) },
		},
		"unspecified IPv6": {
			mutate: func(c *v1.Config) { c.BindHost = "::" },
			check:  func(err error) bool { var e *ErrProvisioningBindHostInvalid; return errors.As(err, &e) },
		},
		"another zone's address": {
			mutate: func(c *v1.Config) { c.BindHost = management.Gateway.String() },
			check:  func(err error) bool { var e *ErrProvisioningBindHostOutsideZone; return errors.As(err, &e) },
		},
		"an address in no zone": {
			mutate: func(c *v1.Config) { c.BindHost = "192.0.2.10" },
			check:  func(err error) bool { var e *ErrProvisioningBindHostOutsideZone; return errors.As(err, &e) },
		},
		"no TLS port": {
			mutate: func(c *v1.Config) { c.TLSPort = 0 },
			check:  func(err error) bool { var e *ErrProvisioningTLSPortRequired; return errors.As(err, &e) },
		},
		"virtual hosts": {
			mutate: func(c *v1.Config) { c.VirtualHosts = &vhosts },
			check:  func(err error) bool { var e *ErrProvisioningVirtualHosts; return errors.As(err, &e) },
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := provisioningConfig(t, plan)
			if tc.mutate != nil {
				tc.mutate(cfg)
			}
			usePlan := plan
			if tc.noPlan {
				usePlan = nil
			}
			err := ValidateProvisioningSurface(cfg, usePlan)
			require.Error(t, err)
			assert.True(t, tc.check(err), "got %v", err)
			assert.Contains(t, err.Error(), cfg.Name)
		})
	}
}

func TestValidateProvisioningSurface_RefusesAPlanWithNoProvisioningZone(t *testing.T) {
	var zones []zone.ZoneConfig
	for _, z := range zone.Defaults() {
		if z.Name != zone.ZoneProvisioning {
			zones = append(zones, z)
		}
	}
	plan, err := netplan.New(netplan.Environment{ID: 4}, zones)
	require.NoError(t, err)

	cfg := &v1.Config{Name: "provisioning", TLSPort: 8081, Surface: v1.SurfaceProvisioning, BindHost: "10.4.0.1"}
	err = ValidateProvisioningSurface(cfg, plan)
	var missing *ErrProvisioningZoneMissing
	require.True(t, errors.As(err, &missing), "got %v", err)
	assert.Error(t, errors.Unwrap(err))
}

func TestErrProvisioningBindHostOutsideZone_NamesTheZone(t *testing.T) {
	numbering, err := testPlan(t).MustZone(zone.ZoneProvisioning)
	require.NoError(t, err)
	msg := (&ErrProvisioningBindHostOutsideZone{Name: "provisioning", BindHost: "192.0.2.10", Zone: numbering}).Error()
	assert.Contains(t, msg, "192.0.2.10")
	assert.Contains(t, msg, numbering.Subnet4.String())
	assert.Contains(t, msg, numbering.Subnet6.String())
}
