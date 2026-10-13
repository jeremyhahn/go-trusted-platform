// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// gateOrchestrator builds the smallest Orchestrator that can run the
// deploy phase, with the config-server probe supplied by the caller.
func gateOrchestrator(t *testing.T, dep DeployerConfig, probe ConfigServerReadiness) *Orchestrator {
	t.Helper()
	cfg := minimalConfig()
	cfg.Deployer = dep
	o, err := NewOrchestrator(OrchestratorParams{
		Config:                cfg,
		BMCFactory:            &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:                orchTestLogger(),
		Deployer:              &mockDeployer{},
		HealthChecker:         &mockHealthChecker{},
		ConfigServerReadiness: probe,
	})
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	return o
}

// TestDeployContainer_FailsWhenConfigServerNotServing is the defect this
// change exists to close.
//
// `docker run -d` returning a container ID says the container was
// created, nothing more. When supervisord retires pxeboot — a port
// conflict on the deployer does exactly that — the container stays Up
// with nothing serving inside it, and the phase used to report
// "Container: done" regardless. Every node would then install from the
// ISO's baked config instead of its own: a whole fleet with the wrong
// identity, while the run reported progress normally.
func TestDeployContainer_FailsWhenConfigServerNotServing(t *testing.T) {
	o := gateOrchestrator(t, DeployerConfig{Host: "deploy-host"}, notServingConfigServer{})

	err := o.deployContainer(context.Background())

	var notServing ErrContainerServiceNotServing
	if !errors.As(err, &notServing) {
		t.Fatalf("deployContainer = %v, want ErrContainerServiceNotServing", err)
	}
	if notServing.Host != "deploy-host" {
		t.Errorf("Host = %q, want deploy-host", notServing.Host)
	}
	if notServing.BaseURL == "" {
		t.Error("BaseURL must name the endpoint that failed to answer")
	}
}

// TestDeployContainer_SucceedsWhenConfigServerServes is the positive
// path, driven against a REAL server rather than a stubbed probe, so it
// exercises installLogBaseURL, the port plumbing and the HTTP probe
// together. It is also what proves the gate is not simply always-fail.
func TestDeployContainer_SucceedsWhenConfigServerServes(t *testing.T) {
	var scriptHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/boot.ipxe" {
			scriptHits++
			_, _ = w.Write([]byte("#!ipxe\nchain menu.ipxe\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// The device-script server is a second listener, and the gate now
	// requires both — so the positive path needs both to exist.
	devSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("#!ipxe\nboot\n"))
	}))
	defer devSrv.Close()

	host, port := hostAndPort(t, srv.URL)
	_, devPort := hostAndPort(t, devSrv.URL)

	// The real probe, not a stub: with the ports now configurable the
	// orchestrator can be pointed at live test servers.
	o := gateOrchestrator(t,
		DeployerConfig{Host: host, BootstrapHTTPPort: port, BootstrapDeviceScriptPort: devPort},
		httpConfigServerReadiness{})

	if err := o.deployContainer(context.Background()); err != nil {
		t.Fatalf("deployContainer = %v, want nil", err)
	}
	if scriptHits == 0 {
		t.Error("the gate never probed /boot.ipxe — it is not actually verifying anything")
	}
}

// TestDeployContainer_FailsAgainstDeadPort drives the real probe against
// a port nothing is listening on, which is the observed failure on the
// jumpbox. Bounded by the caller's context so the test does not sit out
// the probe's own 30s.
func TestDeployContainer_FailsAgainstDeadPort(t *testing.T) {
	// A listener opened and immediately closed yields a port that is
	// almost certainly free, without guessing one.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	host, port := hostAndPort(t, srv.URL)
	srv.Close()

	o := gateOrchestrator(t,
		DeployerConfig{Host: host, BootstrapHTTPPort: port},
		httpConfigServerReadiness{})

	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()

	var notServing ErrContainerServiceNotServing
	if err := o.deployContainer(ctx); !errors.As(err, &notServing) {
		t.Fatalf("deployContainer = %v, want ErrContainerServiceNotServing", err)
	}
}

// TestInstallLogBaseURL_HonoursConfiguredPort pins the other half of the
// port fix. The orchestrator builds every container-facing URL here; a
// literal :8080 meant that moving the container's HTTP port pointed all
// of them at a port nothing was listening on.
// TestDeployContainer_FailsWhenDeviceScriptListenerDead is the failure
// the issue actually reports. The config server answers — the container
// is up and 8080 is bound — while the device-script listener never
// bound because something else on the deployer owns its port. Probing
// only /health would call that healthy.
func TestDeployContainer_FailsWhenDeviceScriptListenerDead(t *testing.T) {
	o := gateOrchestrator(t, DeployerConfig{Host: "deploy-host"}, deadDeviceScriptServer{})

	err := o.deployContainer(context.Background())

	var notServing ErrContainerServiceNotServing
	if !errors.As(err, &notServing) {
		t.Fatalf("deployContainer = %v, want ErrContainerServiceNotServing", err)
	}
	if notServing.Listener != "device-script server" {
		t.Errorf("Listener = %q, want it to name the device-script server", notServing.Listener)
	}
	if !strings.Contains(notServing.BaseURL, strconv.Itoa(DefaultBootstrapHTTPPort+DeviceScriptPortOffset)) {
		t.Errorf("BaseURL = %q, want it to name the device-script port", notServing.BaseURL)
	}
}

// TestRun_NoDeployer_StillVerifiesContainer closes the bypass: with
// deployer.container_image empty the operator runs the container
// themselves, Phase 2 is skipped, and skipping it used to skip the only
// check that anything is serving — so the run provisioned into the same
// silence the gate exists to break.
func TestRun_NoDeployer_StillVerifiesContainer(t *testing.T) {
	cfg := minimalConfig()
	cfg.Deployer = DeployerConfig{Host: "deploy-host"}
	o, err := NewOrchestrator(OrchestratorParams{
		Config:                cfg,
		BMCFactory:            &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:                orchTestLogger(),
		Deployer:              nil,
		HealthChecker:         &mockHealthChecker{},
		ConfigServerReadiness: notServingConfigServer{},
	})
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}

	_, runErr := o.Run(context.Background())

	var notServing ErrContainerServiceNotServing
	if !errors.As(runErr, &notServing) {
		t.Fatalf("Run = %v, want ErrContainerServiceNotServing", runErr)
	}
}

// TestDeployContainer_FailsWhenDeviceScriptPortIsSquatted is the exact
// scenario from the jumpbox, and the reason the device-script probe asks
// for a boot script instead of dialling the port. The container runs
// with --net=host, so when an unrelated service already owns the
// device-script port it ACCEPTS the connection: a liveness check would
// call that serving while pxeboot's own listener never bound.
func TestDeployContainer_FailsWhenDeviceScriptPortIsSquatted(t *testing.T) {
	cfgSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/boot.ipxe" {
			_, _ = w.Write([]byte("#!ipxe\nchain menu.ipxe\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer cfgSrv.Close()

	// Stands in for the sysmon-server that owned 8081: alive, answering,
	// and not the device-script server.
	squatter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("sysmon-server ok\n"))
	}))
	defer squatter.Close()

	host, cfgPort := hostAndPort(t, cfgSrv.URL)
	_, squatPort := hostAndPort(t, squatter.URL)

	o := gateOrchestrator(t,
		DeployerConfig{Host: host, BootstrapHTTPPort: cfgPort, BootstrapDeviceScriptPort: squatPort},
		httpConfigServerReadiness{})

	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()

	var notServing ErrContainerServiceNotServing
	err := o.deployContainer(ctx)
	if !errors.As(err, &notServing) {
		t.Fatalf("deployContainer = %v, want ErrContainerServiceNotServing — a squatting service is not our server", err)
	}
	if notServing.Listener != "device-script server" {
		t.Errorf("Listener = %q, want device-script server", notServing.Listener)
	}
}

// TestDeployContainer_FailsWhenConfigPortIsSquatted is the config-server
// half of the same false positive. /health is registered
// unconditionally and answers a generic {"status":"healthy"} that any
// number of services also produce, so a 2xx from it proves only that
// SOMETHING is on the port — which under --net=host is exactly what a
// squatter gives you. The probe asks /boot.ipxe instead.
func TestDeployContainer_FailsWhenConfigPortIsSquatted(t *testing.T) {
	squatter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	}))
	defer squatter.Close()

	host, port := hostAndPort(t, squatter.URL)
	o := gateOrchestrator(t,
		DeployerConfig{Host: host, BootstrapHTTPPort: port},
		httpConfigServerReadiness{})

	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()

	var notServing ErrContainerServiceNotServing
	err := o.deployContainer(ctx)
	if !errors.As(err, &notServing) {
		t.Fatalf("deployContainer = %v, want ErrContainerServiceNotServing — a healthy-looking squatter is not our server", err)
	}
	if notServing.Listener != "config server" {
		t.Errorf("Listener = %q, want config server", notServing.Listener)
	}
}

func TestInstallLogBaseURL_HonoursConfiguredPort(t *testing.T) {
	cases := []struct {
		name string
		dep  DeployerConfig
		want string
	}{
		{"default", DeployerConfig{Host: "deploy-host"}, "http://deploy-host:8080"},
		{"configured", DeployerConfig{Host: "deploy-host", BootstrapHTTPPort: 18080}, "http://deploy-host:18080"},
		{"smb host wins", DeployerConfig{Host: "mgmt", SMBHost: "prov", BootstrapHTTPPort: 18080}, "http://prov:18080"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := installLogBaseURL(&tc.dep)
			if err != nil {
				t.Fatalf("installLogBaseURL: %v", err)
			}
			if got != tc.want {
				t.Fatalf("installLogBaseURL = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDeployerConfig_EffectivePorts covers the accessors that keep the
// deployer, the orchestrator and the container agreeing on one pair of
// ports.
func TestDeployerConfig_EffectivePorts(t *testing.T) {
	cases := []struct {
		name           string
		dep            DeployerConfig
		wantHTTP       int
		wantDeviceScri int
	}{
		{"both defaulted", DeployerConfig{}, 8080, 8081},
		{"http moved carries device script", DeployerConfig{BootstrapHTTPPort: 9000}, 9000, 9001},
		{"device script moved alone", DeployerConfig{BootstrapDeviceScriptPort: 18081}, 8080, 18081},
		{"both explicit", DeployerConfig{BootstrapHTTPPort: 18080, BootstrapDeviceScriptPort: 19090}, 18080, 19090},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.dep.EffectiveBootstrapHTTPPort(); got != tc.wantHTTP {
				t.Errorf("EffectiveBootstrapHTTPPort = %d, want %d", got, tc.wantHTTP)
			}
			if got := tc.dep.EffectiveBootstrapDeviceScriptPort(); got != tc.wantDeviceScri {
				t.Errorf("EffectiveBootstrapDeviceScriptPort = %d, want %d", got, tc.wantDeviceScri)
			}
		})
	}
}

// hostAndPort splits an httptest server URL into the pieces a
// DeployerConfig needs.
func hostAndPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("port of %q: %v", rawURL, err)
	}
	return u.Hostname(), port
}

// TestBootstrapConfig_Validate_Ports rejects container ports at config
// load rather than after the container is deployed.
//
// The derived-overflow row is the one that motivated this: an HTTP port
// of 65535 with the device-script port unset derives 65536, which is
// not a port. Left to the bind that is a silent failure — the same
// class of problem this whole change is about.
func TestBootstrapConfig_Validate_Ports(t *testing.T) {
	cases := []struct {
		name      string
		httpPort  int
		devPort   int
		wantField string // "" means the config must validate
	}{
		{"both unset", 0, 0, ""},
		{"both explicit and distinct", 18080, 18081, ""},
		{"lowest usable", 1, 2, ""},
		{"highest usable, device script explicit", maxPort, 18081, ""},

		{"negative http", -1, 0, "deployer.bootstrap_http_port"},
		{"negative device script", 0, -1, "deployer.bootstrap_device_script_port"},
		{"oversized http", maxPort + 1, 0, "deployer.bootstrap_http_port"},
		{"oversized device script", 0, maxPort + 1, "deployer.bootstrap_device_script_port"},

		// 65535 + 1 is not a port.
		{"derived overflow", maxPort, 0, "deployer.bootstrap_http_port"},

		{"explicit collision", 18080, 18080, "deployer.bootstrap_device_script_port"},
		// A derived port is always base+1, so it can never collide with
		// its own base — only an explicit pair can collide.
		{"derived never collides with its base", 8081, 0, ""},
		{"explicit device script equal to http", 9000, 9000, "deployer.bootstrap_device_script_port"},
		// Explicit device-script port equal to the DEFAULTED http port:
		// the collision check has to compare effective values, not raw ones.
		{"explicit device script equal to defaulted http", 0, DefaultBootstrapHTTPPort, "deployer.bootstrap_device_script_port"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dep := DeployerConfig{
				BootstrapHTTPPort:         tc.httpPort,
				BootstrapDeviceScriptPort: tc.devPort,
			}
			err := dep.validatePorts()

			if tc.wantField == "" {
				if err != nil {
					t.Fatalf("validatePorts = %v, want nil", err)
				}
				return
			}
			var invalid ErrInvalidPort
			if !errors.As(err, &invalid) {
				t.Fatalf("validatePorts = %v, want ErrInvalidPort", err)
			}
			if invalid.Field != tc.wantField {
				t.Fatalf("Field = %q, want %q", invalid.Field, tc.wantField)
			}
		})
	}
}

// TestBootstrapConfig_Validate_BindHost pins deployer.bootstrap_bind_host
// (#93): empty or an IP address validates, anything else names the field.
func TestBootstrapConfig_Validate_BindHost(t *testing.T) {
	cases := []struct {
		name     string
		bindHost string
		wantErr  bool
	}{
		{"unset is every interface", "", false},
		{"IPv4", "192.0.2.1", false},
		{"IPv6", "fd00::1", false},
		{"hostname", "pxe.example.com", true},
		{"host and port", "192.0.2.1:8080", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dep := DeployerConfig{BootstrapBindHost: tc.bindHost}
			err := dep.validateBindHost()

			if !tc.wantErr {
				if err != nil {
					t.Fatalf("validateBindHost = %v, want nil", err)
				}
				return
			}
			var invalid ErrInvalidConfig
			if !errors.As(err, &invalid) {
				t.Fatalf("validateBindHost = %v, want ErrInvalidConfig", err)
			}
			if invalid.Field != "deployer.bootstrap_bind_host" {
				t.Fatalf("Field = %q, want deployer.bootstrap_bind_host", invalid.Field)
			}
		})
	}
}

// TestBootstrapConfig_Validate_RejectsBadPorts proves the check is
// actually reached from BootstrapConfig.Validate, not merely present.
func TestBootstrapConfig_Validate_RejectsBadPorts(t *testing.T) {
	cfg := minimalConfig()
	cfg.Deployer.BootstrapHTTPPort = maxPort + 1

	var invalid ErrInvalidPort
	if err := cfg.Validate(); !errors.As(err, &invalid) {
		t.Fatalf("Validate = %v, want ErrInvalidPort", err)
	}
}
