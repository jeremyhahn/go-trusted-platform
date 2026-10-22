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

// No build tag: these tests run in the unit suite (TEST_UNIT_PKGS), so a runner
// edit that stops feeding the shared helpers fails `make test`, not a suite
// run that reports an unrelated connection error (#502).

package helpers

import (
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// runnerScript is the integration runner, relative to this package.
const runnerScript = "../../../build/docker/devcontainer/run-integration-tests.sh"

// endpointBinding ties a shared helper to the variable it reads and to the
// `platformd serve` flag that sets what the daemon listens on.
type endpointBinding struct {
	env      string
	flag     string
	get      func() string
	fallback string
}

var endpointBindings = []endpointBinding{
	{env: envRESTEndpoint, flag: "rest-port", get: GetRESTEndpoint, fallback: defaultRESTEndpoint},
	{env: envGRPCEndpoint, flag: "grpc-port", get: GetGRPCEndpoint, fallback: defaultGRPCEndpoint},
	{env: envQUICEndpoint, flag: "quic-port", get: GetQUICEndpoint, fallback: defaultQUICEndpoint},
	{env: envMCPEndpoint, flag: "mcp-port", get: GetMCPEndpoint, fallback: defaultMCPEndpoint},
	{env: envSocketPath, flag: "socket-path", get: GetSocketPath, fallback: defaultSocketPath},
}

// runnerBindingError reports a runner that does not hand the suites the
// endpoint platformd was told to listen on.
type runnerBindingError struct {
	env    string
	flag   string
	reason string
}

func (e *runnerBindingError) Error() string {
	return "run-integration-tests.sh: " + e.env + " / --" + e.flag + ": " + e.reason
}

// checkRunnerBinding returns nil when script passes --<flag> to platformd from
// a variable and exports <env> built from that same variable, so changing the
// one value moves the daemon and the suites together.
func checkRunnerBinding(script, env, flag string) error {
	flagValue := regexp.MustCompile(`--` + regexp.QuoteMeta(flag) + `="\$\{(\w+)\}"`).FindStringSubmatch(script)
	if flagValue == nil {
		return &runnerBindingError{env: env, flag: flag, reason: "the platformd flag does not take its value from a variable"}
	}
	exported := regexp.MustCompile(`(?m)^\s*export ` + regexp.QuoteMeta(env) + `="([^"]*)"`).FindStringSubmatch(script)
	if exported == nil {
		return &runnerBindingError{env: env, flag: flag, reason: "not exported"}
	}
	portVar := "${" + flagValue[1] + "}"
	if !strings.Contains(exported[1], portVar) {
		return &runnerBindingError{env: env, flag: flag, reason: "exported as " + exported[1] + ", not built from " + portVar}
	}
	return nil
}

func TestEndpointHelpersReadTheVariablesTheRunnerExports(t *testing.T) {
	for _, b := range endpointBindings {
		want := "from-" + b.env
		t.Setenv(b.env, want)
		if got := b.get(); got != want {
			t.Errorf("with %s=%q the helper returned %q", b.env, want, got)
		}
	}

	config := GetEndpointConfig()
	got := []string{config.REST, config.GRPC, config.QUIC, config.MCP, config.Socket}
	for i, b := range endpointBindings {
		if want := "from-" + b.env; got[i] != want {
			t.Errorf("GetEndpointConfig: %s resolved to %q, want %q", b.env, got[i], want)
		}
	}
}

func TestEndpointHelpersFallBackToTheStandardPortsOutsideTheRunner(t *testing.T) {
	for _, b := range endpointBindings {
		t.Setenv(b.env, "")
		if got := b.get(); got != b.fallback {
			t.Errorf("with %s empty the helper returned %q, want the documented default %q", b.env, got, b.fallback)
		}
	}
}

func TestRunnerExportsEveryEndpointFromThePortItGivesPlatformd(t *testing.T) {
	script, err := os.ReadFile(runnerScript)
	if err != nil {
		t.Fatalf("read the runner: %v", err)
	}
	for _, b := range endpointBindings {
		if err := checkRunnerBinding(string(script), b.env, b.flag); err != nil {
			t.Error(err)
		}
	}
}

func TestCheckRunnerBindingAcceptsAPortFromOneVariable(t *testing.T) {
	script := "    --quic-port=\"${QUIC_PORT}\" \\\n" +
		"    export PLATFORM_QUIC_ENDPOINT=\"localhost:${QUIC_PORT}\"\n"
	if err := checkRunnerBinding(script, envQUICEndpoint, "quic-port"); err != nil {
		t.Fatalf("a flag and export sharing one variable was rejected: %v", err)
	}
}

func TestCheckRunnerBindingRejectsAMismatchedRunner(t *testing.T) {
	cases := map[string]string{
		// The shape #502 found: a literal flag and a literal export that agree
		// only by coincidence.
		"literal port": "    --quic-port=9444 \\\n" +
			"    export PLATFORM_QUIC_ENDPOINT=\"localhost:9444\"\n",
		// The flag is right but the helper's variable is never exported.
		"not exported": "    --quic-port=\"${QUIC_PORT}\" \\\n" +
			"    export QUIC_SERVER_ADDR=\"localhost:${QUIC_PORT}\"\n",
		// The export exists but carries some other port.
		"other variable": "    --quic-port=\"${QUIC_PORT}\" \\\n" +
			"    export PLATFORM_QUIC_ENDPOINT=\"localhost:${MCP_PORT}\"\n",
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			err := checkRunnerBinding(script, envQUICEndpoint, "quic-port")
			var bindingErr *runnerBindingError
			if !errors.As(err, &bindingErr) {
				t.Fatalf("got %v, want a *runnerBindingError", err)
			}
			if bindingErr.env != envQUICEndpoint {
				t.Errorf("error names %q, want %q", bindingErr.env, envQUICEndpoint)
			}
		})
	}
}

// integrationConfig is the config the runner starts platformd with.
const integrationConfig = "../config.yaml"

// webServiceBindingError reports a runner whose exported webservice endpoint
// does not reach the listener the config declares.
type webServiceBindingError struct {
	reason string
}

func (e *webServiceBindingError) Error() string {
	return "webservice endpoint: " + e.reason
}

// checkWebServiceBinding verifies that the runner exports
// PLATFORM_WEBSERVICE_ENDPOINT built from PLATFORMD_WEBSERVICE_TLS_PORT, and
// that the variable holds the tls-port of the config's one webservice. The
// port is not a serve flag, so unlike checkRunnerBinding the agreement is
// between the runner and the config file.
func checkWebServiceBinding(script string, config []byte) error {
	var cfg struct {
		WebServices []struct {
			TLSPort int `yaml:"tls-port"`
		} `yaml:"webservices"`
	}
	if err := yaml.Unmarshal(config, &cfg); err != nil {
		return &webServiceBindingError{reason: "config does not parse: " + err.Error()}
	}
	if len(cfg.WebServices) != 1 {
		return &webServiceBindingError{reason: "config declares " + strconv.Itoa(len(cfg.WebServices)) + " webservices, want 1"}
	}
	portValue := regexp.MustCompile(`(?m)^PLATFORMD_WEBSERVICE_TLS_PORT="(\d+)"`).FindStringSubmatch(script)
	if portValue == nil {
		return &webServiceBindingError{reason: "PLATFORMD_WEBSERVICE_TLS_PORT is not set to a port"}
	}
	if configPort := strconv.Itoa(cfg.WebServices[0].TLSPort); portValue[1] != configPort {
		return &webServiceBindingError{reason: "runner port " + portValue[1] + ", config tls-port " + configPort}
	}
	exported := regexp.MustCompile(`(?m)^\s*export ` + envWebServiceEndpoint + `="([^"]*)"`).FindStringSubmatch(script)
	if exported == nil {
		return &webServiceBindingError{reason: envWebServiceEndpoint + " not exported"}
	}
	if !strings.HasSuffix(exported[1], ":${PLATFORMD_WEBSERVICE_TLS_PORT}") {
		return &webServiceBindingError{reason: "exported as " + exported[1] + ", not built from ${PLATFORMD_WEBSERVICE_TLS_PORT}"}
	}
	return nil
}

func TestWebServiceEndpointHelperReadsTheRunnerVariable(t *testing.T) {
	t.Setenv(envWebServiceEndpoint, "https://localhost:18444")
	if got := GetWebServiceEndpoint(); got != "https://localhost:18444" {
		t.Errorf("with %s set the helper returned %q", envWebServiceEndpoint, got)
	}
}

func TestWebServiceEndpointHelperFallsBackOutsideTheRunner(t *testing.T) {
	t.Setenv(envWebServiceEndpoint, "")
	if got := GetWebServiceEndpoint(); got != defaultWebServiceEndpoint {
		t.Errorf("with %s empty the helper returned %q, want %q", envWebServiceEndpoint, got, defaultWebServiceEndpoint)
	}
}

func TestRunnerExportsTheWebServiceEndpointTheConfigListensOn(t *testing.T) {
	script, err := os.ReadFile(runnerScript)
	if err != nil {
		t.Fatalf("read the runner: %v", err)
	}
	config, err := os.ReadFile(integrationConfig)
	if err != nil {
		t.Fatalf("read the integration config: %v", err)
	}
	if err := checkWebServiceBinding(string(script), config); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), "\nPLATFORMD_WEBSERVICE_TLS_PORT=\""+strings.TrimPrefix(defaultWebServiceEndpoint, "https://localhost:")+"\"\n") {
		t.Errorf("default %s is not on the runner's webservice port", defaultWebServiceEndpoint)
	}
}

func TestCheckWebServiceBindingRejectsAMismatch(t *testing.T) {
	const runner = "PLATFORMD_WEBSERVICE_TLS_PORT=\"8444\"\n" +
		"    export PLATFORM_WEBSERVICE_ENDPOINT=\"https://localhost:${PLATFORMD_WEBSERVICE_TLS_PORT}\"\n"
	const config = "webservices:\n  - name: integration\n    tls-port: 8444\n"
	if err := checkWebServiceBinding(runner, []byte(config)); err != nil {
		t.Fatalf("matching runner and config rejected: %v", err)
	}

	const portLine = "PLATFORMD_WEBSERVICE_TLS_PORT=\"8444\"\n"
	cases := map[string]struct {
		runner string
		config string
	}{
		"no webservice in the config": {
			runner: runner,
			config: "dns:\n  enabled: true\n",
		},
		"config on another port": {
			runner: runner,
			config: "webservices:\n  - tls-port: 9443\n",
		},
		"config does not parse": {
			runner: runner,
			config: "webservices: [\n",
		},
		"port not set": {
			runner: "    export PLATFORM_WEBSERVICE_ENDPOINT=\"https://localhost:8444\"\n",
			config: config,
		},
		"not exported": {
			runner: portLine + "    export WEBSERVICE_ADDR=\"https://localhost:${PLATFORMD_WEBSERVICE_TLS_PORT}\"\n",
			config: config,
		},
		"exported from a literal": {
			runner: portLine + "    export PLATFORM_WEBSERVICE_ENDPOINT=\"https://localhost:8444\"\n",
			config: config,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := checkWebServiceBinding(tc.runner, []byte(tc.config))
			var bindingErr *webServiceBindingError
			if !errors.As(err, &bindingErr) {
				t.Fatalf("got %v, want a *webServiceBindingError", err)
			}
		})
	}
}
