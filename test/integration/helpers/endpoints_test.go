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
	"strings"
	"testing"
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
