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

package deployer

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// imageDir is the bootstrap image's build context, beside this package.
const imageDir = "../../../build/docker/bootstrap"

// pxebootArgs sources the image's pxeboot-env.sh under env, as the
// entrypoint does, and returns the optional pxeboot flags it assembled. It
// only sets shell variables, so nothing on the host changes.
func pxebootArgs(t *testing.T, env ...string) (args, stderr string, err error) {
	t.Helper()
	script, err := filepath.Abs(filepath.Join(imageDir, "pxeboot-env.sh"))
	if err != nil {
		t.Fatalf("resolve pxeboot-env.sh: %v", err)
	}
	cmd := exec.CommandContext(t.Context(), "sh", "-eu", "-c", `. "$1"; printf '%s' "$BOOTSTRAP_PXEBOOT_ARGS"`, "sh", script)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err = cmd.Run()
	return out.String(), errOut.String(), err
}

// TestPxebootEnv_Gateway pins what the image passes pxeboot for the DHCP
// router option: pxeboot advertises option 3 only when it gets
// --dhcp-gateway, so no-router must drop the flag, and off the default
// and a configured gateway must reach it as before.
func TestPxebootEnv_Gateway(t *testing.T) {
	tests := []struct {
		name string
		env  []string
		want string
	}{
		{name: "default gateway", want: "--dhcp-gateway 192.0.2.1"},
		{name: "configured gateway", env: []string{"BOOTSTRAP_GATEWAY=10.9.9.1"}, want: "--dhcp-gateway 10.9.9.1"},
		{name: "no-router off", env: []string{"BOOTSTRAP_NO_ROUTER=false"}, want: "--dhcp-gateway 192.0.2.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args, stderr, err := pxebootArgs(t, tt.env...)
			if err != nil {
				t.Fatalf("pxeboot-env.sh: %v: %s", err, stderr)
			}
			if !strings.Contains(args, tt.want) {
				t.Errorf("pxeboot args = %q, want %q", args, tt.want)
			}
		})
	}

	args, stderr, err := pxebootArgs(t, "BOOTSTRAP_NO_ROUTER=true", "BOOTSTRAP_PROXY_DHCP=true")
	if err != nil {
		t.Fatalf("pxeboot-env.sh with no-router: %v: %s", err, stderr)
	}
	if strings.Contains(args, "--dhcp-gateway") {
		t.Errorf("pxeboot args = %q, no-router must pass no gateway", args)
	}
	if !strings.Contains(args, "--dhcp-proxy") {
		t.Errorf("pxeboot args = %q, the other flags must still be assembled", args)
	}
}

// TestPxebootEnv_GatewayRefused: the entrypoint refuses what the deployer
// refuses — no-router with a gateway — and a value that is not a boolean,
// rather than starting a DHCP server that does something unasked.
func TestPxebootEnv_GatewayRefused(t *testing.T) {
	for name, env := range map[string][]string{
		"no-router with gateway": {"BOOTSTRAP_NO_ROUTER=true", "BOOTSTRAP_GATEWAY=192.0.2.1"},
		"no-router not boolean":  {"BOOTSTRAP_NO_ROUTER=yes"},
	} {
		t.Run(name, func(t *testing.T) {
			args, stderr, err := pxebootArgs(t, env...)
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
				t.Fatalf("pxeboot-env.sh = %v (args %q), want exit status 2", err, args)
			}
			if !strings.Contains(stderr, "BOOTSTRAP_NO_ROUTER") {
				t.Errorf("stderr = %q, want it to name BOOTSTRAP_NO_ROUTER", stderr)
			}
		})
	}
}

// TestImageGatewayWiring: the gateway reaches pxeboot only through
// pxeboot-env.sh. A --dhcp-gateway left in supervisord.conf would advertise
// a router under no-router, and the entrypoint must source the copy the
// Dockerfile installs.
func TestImageGatewayWiring(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(imageDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(b)
	}
	if conf := read("supervisord.conf"); strings.Contains(conf, "--dhcp-gateway") {
		t.Error("supervisord.conf passes --dhcp-gateway; it belongs to BOOTSTRAP_PXEBOOT_ARGS")
	}
	const installed = "/usr/local/bin/pxeboot-env.sh"
	if !strings.Contains(read("Dockerfile"), "COPY pxeboot-env.sh "+installed+"\n") {
		t.Errorf("Dockerfile does not install pxeboot-env.sh at %s", installed)
	}
	if !strings.Contains(read("entrypoint.sh"), "\n. "+installed+"\n") {
		t.Errorf("entrypoint.sh does not source %s", installed)
	}
}
