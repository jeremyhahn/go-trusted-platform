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

package helpers

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ovsdbTestPort stands in for the OVSDB_TCP_PORT choose_platformd_ports picks.
const ovsdbTestPort = "40123"

// addRemoteCall is the stub log line for the runtime remote start_ovs must
// add, so OVSDB_ADDRESS is listening whoever started ovsdb-server.
const addRemoteCall = "ovs-appctl -t ovsdb-server ovsdb-server/add-remote ptcp:" + ovsdbTestPort + ":127.0.0.1"

// ovsStubs are the commands start_ovs runs. Each stub only appends its
// command line to $STUB_LOG, so nothing on the host is started or changed.
// pgrep and ovs-appctl exit with $PGREP_RC and $APPCTL_RC.
var ovsStubs = map[string]string{
	"mkdir":        "0",
	"ovsdb-tool":   "0",
	"ovsdb-server": "0",
	"ovs-vswitchd": "0",
	"ovs-vsctl":    "0",
	"pgrep":        "${PGREP_RC:-0}",
	"ovs-appctl":   "${APPCTL_RC:-0}",
}

// shellFunction returns the definition of function name from script: from
// its "name() {" line to the first line holding only "}".
func shellFunction(t *testing.T, script, name string) string {
	t.Helper()
	start := strings.Index(script, "\n"+name+"() {\n")
	if start < 0 {
		t.Fatalf("%s: no function %s", runnerScript, name)
	}
	body := script[start+1:]
	end := strings.Index(body, "\n}\n")
	if end < 0 {
		t.Fatalf("%s: function %s has no closing brace", runnerScript, name)
	}
	return body[:end+3]
}

// runStartOVS runs the runner's start_ovs against the stubs with pgrep and
// ovs-appctl exiting pgrepRC and appctlRC. It returns start_ovs's error and
// the commands it ran, one per line.
func runStartOVS(t *testing.T, pgrepRC, appctlRC string) (error, string) {
	t.Helper()
	raw, err := os.ReadFile(runnerScript)
	if err != nil {
		t.Fatalf("read the runner: %v", err)
	}
	script := string(raw)
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("find bash: %v", err)
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatalf("create the stub dir: %v", err)
	}
	for name, rc := range ovsStubs {
		stub := "#!/bin/sh\necho \"" + name + " $*\" >> \"$STUB_LOG\"\nexit " + rc + "\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(stub), 0o755); err != nil {
			t.Fatalf("write the %s stub: %v", name, err)
		}
	}

	harness := strings.Join([]string{
		"set -u",
		"wait_for() { :; }",
		shellFunction(t, script, "ovsdb_listen_tcp"),
		shellFunction(t, script, "start_ovs"),
		"start_ovs",
	}, "\n")
	logPath := filepath.Join(dir, "calls.log")
	cmd := exec.Command(bash, "-c", harness)
	cmd.Env = []string{
		"PATH=" + bin,
		"STUB_LOG=" + logPath,
		"PGREP_RC=" + pgrepRC,
		"APPCTL_RC=" + appctlRC,
		"OVSDB_TCP_PORT=" + ovsdbTestPort,
		"OVSDB_ADDRESS=tcp:127.0.0.1:" + ovsdbTestPort,
		"OVS_INT_BRIDGE=br-int-test",
	}
	runErr := cmd.Run()
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read the stub log: %v", err)
	}
	return runErr, string(calls)
}

// TestStartOVSListensOnTheChosenPortWhenReusingADaemon covers an ovsdb-server
// that was already running (the devcontainer entrypoint's, on 6640): start_ovs
// must not start a second one and must add the chosen port at runtime.
func TestStartOVSListensOnTheChosenPortWhenReusingADaemon(t *testing.T) {
	runErr, calls := runStartOVS(t, "0", "0")
	if runErr != nil {
		t.Fatalf("start_ovs: %v\n%s", runErr, calls)
	}
	if !strings.Contains(calls, addRemoteCall+"\n") {
		t.Errorf("start_ovs reused ovsdb-server without adding %s:\n%s", addRemoteCall, calls)
	}
	if strings.Contains(calls, "ovsdb-server --remote") {
		t.Errorf("start_ovs started a second ovsdb-server:\n%s", calls)
	}
}

// TestStartOVSListensOnTheChosenPortWhenStartingTheDaemon covers the runner
// starting ovsdb-server itself: the chosen port is added the same way.
func TestStartOVSListensOnTheChosenPortWhenStartingTheDaemon(t *testing.T) {
	runErr, calls := runStartOVS(t, "1", "0")
	if runErr != nil {
		t.Fatalf("start_ovs: %v\n%s", runErr, calls)
	}
	if !strings.Contains(calls, "ovsdb-server --remote=punix:/var/run/openvswitch/db.sock") {
		t.Errorf("start_ovs did not start ovsdb-server:\n%s", calls)
	}
	if !strings.Contains(calls, addRemoteCall+"\n") {
		t.Errorf("start_ovs started ovsdb-server without adding %s:\n%s", addRemoteCall, calls)
	}
}

// TestStartOVSFailsWhenTheChosenPortCannotBeAdded checks a refused remote
// fails start_ovs instead of leaving OVSDB_ADDRESS naming an unbound port.
func TestStartOVSFailsWhenTheChosenPortCannotBeAdded(t *testing.T) {
	runErr, calls := runStartOVS(t, "0", "1")
	if runErr == nil {
		t.Fatalf("start_ovs succeeded with the remote refused:\n%s", calls)
	}
	if strings.Contains(calls, "ovs-vsctl --may-exist add-br") {
		t.Errorf("start_ovs carried on after the remote was refused:\n%s", calls)
	}
}
