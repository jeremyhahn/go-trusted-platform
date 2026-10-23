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

package boundedexec

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// standIn writes an executable shell script called name into a fresh
// directory and puts that directory first on PATH, so the test runs it in
// place of the real OVS tool.
func standIn(t *testing.T, name, body string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatalf("write stand-in %s: %v", name, err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestCommandIsKilledAtTheDeadlineAndTheErrorNamesIt(t *testing.T) {
	standIn(t, "ovs-ofctl", "echo 'connecting to br-int' >&2\nexec sleep 30")

	start := time.Now()
	out, err := Command("ovs-ofctl", "dump-flows", "br-int").WithDeadline(300 * time.Millisecond).CombinedOutput()
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("the call returned after %s: the deadline did not fire", took)
	}

	var timeout *TimeoutError
	if !errors.As(err, &timeout) {
		t.Fatalf("err = %v (%T), want a *TimeoutError", err, err)
	}
	if timeout.Command != "ovs-ofctl dump-flows br-int" {
		t.Errorf("Command = %q, want the full command line", timeout.Command)
	}
	if timeout.Elapsed < 300*time.Millisecond {
		t.Errorf("Elapsed = %s, shorter than the 300ms deadline", timeout.Elapsed)
	}
	if timeout.Stderr != "connecting to br-int\n" {
		t.Errorf("Stderr = %q, want what the command wrote before it was killed", timeout.Stderr)
	}
	for _, want := range []string{"ovs-ofctl dump-flows br-int", "300ms deadline", "connecting to br-int"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err.Error(), want)
		}
	}
	if !strings.Contains(string(out), "connecting to br-int") {
		t.Errorf("combined output %q lost the stderr written before the kill", out)
	}
}

func TestCommandReturnsTheOutputOfAFastCommand(t *testing.T) {
	standIn(t, "ovs-ofctl", `echo "$@"`)

	out, err := Command("ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "br-int").Output()
	if err != nil {
		t.Fatalf("Output: %v", err)
	}
	if string(out) != "-O OpenFlow13 dump-flows br-int\n" {
		t.Errorf("stdout = %q, want the arguments unchanged (ovs-ofctl gets no --timeout)", out)
	}
}

func TestOVSVsctlGetsATimeoutOfTheDeadline(t *testing.T) {
	standIn(t, "ovs-vsctl", `echo "$@"`)

	out, err := Command("ovs-vsctl", "--if-exists", "del-br", "br0").Output()
	if err != nil {
		t.Fatalf("Output: %v", err)
	}
	if string(out) != "--timeout=30 --if-exists del-br br0\n" {
		t.Errorf("ovs-vsctl was run with %q, want --timeout=30 first", out)
	}

	out, err = Command("ovs-vsctl", "list-br").WithDeadline(200 * time.Millisecond).Output()
	if err != nil {
		t.Fatalf("Output: %v", err)
	}
	if string(out) != "--timeout=1 list-br\n" {
		t.Errorf("a sub-second deadline gave %q, want --timeout=1 (0 means wait forever)", out)
	}
}

func TestOVSVsctlKeepsACallersOwnTimeout(t *testing.T) {
	standIn(t, "ovs-vsctl", `echo "$@"`)

	out, err := Command("ovs-vsctl", "--timeout=5", "show").Output()
	if err != nil {
		t.Fatalf("Output: %v", err)
	}
	if string(out) != "--timeout=5 show\n" {
		t.Errorf("ovs-vsctl was run with %q, want the caller's --timeout alone", out)
	}
}

func TestCommandErrorCarriesTheExitCodeAndStderr(t *testing.T) {
	standIn(t, "ovs-vsctl", "echo 'no bridge named br9' >&2\nexit 2")

	err := Command("ovs-vsctl", "br-exists", "br9").Run()

	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) {
		t.Fatalf("err = %v (%T), want a *CommandError", err, err)
	}
	if cmdErr.Stderr != "no bridge named br9\n" {
		t.Errorf("Stderr = %q, want the command's stderr", cmdErr.Stderr)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Errorf("err = %v, want it to unwrap to an *exec.ExitError with code 2", err)
	}
	if !strings.Contains(err.Error(), "ovs-vsctl --timeout=30 br-exists br9") {
		t.Errorf("error %q does not name the command line", err.Error())
	}
}

func TestCommandThatCannotStartIsACommandError(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	_, err := Command("ovs-ofctl", "show", "br-int").CombinedOutput()

	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) {
		t.Fatalf("err = %v (%T), want a *CommandError", err, err)
	}
	if !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("err = %v, want it to unwrap to exec.ErrNotFound", err)
	}
}
