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

package main

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// These tests close the last link of #53's seam (#352): that a startup failure
// in `platformd serve` becomes a non-zero PROCESS exit. An in-process test
// cannot observe its own exit status, so each test re-executes this test
// binary as `platformd`: TestMain sees helperEnv and runs the real main() with
// the arguments after "--". Nothing is built and nothing on the host changes;
// the failing startup is a config file that does not exist, which App.Init
// rejects before it touches a TPM, a store or a listener.
//
// The expected codes are read from docs/daemon/cli.md, the documented
// contract, not chosen here (#352).

const helperEnv = "PLATFORMD_MAIN_TEST_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		runMainAsPlatformd()
	}
	os.Exit(m.Run())
}

// runMainAsPlatformd runs main() with the arguments after "--", as the
// platformd binary would, and exits 0 if main returns — what the Go runtime
// does when a real main returns.
func runMainAsPlatformd() {
	args := []string{}
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	os.Args = append([]string{"platformd"}, args...)
	main()
	os.Exit(0)
}

// platformdRun is one finished platformd process.
type platformdRun struct {
	exitCode int
	stderr   string
}

// runPlatformd runs this test binary as `platformd <args>` in a scratch
// working directory and reports how the process exited.
func runPlatformd(t *testing.T, args ...string) platformdRun {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	cmd.Dir = t.TempDir()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("platformd %v did not run: %v", args, err)
	}
	return platformdRun{exitCode: cmd.ProcessState.ExitCode(), stderr: stderr.String()}
}

// documentedServeExitCodes reads the `platformd serve` exit-code table from
// docs/daemon/cli.md (§7.1 "Exit codes") and returns the code documented for
// a clean shutdown and the one documented for a startup failure.
func documentedServeExitCodes(t *testing.T) (clean, startupFailed int) {
	t.Helper()
	doc, err := os.Open(filepath.Join("..", "..", "docs", "daemon", "cli.md"))
	if err != nil {
		t.Fatalf("open the documented exit-code contract: %v", err)
	}
	defer doc.Close()

	clean, startupFailed = -1, -1
	inSection := false
	scanner := bufio.NewScanner(doc)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			inSection = line == "#### Exit codes"
			continue
		}
		if !inSection || !strings.HasPrefix(line, "| `") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) < 3 {
			continue
		}
		code, convErr := strconv.Atoi(strings.Trim(strings.TrimSpace(cells[1]), "`"))
		if convErr != nil {
			continue
		}
		meaning := strings.TrimSpace(cells[2])
		switch {
		case strings.HasPrefix(meaning, "The daemon started"):
			clean = code
		case strings.HasPrefix(meaning, "Startup failed"):
			startupFailed = code
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read docs/daemon/cli.md: %v", err)
	}
	if clean < 0 || startupFailed < 0 {
		t.Fatalf("docs/daemon/cli.md §7.1 \"Exit codes\" no longer documents both codes "+
			"(clean=%d, startup failed=%d); the test asserts against that table", clean, startupFailed)
	}
	return clean, startupFailed
}

// failingStartupArgs makes App.Init fail at its first step: the config file
// named by --config does not exist, so it cannot be read.
func failingStartupArgs(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	return []string{
		"--config", filepath.Join(dir, "missing", "config.yaml"),
		"--platform-dir", filepath.Join(dir, "trusted-data"),
		"--log-dir", filepath.Join(dir, "log"),
		"--ca-dir", filepath.Join(dir, "ca"),
	}
}

// TestPlatformdExitsZeroWhenACommandSucceeds is the control, and is first on
// purpose: without it the failure tests below pass against a main() that exits
// non-zero always, which cannot tell "startup failure is reported" from
// "nothing ever succeeds". It goes through the same main() and Execute().
func TestPlatformdExitsZeroWhenACommandSucceeds(t *testing.T) {
	clean, _ := documentedServeExitCodes(t)

	run := runPlatformd(t, "version")

	if run.exitCode != clean {
		t.Fatalf("platformd version exited %d, want %d; stderr:\n%s", run.exitCode, clean, run.stderr)
	}
}

// TestPlatformdServeStartupFailureExitsNonZero is the property #53 was about:
// a `platformd serve` that never came up must not exit as if it had run and
// been stopped, or a service manager with Restart=on-failure never retries it.
func TestPlatformdServeStartupFailureExitsNonZero(t *testing.T) {
	_, startupFailed := documentedServeExitCodes(t)

	run := runPlatformd(t, append([]string{"serve"}, failingStartupArgs(t)...)...)

	if run.exitCode != startupFailed {
		t.Fatalf("platformd serve with an unreadable config exited %d, want %d; stderr:\n%s",
			run.exitCode, startupFailed, run.stderr)
	}
	// The error names the phase, once. Execute must hand the error to main()
	// rather than exiting itself: a second copy in the journal is the sign that
	// something other than main.go decided the exit.
	const phase = "platformd serve: app initialization: "
	if got := strings.Count(run.stderr, phase); got != 1 {
		t.Fatalf("stderr names the failed phase %q %d times, want once; stderr:\n%s", phase, got, run.stderr)
	}
}

// TestPlatformdWithoutSubcommandReportsStartupFailure covers bare `platformd`,
// which runs serve. It must report a failed startup the same way, not crash:
// a panic exits 2 with a stack trace and never reaches the serve error.
func TestPlatformdWithoutSubcommandReportsStartupFailure(t *testing.T) {
	_, startupFailed := documentedServeExitCodes(t)

	run := runPlatformd(t, failingStartupArgs(t)...)

	if run.exitCode != startupFailed {
		t.Fatalf("platformd without a subcommand exited %d on a failed startup, want %d; stderr:\n%s",
			run.exitCode, startupFailed, run.stderr)
	}
	if !strings.Contains(run.stderr, "platformd serve: app initialization: ") {
		t.Fatalf("stderr does not name the failed phase; stderr:\n%s", run.stderr)
	}
}

// TestPlatformdUsageErrorExitsNonZero: a flag platformd does not have is a
// failure too, and goes through the same exit decision.
func TestPlatformdUsageErrorExitsNonZero(t *testing.T) {
	_, startupFailed := documentedServeExitCodes(t)

	run := runPlatformd(t, "serve", "--no-such-flag")

	if run.exitCode != startupFailed {
		t.Fatalf("platformd serve --no-such-flag exited %d, want %d; stderr:\n%s",
			run.exitCode, startupFailed, run.stderr)
	}
	if !strings.Contains(run.stderr, "unknown flag: --no-such-flag") {
		t.Fatalf("stderr does not name the bad flag; stderr:\n%s", run.stderr)
	}
}
