package iso

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// startLine is the first line autoinstall.sh logs after its script-start
// checkpoint, and so the script's first write to its console.
const startLine = `log "Starting platformd system installation..."`

// runAutoinstallOpening runs the generated autoinstall script up to the end
// of the line holding through, then runs then, then marks that it got past
// both. The guest it runs in has a default route to 192.0.2.1 and no debug
// sink: curl, wget and nc are stubs that cannot connect, as in the ISO test
// install where nothing listens on 10.0.2.2:8080. The script's stdout and
// stderr are console, and its /tmp files land in a test directory.
//
// It returns whether the script reached the mark and the shell's error.
func runAutoinstallOpening(t *testing.T, through, then string, console *os.File) (bool, error) {
	t.Helper()
	script := autoinstallScriptFor(t, "poweroff")
	at := strings.Index(script, through)
	if at < 0 {
		t.Fatalf("the autoinstall script has no %q", through)
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	stubs := map[string]string{
		"ip":   "#!/bin/sh\necho 'default via 192.0.2.1 dev eth0'\n",
		"curl": "#!/bin/sh\necho 'curl: (7) Failed to connect' >&2\nexit 7\n",
		"wget": "#!/bin/sh\necho 'wget: can not connect' >&2\nexit 1\n",
		"nc":   "#!/bin/sh\ncat >/dev/null\necho 'nc: connection refused' >&2\nexit 1\n",
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	mark := filepath.Join(dir, "survived")
	opening := strings.ReplaceAll(script[:at+len(through)]+"\n"+then+"\n", "/tmp/", dir+"/")
	opening += ": > \"" + mark + "\"\n"

	cmd := exec.CommandContext(t.Context(), "sh", "-c", opening)
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	cmd.Stdout = console
	cmd.Stderr = console
	err := cmd.Run()

	_, statErr := os.Stat(mark)
	return statErr == nil, err
}

// openConsole opens path for writing as the script's console.
func openConsole(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// TestAutoinstallScript_UnreachableSinkDoesNotStopTheInstall pins
// docs/installer/autoinstall.md §8: a sink that cannot be reached leaves
// the install running. The script-start checkpoint is the first upload.
func TestAutoinstallScript_UnreachableSinkDoesNotStopTheInstall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "console")
	console := openConsole(t, path)

	survived, err := runAutoinstallOpening(t, "upload_checkpoint script-start", startLine, console)

	if err != nil || !survived {
		out, _ := os.ReadFile(path)
		t.Fatalf("the script stopped at its script-start checkpoint with no sink to reach (err=%v):\n%s", err, out)
	}
}

// TestAutoinstallScript_ConsoleThatRefusesWritesDoesNotStopTheInstall is
// the ISO test install's failure on #973: the guest console refused the
// script's first write, the echo in log() failed under set -e, and the
// script exited 1 straight after its script-start checkpoint. /dev/full
// refuses every write the same way.
func TestAutoinstallScript_ConsoleThatRefusesWritesDoesNotStopTheInstall(t *testing.T) {
	console := openConsole(t, "/dev/full")

	survived, err := runAutoinstallOpening(t, startLine, `log "a second line"`, console)

	if err != nil || !survived {
		t.Fatalf("a console that refuses writes stopped the install at its first log line (err=%v)", err)
	}
}

// TestAutoinstallScript_ErrorFailsTheInstallWhateverTheConsole pins the
// other half: a real failure still exits 1, on a working console and on one
// that refuses writes.
func TestAutoinstallScript_ErrorFailsTheInstallWhateverTheConsole(t *testing.T) {
	for name, path := range map[string]string{
		"working console":         filepath.Join(t.TempDir(), "console"),
		"console refusing writes": "/dev/full",
	} {
		t.Run(name, func(t *testing.T) {
			console := openConsole(t, path)

			survived, err := runAutoinstallOpening(t, startLine, `error "target disk missing"`, console)

			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
				t.Fatalf("error() must exit 1, got %v", err)
			}
			if survived {
				t.Fatal("the script ran on past error()")
			}
		})
	}
}
