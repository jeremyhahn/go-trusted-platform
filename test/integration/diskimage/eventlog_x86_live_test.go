//go:build integration && eventlog_live

package diskimage

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/measure"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu/harness"
)

// x86BootTimeout bounds the x86 ISO boot, from QEMU start to the captured
// event log; a TCG boot of an installer ISO is slow.
const x86BootTimeout = 45 * time.Minute

// TestX86ISOEventLogMatchesTheSignedManifest boots an x86 ISO under OVMF and
// swtpm, copies the guest's binary_bios_measurements out over the serial
// console and checks it against the ISO's signed measurement manifest
// (docs/SPEC.md: every signed image's manifest reproduces the live event
// log). It needs the DISKIMAGE_X86_* variables and DISKIMAGE_MANIFEST_ROOTS,
// and fails when one is unset; it logs in as DISKIMAGE_CONSOLE_LOGIN with
// DISKIMAGE_CONSOLE_PASSWORD (default root and the installer's default root
// password).
func TestX86ISOEventLogMatchesTheSignedManifest(t *testing.T) {
	in, err := x86InputsFromEnv(os.Getenv)
	var missing *MissingInputError
	if errors.As(err, &missing) {
		t.Fatalf("%v; the eventlog_live build runs the x86 ISO check, which needs every DISKIMAGE_X86_* input", missing)
	}
	require.NoError(t, err)
	rootsPath, err := manifestRootsFromEnv(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	cred := consoleCredentialsFromEnv(os.Getenv)

	isoSHA256 := hashFile(t, in.iso)
	signed, err := os.ReadFile(in.manifest)
	require.NoError(t, err)
	pem, err := os.ReadFile(rootsPath)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatalf("%s holds no PEM certificate", rootsPath)
	}

	workDir := filepath.Join(t.TempDir(), "eventlog-x86")
	require.NoError(t, os.MkdirAll(workDir, 0o755))
	cfg := x86BootConfig(in, workDir)
	logger := logging.DefaultLogger()

	ctx, cancel := context.WithTimeout(context.Background(), x86BootTimeout)
	defer cancel()

	tpm, _, err := harness.StartTPM(ctx, logger, cfg)
	require.NoError(t, err)
	defer harness.StopTPM(logger, tpm)

	vm, err := qemu.NewVM(cfg, logger)
	require.NoError(t, err)
	require.NoError(t, vm.CreateDisk())
	require.NoError(t, vm.Start(ctx, string(qemu.BootModeInstall)))
	defer func() { _ = vm.Stop() }()

	console, err := harness.DialConsole(ctx, cfg.ConsoleSocketPath)
	require.NoError(t, err)
	defer console.Close()

	if _, err := console.Expect(ctx, in.ready); err != nil {
		t.Fatalf("waiting for %q: %v\n%s", in.ready, err, harness.MissingMilestone(cfg.SerialLogFile, []string{in.ready}))
	}
	console.Discard()
	require.NoError(t, loginAtConsole(ctx, console, cred, passwordPromptWait))

	captured, err := captureEventLog(ctx, console)
	if err != nil {
		if strings.Contains(console.Transcript(), "Login incorrect") {
			t.Fatalf("%s=%s was refused; set %s to the account's password: %v", envConsoleLogin, cred.login, envConsolePassword, err)
		}
		t.Fatalf("capturing the event log: %v", err)
	}
	eventLog, err := decodeEventLogCapture(captured)
	require.NoError(t, err)

	if _, err := measure.CheckManifestEventLog(signed, isoSHA256, roots, time.Now(), eventLog); err != nil {
		t.Fatalf("the x86 boot's event log against %s: %v", in.manifest, err)
	}
}
