//go:build integration && eventlog_live

package diskimage

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	pkgdiskimage "github.com/jeremyhahn/go-trusted-platform/pkg/diskimage"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/measure"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu/harness"
)

const (
	// envManifestRoots names a PEM file of the CA roots the image's signed
	// manifest verifies to.
	envManifestRoots = "DISKIMAGE_MANIFEST_ROOTS"
	// envConsoleLogin names the account to log in as at the guest's
	// "login:" prompt. The account must open a shell without a password
	// and be able to read securityfs; the test invents no credentials.
	envConsoleLogin = "DISKIMAGE_CONSOLE_LOGIN"

	// eventLogCommand prints the guest's TCG event log between the markers
	// decodeEventLogCapture looks for.
	eventLogCommand = "echo " + eventLogBeginMarker +
		"; base64 /sys/kernel/security/tpm0/binary_bios_measurements; echo " + eventLogEndMarker
	// eventLogRetry is how long one attempt waits for the capture before
	// the command is sent again (the shell may not be up yet after login).
	eventLogRetry = 10 * time.Second
)

// TestBootEventLogMatchesTheSignedManifest boots the aarch64 stand-in image
// under swtpm, copies the guest's binary_bios_measurements out over the
// serial console and checks it against the image's signed measurement
// manifest (docs/SPEC.md: every signed image's manifest reproduces the live
// event log). It needs the suite's inputs, DISKIMAGE_MANIFEST_ROOTS and
// DISKIMAGE_CONSOLE_LOGIN; the eventlog_live build tag keeps it out of the
// default integration run.
func TestBootEventLogMatchesTheSignedManifest(t *testing.T) {
	in := requireInputs(t)
	rootsPath := os.Getenv(envManifestRoots)
	if rootsPath == "" {
		t.Skip(envManifestRoots + " is not set")
	}
	login := os.Getenv(envConsoleLogin)
	if login == "" {
		t.Skip(envConsoleLogin + " is not set")
	}

	// The boot works on a copy, so hash the image itself first.
	imageSHA256 := hashFile(t, in.image)
	manifestPath := pkgdiskimage.ManifestPath(in.image)
	signed, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	pem, err := os.ReadFile(rootsPath)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatalf("%s holds no PEM certificate", rootsPath)
	}

	workDir := filepath.Join(t.TempDir(), "eventlog")
	serialLog := filepath.Join(workDir, "boot.log")
	socket := filepath.Join(workDir, "console.sock")

	ctx, cancel := context.WithTimeout(context.Background(), firstBootTimeout)
	defer cancel()
	vmCtx, stopVM := context.WithCancel(ctx)
	booted := make(chan error, 1)
	go func() {
		_, err := pkgdiskimage.Boot(vmCtx, pkgdiskimage.BootOptions{
			Image:         in.image,
			Firmware:      in.uboot,
			WorkDir:       workDir,
			SerialLog:     serialLog,
			ConsoleSocket: socket,
			Logger:        logging.DefaultLogger(),
		})
		booted <- err
	}()
	// Stop the VM at the end and wait for Boot to tear down QEMU and swtpm;
	// its error then is the cancellation, and an early end of the boot
	// already fails the console waits below.
	defer func() {
		stopVM()
		<-booted
	}()

	console, err := harness.DialConsole(ctx, socket)
	require.NoError(t, err)
	defer console.Close()

	last := firstBootMilestones[len(firstBootMilestones)-1]
	if _, err := console.Expect(ctx, last); err != nil {
		t.Fatalf("waiting for %q: %v\n%s", last, err, harness.MissingMilestone(serialLog, firstBootMilestones))
	}
	console.Discard()
	require.NoError(t, console.SendLine(login))

	captured, err := captureEventLog(ctx, console)
	if err != nil {
		if strings.Contains(console.Transcript(), "Password:") {
			t.Fatalf("%s=%s asks for a password; the test needs a passwordless console account: %v", envConsoleLogin, login, err)
		}
		t.Fatalf("capturing the event log: %v", err)
	}
	eventLog, err := decodeEventLogCapture(captured)
	require.NoError(t, err)

	if _, err := measure.CheckManifestEventLog(signed, imageSHA256, roots, time.Now(), eventLog); err != nil {
		t.Fatalf("the boot's event log against %s: %v", manifestPath, err)
	}
}

// captureEventLog sends eventLogCommand until the guest answers with an
// EVENTLOG-END line, and returns the transcript up to it. The marker is
// matched after a newline so the echoed command line does not end the wait.
func captureEventLog(ctx context.Context, console *harness.Console) (string, error) {
	for {
		if err := console.SendLine(eventLogCommand); err != nil {
			return "", err
		}
		attempt, cancel := context.WithTimeout(ctx, eventLogRetry)
		out, err := console.Expect(attempt, "\n"+eventLogEndMarker)
		cancel()
		if err == nil {
			return out, nil
		}
		if ctx.Err() != nil {
			return out, err
		}
		var timeout *harness.ConsoleTimeoutError
		if !errors.As(err, &timeout) {
			return out, err
		}
	}
}

// hashFile returns the SHA-256 of the file at path, read as a stream.
func hashFile(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
	require.NoError(t, err)
	return h.Sum(nil)
}
