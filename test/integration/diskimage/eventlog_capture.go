//go:build integration

package diskimage

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu/harness"
)

// The guest prints its event log base64 encoded between these two lines,
// each on a line of its own, so the capture can be cut out of a console
// transcript that also holds the boot output and the echoed command.
const (
	eventLogBeginMarker = "EVENTLOG-BEGIN"
	eventLogEndMarker   = "EVENTLOG-END"
)

const (
	// envManifestRoots names a PEM file of the CA roots the image's signed
	// manifest verifies to.
	envManifestRoots = "DISKIMAGE_MANIFEST_ROOTS"
	// envConsoleLogin names the account to log in as at the guest's
	// "login:" prompt; it must be able to read securityfs.
	envConsoleLogin = "DISKIMAGE_CONSOLE_LOGIN"
	// envConsolePassword is that account's password, sent when the guest
	// asks for one.
	envConsolePassword = "DISKIMAGE_CONSOLE_PASSWORD"

	defaultConsoleLogin = "root"
	// defaultConsolePassword is the root password pkg/installer/installer.go
	// sets when the build config names none.
	defaultConsolePassword = "password"

	// passwordPrompt is what the guest prints after the login name when the
	// account has a password.
	passwordPrompt = "Password:"
	// passwordPromptWait is how long the login waits for passwordPrompt
	// before it takes the account to have opened a shell without one.
	passwordPromptWait = 15 * time.Second
)

// consoleCredentials are the account the live checks log in with.
type consoleCredentials struct {
	login, password string
}

// consoleCredentialsFromEnv reads envConsoleLogin and envConsolePassword,
// each defaulting to the account the factory image always has.
func consoleCredentialsFromEnv(getenv func(string) string) consoleCredentials {
	cred := consoleCredentials{login: getenv(envConsoleLogin), password: getenv(envConsolePassword)}
	if cred.login == "" {
		cred.login = defaultConsoleLogin
	}
	if cred.password == "" {
		cred.password = defaultConsolePassword
	}
	return cred
}

// manifestRootsFromEnv returns the path envManifestRoots names, or a
// *MissingInputError when it is unset.
func manifestRootsFromEnv(getenv func(string) string) (string, error) {
	path := getenv(envManifestRoots)
	if path == "" {
		return "", &MissingInputError{Variable: envManifestRoots}
	}
	return path, nil
}

// consoleLine is the part of *harness.Console the login uses.
type consoleLine interface {
	SendLine(string) error
	Expect(context.Context, string) (string, error)
}

var _ consoleLine = (*harness.Console)(nil)

// loginAtConsole sends the login name and, when the guest asks for a
// password within promptWait, the password. A guest that asks for none in
// that time is taken to have opened a shell.
func loginAtConsole(ctx context.Context, c consoleLine, cred consoleCredentials, promptWait time.Duration) error {
	if err := c.SendLine(cred.login); err != nil {
		return err
	}
	wait, cancel := context.WithTimeout(ctx, promptWait)
	_, err := c.Expect(wait, passwordPrompt)
	cancel()
	if err == nil {
		return c.SendLine(cred.password)
	}
	var timeout *harness.ConsoleTimeoutError
	if errors.As(err, &timeout) && ctx.Err() == nil {
		return nil
	}
	return err
}

// ErrEventLogCaptureEmpty is returned when the markers enclose no bytes.
var ErrEventLogCaptureEmpty = errors.New("diskimage: the captured event log is empty")

// EventLogMarkerError reports a marker missing from a console transcript.
type EventLogMarkerError struct {
	Marker string
}

func (e *EventLogMarkerError) Error() string {
	return fmt.Sprintf("diskimage: no %s line in the console transcript", e.Marker)
}

// EventLogDecodeError reports a capture body that is not base64.
type EventLogDecodeError struct {
	Err error
}

func (e *EventLogDecodeError) Error() string {
	return fmt.Sprintf("diskimage: the captured event log is not base64: %v", e.Err)
}

func (e *EventLogDecodeError) Unwrap() error { return e.Err }

// decodeEventLogCapture returns the bytes the guest printed between the last
// EVENTLOG-BEGIN line and the next EVENTLOG-END line of transcript. A marker
// counts only on a line of its own (CR and surrounding blanks ignored), so
// the echoed command that prints the markers is not taken for them.
func decodeEventLogCapture(transcript string) ([]byte, error) {
	lines := strings.Split(transcript, "\n")
	begin := -1
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == eventLogBeginMarker {
			begin = i
			break
		}
	}
	if begin < 0 {
		return nil, &EventLogMarkerError{Marker: eventLogBeginMarker}
	}
	end := -1
	for i := begin + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == eventLogEndMarker {
			end = i
			break
		}
	}
	if end < 0 {
		return nil, &EventLogMarkerError{Marker: eventLogEndMarker}
	}
	body := strings.Join(strings.Fields(strings.Join(lines[begin+1:end], "")), "")
	log, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, &EventLogDecodeError{Err: err}
	}
	if len(log) == 0 {
		return nil, ErrEventLogCaptureEmpty
	}
	return log, nil
}
