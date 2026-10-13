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

package ntp

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// errCause is the sentinel wrapped by the wrapping error types.
var errCause = errors.New("underlying failure")

func TestErrorMessagesIdentifyTheirOrigin(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"nil config":            {ErrNilConfig{}, "configuration is nil"},
		"invalid mode":          {ErrInvalidMode{Mode: "x"}, `invalid mode "x"`},
		"invalid action":        {ErrInvalidTimeoutAction{Action: "x"}, `invalid startup-gate.on-timeout "x"`},
		"missing consume":       {ErrMissingConsumeSection{Mode: "both"}, "requires a consume section"},
		"missing serve":         {ErrMissingServeSection{Mode: "both"}, "requires a serve section"},
		"no upstream":           {ErrNoUpstream{}, "no time source"},
		"empty address":         {ErrEmptyUpstreamAddress{Index: 2}, "consume.upstream[2].address is empty"},
		"invalid address":       {ErrInvalidUpstreamAddress{Address: "a b"}, "invalid upstream address"},
		"no listen networks":    {ErrNoListenNetworks{}, "explicit CIDR allow-list is required"},
		"invalid network":       {ErrInvalidListenNetwork{Network: "x", Cause: errCause}, "invalid serve.listen-networks entry"},
		"unrestricted network":  {ErrUnrestrictedListenNetwork{Network: "0.0.0.0/0"}, "is unrestricted"},
		"invalid stratum":       {ErrInvalidLocalStratum{Stratum: 42}, "out of range (1-15)"},
		"invalid NTS-KE port":   {ErrInvalidNTSKEPort{Port: 0}, "serve.nts.port 0 out of range (1-65535)"},
		"missing NTS material":  {ErrMissingNTSMaterial{Field: "serve.nts.key-uri"}, "serve.nts.key-uri"},
		"invalid gate timeout":  {ErrInvalidGateTimeout{Seconds: -1}, "must be positive"},
		"render failed":         {ErrRenderFailed{Cause: errCause}, "chrony.conf render failed"},
		"write failed":          {ErrWriteConfigFailed{Path: "/etc/x", Cause: errCause}, "failed to write /etc/x"},
		"service failed":        {ErrServiceCommandFailed{Service: "chronyd", Action: "restart", Output: "oops", Cause: errCause}, "rc-service chronyd restart failed"},
		"control unavailable":   {ErrControlUnavailable{Command: "tracking", Output: "506", Cause: errCause}, "chrony control command"},
		"malformed output":      {ErrMalformedControlOutput{Command: "sources", Line: "a,b", Want: 10, Got: 2}, "malformed sources output"},
		"sync timeout":          {ErrSyncTimeout{Seconds: 120}, "did not synchronize within 120s"},
		"no reachable source":   {ErrNoReachableSource{Total: 3}, "no reachable time source (3 configured)"},
		"rtc write failed":      {ErrRTCWriteFailed{Output: "ioctl", Cause: errCause}, "hwclock --systohc failed"},
		"disabled":              {ErrDisabled{}, "not enabled"},
		"unresolved NTS secret": {ErrUnresolvedNTSMaterial{Field: "serve.nts.key-uri", Value: "kms://k"}, "unresolved secret reference"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			msg := tc.err.Error()
			if !strings.HasPrefix(msg, "ntp: ") {
				t.Fatalf("error %q does not identify its origin", msg)
			}
			if !strings.Contains(msg, tc.want) {
				t.Fatalf("error %q does not contain %q", msg, tc.want)
			}
		})
	}
}

func TestWrappingErrorsUnwrapToTheirCause(t *testing.T) {
	wrappers := map[string]error{
		"invalid network":     ErrInvalidListenNetwork{Network: "x", Cause: errCause},
		"render failed":       ErrRenderFailed{Cause: errCause},
		"write failed":        ErrWriteConfigFailed{Path: "/etc/x", Cause: errCause},
		"service failed":      ErrServiceCommandFailed{Cause: errCause},
		"control unavailable": ErrControlUnavailable{Cause: errCause},
		"rtc write failed":    ErrRTCWriteFailed{Cause: errCause},
	}

	for name, err := range wrappers {
		t.Run(name, func(t *testing.T) {
			if !errors.Is(err, errCause) {
				t.Fatalf("errors.Is(%v, errCause) = false, want true", err)
			}
		})
	}
}

func TestErrorsOmitEmptyCommandOutput(t *testing.T) {
	withOutput := ErrServiceCommandFailed{Service: "chronyd", Action: "start", Output: "  ", Cause: errCause}
	if strings.Contains(withOutput.Error(), "()") {
		t.Fatalf("blank output should be omitted, got %q", withOutput.Error())
	}
	control := ErrControlUnavailable{Command: "tracking", Output: "", Cause: errCause}
	if strings.Contains(control.Error(), "()") {
		t.Fatalf("blank output should be omitted, got %q", control.Error())
	}
	rtc := ErrRTCWriteFailed{Output: "", Cause: errCause}
	if strings.Contains(rtc.Error(), "()") {
		t.Fatalf("blank output should be omitted, got %q", rtc.Error())
	}
}

func TestOSFileSystemRoundTripsThroughATempDirectory(t *testing.T) {
	fs := osFileSystem{}
	root := filepath.Join(t.TempDir(), "chrony")

	if err := fs.MkdirAll(root, dirMode); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	path := filepath.Join(root, "chrony.conf")
	if err := fs.WriteFile(path, []byte("makestep 1.0 3\n"), configFileMode); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	data, err := fs.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != "makestep 1.0 3\n" {
		t.Fatalf("ReadFile() = %q, want the written content", data)
	}

	if _, err := fs.ReadFile(filepath.Join(root, "missing.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ReadFile(missing) error = %v, want os.ErrNotExist", err)
	}
}

// TestOSFileSystemWriteFileEnforcesModeOnAnExistingPath pins the reason
// WriteFile does not simply call os.WriteFile: os.WriteFile applies its
// permission argument only when it CREATES the file, so writing the NTS
// private key over a path that already exists world-readable would publish
// the key at that wider mode.
func TestOSFileSystemWriteFileEnforcesModeOnAnExistingPath(t *testing.T) {
	fs := osFileSystem{}
	path := filepath.Join(t.TempDir(), "nts-server.key")

	// Pre-create the path wide open, as a stale artifact or a hostile
	// local process could.
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatalf("seed WriteFile() error = %v", err)
	}

	key := []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
	if err := fs.WriteFile(path, key, keyFileMode); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != keyFileMode {
		t.Fatalf("mode = %v, want %v — the private key must not inherit the pre-existing mode", got, keyFileMode)
	}
	data, err := fs.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != string(key) {
		t.Fatalf("ReadFile() = %q, want the written key", data)
	}

	// The write must also truncate: no tail of the longer stale content
	// may survive under the new key.
	if err := fs.WriteFile(path, []byte("short\n"), keyFileMode); err != nil {
		t.Fatalf("second WriteFile() error = %v", err)
	}
	if data, _ := fs.ReadFile(path); string(data) != "short\n" {
		t.Fatalf("ReadFile() = %q, want the truncated content", data)
	}
}

// TestOSFileSystemWriteFileDoesNotFollowASymlink pins the other half of the
// reason WriteFile stages and renames: a symlink planted at the destination
// must be REPLACED, never followed. Following it would write the NTS private
// key to a location an attacker chose, where mode 0600 protects them.
func TestOSFileSystemWriteFileDoesNotFollowASymlink(t *testing.T) {
	fs := osFileSystem{}
	root := t.TempDir()
	victim := filepath.Join(root, "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o644); err != nil {
		t.Fatalf("seed victim error = %v", err)
	}

	path := filepath.Join(root, "nts-server.key")
	if err := os.Symlink(victim, path); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	key := []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
	if err := fs.WriteFile(path, key, keyFileMode); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// The key landed at the real path, not through the link.
	if data, _ := fs.ReadFile(path); string(data) != string(key) {
		t.Fatalf("ReadFile(path) = %q, want the key", data)
	}
	if data, _ := os.ReadFile(victim); string(data) != "untouched" {
		t.Fatalf("the symlink target was written through: %q", data)
	}

	// The destination is now a regular file at the intended mode.
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("the planted symlink must be replaced, not preserved")
	}
	if got := info.Mode().Perm(); got != keyFileMode {
		t.Fatalf("mode = %v, want %v", got, keyFileMode)
	}
}

func TestWithServiceNameOverridesTheOpenRCUnit(t *testing.T) {
	runner := newFakeRunner(map[string]fakeResponse{
		"default": {Output: ""},
		"restart": {Output: ""},
		"status":  {Err: errors.New("stopped")},
	})
	svc, err := NewService(consumerConfig(),
		WithPaths(testPaths()),
		WithLogger(quietLogger()),
		WithRunner(runner),
		WithFileSystem(newMemFS()),
		WithController(&fakeController{}),
		WithServiceName("chrony"),
	)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if err := svc.Apply(t.Context()); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	call, ok := runner.callFor("default")
	if !ok {
		t.Fatal("rc-update was not invoked")
	}
	if call.Args[1] != "chrony" {
		t.Fatalf("rc-update service = %q, want chrony", call.Args[1])
	}
}

func TestWrappingErrorsTolerateANilCause(t *testing.T) {
	// Error values can be constructed without a cause (e.g. a transport
	// reporting only a command name). Formatting one must never panic —
	// a nil-deref here would take down the QUIC handler goroutine.
	nilCause := map[string]error{
		"invalid network":     ErrInvalidListenNetwork{Network: "x"},
		"render failed":       ErrRenderFailed{},
		"write failed":        ErrWriteConfigFailed{Path: "/etc/x"},
		"service failed":      ErrServiceCommandFailed{Service: "chronyd", Action: "start"},
		"control unavailable": ErrControlUnavailable{Command: "tracking"},
		"rtc write failed":    ErrRTCWriteFailed{},
	}

	for name, err := range nilCause {
		t.Run(name, func(t *testing.T) {
			msg := err.Error()
			if !strings.Contains(msg, "unknown cause") {
				t.Fatalf("error %q should report an unknown cause", msg)
			}
		})
	}
}
