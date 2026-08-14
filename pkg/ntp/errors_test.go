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
