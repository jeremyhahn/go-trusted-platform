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

package bmc

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

func TestRunConsole_NoMode(t *testing.T) {
	err := runConsole(context.Background(), &standaloneBMCFlags{}, "", false, nil, 0)
	var nomode ErrBMCNoMode
	require.ErrorAs(t, err, &nomode)
}

func TestRunConsole_RedfishProtocolRejected(t *testing.T) {
	err := runConsole(context.Background(), &standaloneBMCFlags{
		host:     "1.2.3.4",
		user:     "admin",
		password: "secret",
		protocol: string(bmc.ProtocolRedfish),
	}, "", false, nil, 0)
	var notSupported ErrBMCConsoleNotSupported
	require.ErrorAs(t, err, &notSupported)
	assert.Equal(t, string(bmc.ProtocolRedfish), notSupported.Protocol)
	assert.EqualError(t, err, "bmc: protocol redfish does not support SOL console (use --bmc-protocol ipmi)")
}

func TestRunConsole_ConsoleActivateError(t *testing.T) {
	mock := bmc.NewMockClient()
	mock.ConsoleErr = errors.New("activate boom")
	defer withMockBMCClient(t, mock)()

	err := runConsole(context.Background(), &standaloneBMCFlags{
		host:     "1.2.3.4",
		user:     "admin",
		password: "secret",
		protocol: string(bmc.ProtocolIPMI),
	}, "", false, nil, 0)
	var act ErrBMCConsoleActivate
	require.ErrorAs(t, err, &act)
	require.ErrorIs(t, err, mock.ConsoleErr)
	assert.EqualError(t, err, "bmc: failed to activate SOL console: activate boom")
	assert.Equal(t, int64(1), mock.ConsoleCalls())
}

// SOL is IPMI-only, so an unset or "auto" protocol is pinned to IPMI before
// the client is built rather than probing for Redfish.
func TestRunConsole_UnsetProtocolForcesIPMI(t *testing.T) {
	for _, protocol := range []string{"", "auto"} {
		t.Run("protocol="+protocol, func(t *testing.T) {
			mock := bmc.NewMockClient()
			mock.ConsoleErr = errors.New("activate boom")
			defer withMockBMCClient(t, mock)()

			flags := &standaloneBMCFlags{
				host:     "192.0.2.10",
				user:     "admin",
				password: "secret",
				protocol: protocol,
			}
			err := runConsole(context.Background(), flags, "", false, nil, 0)
			var act ErrBMCConsoleActivate
			require.ErrorAs(t, err, &act)
			assert.Equal(t, string(bmc.ProtocolIPMI), flags.protocol)
			assert.Equal(t, int64(1), mock.ConsoleCalls())
		})
	}
}

func TestRunConsole_ClientConfigError(t *testing.T) {
	err := runConsole(context.Background(), &standaloneBMCFlags{
		host:     "192.0.2.10",
		password: "secret",
		protocol: string(bmc.ProtocolIPMI),
	}, "", false, nil, 0)
	var missing ErrBMCMissingCredential
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, "username (set --bmc-user)", missing.Field)
}

// TestCtlXReader_PassesThroughBytesUntilEscape verifies that the disconnect
// reader returns errCtrlX exactly when it encounters the escape byte.
func TestCtlXReader_PassesThroughBytesUntilEscape(t *testing.T) {
	src := strings.NewReader("hello\x1Dworld")
	cr := &ctlXReader{r: src}

	buf := make([]byte, 16)
	n, err := cr.Read(buf)
	require.ErrorIs(t, err, errCtrlX)
	assert.Equal(t, "hello", string(buf[:n]))
}

func TestCtlXReader_NoEscapePassesThrough(t *testing.T) {
	src := strings.NewReader("hello")
	cr := &ctlXReader{r: src}

	buf := make([]byte, 16)
	n, err := cr.Read(buf)
	// io.EOF is reported by the underlying reader once the buffer drains.
	assert.True(t, err == nil || errors.Is(err, io.EOF))
	assert.Equal(t, "hello", string(buf[:n]))
}

// ---------------------------------------------------------------------------
// --send escape grammar
// ---------------------------------------------------------------------------

func TestDecodeSendEscapes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: ""},
		{name: "literal text", input: "fs0:", want: "fs0:"},
		{name: "line controls", input: `boot\r\n\t`, want: "boot\r\n\t"},
		{name: "escaped backslash", input: `a\\b`, want: `a\b`},
		{name: "escape key", input: `\e[A`, want: "\x1b[A"},
		{name: "hex lower, upper and mixed case", input: `\x41\x0a\xfF`, want: "A\n\xff"},
		{name: "hex followed by literal", input: `\x03q`, want: "\x03q"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeSendEscapes(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestDecodeSendEscapes_Errors(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		reason string
	}{
		{name: "trailing backslash", input: `abc\`, reason: "trailing backslash"},
		{name: "hex with no digits", input: `\x`, reason: `truncated \xNN escape`},
		{name: "hex with one digit", input: `\x4`, reason: `truncated \xNN escape`},
		{name: "non-hex first digit", input: `\xg1`, reason: `non-hex digit in \xNN escape`},
		{name: "non-hex second digit", input: `\x1G`, reason: `non-hex digit in \xNN escape`},
		{name: "unknown escape", input: `\q`, reason: `unrecognised escape \q`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeSendEscapes(tt.input)
			assert.Nil(t, got)
			var reason ErrBMCConsoleSendDecodeReason
			require.ErrorAs(t, err, &reason)
			assert.Equal(t, tt.reason, reason.Reason)
			assert.EqualError(t, err, tt.reason)
		})
	}
}

// ---------------------------------------------------------------------------
// SOL fake for --send and log mode
// ---------------------------------------------------------------------------

// fakeSOL stands in for *bmc.SOLSession. Read replays chunks, then blocks
// on block (when set) and returns readErr. Write records each payload.
type fakeSOL struct {
	chunks        []string
	readErr       error
	block         chan struct{}
	written       []string
	writeErr      error
	bytesReceived uint64
	instance      byte
}

func (f *fakeSOL) Read(p []byte) (int, error) {
	if len(f.chunks) > 0 {
		n := copy(p, f.chunks[0])
		f.chunks = f.chunks[1:]
		return n, nil
	}
	if f.block != nil {
		<-f.block
	}
	return 0, f.readErr
}

func (f *fakeSOL) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	f.written = append(f.written, string(p))
	return len(p), nil
}

func (f *fakeSOL) BytesReceived() uint64 { return f.bytesReceived }

func (f *fakeSOL) PayloadInstance() byte { return f.instance }

func TestSendStringsToSOL(t *testing.T) {
	sol := &fakeSOL{}
	stderr, err := captureStderr(t, func() error {
		return sendStringsToSOL(context.Background(), sol, []string{`root\r`, `\x03`}, 0)
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"root\r", "\x03"}, sol.written)
	assert.Equal(t,
		"bmc: console: sent 5 bytes (--send #1)\n"+
			"bmc: console: sent 1 bytes (--send #2)\n",
		stderr)
}

func TestSendStringsToSOL_DecodeErrorStopsBeforeWrite(t *testing.T) {
	sol := &fakeSOL{}
	_, err := captureStderr(t, func() error {
		return sendStringsToSOL(context.Background(), sol, []string{"ok", `bad\`}, 0)
	})
	var decode ErrBMCConsoleSendDecode
	require.ErrorAs(t, err, &decode)
	assert.Equal(t, `bad\`, decode.Input)
	var reason ErrBMCConsoleSendDecodeReason
	require.ErrorAs(t, err, &reason)
	assert.EqualError(t, err, `bmc: console: failed to decode --send input "bad\\": trailing backslash`)
	assert.Equal(t, []string{"ok"}, sol.written)
}

func TestSendStringsToSOL_WriteError(t *testing.T) {
	boom := errors.New("sol write boom")
	sol := &fakeSOL{writeErr: boom}
	err := sendStringsToSOL(context.Background(), sol, []string{"x"}, 0)
	var write ErrBMCConsoleSendWrite
	require.ErrorAs(t, err, &write)
	assert.Equal(t, 0, write.Index)
	require.ErrorIs(t, err, boom)
	assert.EqualError(t, err, "bmc: console: SOL write failed for --send #1: sol write boom")
}

// A cancelled context ends the inter-string delay without sending the rest.
func TestSendStringsToSOL_ContextCancelledDuringDelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sol := &fakeSOL{}
	_, err := captureStderr(t, func() error {
		return sendStringsToSOL(ctx, sol, []string{"first", "second"}, time.Hour)
	})
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, []string{"first"}, sol.written)
}

// ---------------------------------------------------------------------------
// log mode
// ---------------------------------------------------------------------------

func TestRunConsoleLogMode_Stdout(t *testing.T) {
	sol := &fakeSOL{chunks: []string{"hello ", "world"}, readErr: io.EOF, bytesReceived: 11}
	var stdout string
	stderr, err := captureStderr(t, func() error {
		var runErr error
		stdout, runErr = captureStdout(t, func() error {
			return runConsoleLogMode(context.Background(), sol, "")
		})
		return runErr
	})
	require.NoError(t, err)
	assert.Equal(t, "hello world", stdout)
	assert.Empty(t, stderr)
}

// The log file is truncated, owner-only, and holds exactly the SOL bytes.
func TestRunConsoleLogMode_LogFile(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "sol.log")
	require.NoError(t, os.WriteFile(logFile, []byte("stale bytes from a prior capture"), 0o600))

	sol := &fakeSOL{chunks: []string{"POST ", "ok\r\n"}, readErr: io.EOF, bytesReceived: 9}
	stderr, err := captureStderr(t, func() error {
		return runConsoleLogMode(context.Background(), sol, logFile)
	})
	require.NoError(t, err)
	assert.Equal(t, "Capturing SOL session to "+logFile+". Press Ctrl+C to stop.\n", stderr)

	data, err := os.ReadFile(logFile)
	require.NoError(t, err)
	assert.Equal(t, "POST ok\r\n", string(data))
	info, err := os.Stat(logFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

// A session that never delivered a byte warns about the payload instance.
func TestRunConsoleLogMode_ZeroBytesWarns(t *testing.T) {
	sol := &fakeSOL{readErr: io.EOF, instance: 1}
	logFile := filepath.Join(t.TempDir(), "sol.log")
	stderr, err := captureStderr(t, func() error {
		return runConsoleLogMode(context.Background(), sol, logFile)
	})
	require.NoError(t, err)
	assert.Contains(t, stderr, "WARNING: SOL session activated on payload instance 0x01 but received zero data bytes.")
	assert.Contains(t, stderr, "Try --sol-instance 2.\n")
}

func TestRunConsoleLogMode_ReadError(t *testing.T) {
	boom := errors.New("sol read boom")
	sol := &fakeSOL{chunks: []string{"x"}, readErr: boom, bytesReceived: 1}
	_, err := captureStderr(t, func() error {
		return runConsoleLogMode(context.Background(), sol, filepath.Join(t.TempDir(), "sol.log"))
	})
	require.ErrorIs(t, err, boom)
}

func TestRunConsoleLogMode_OutputWriteError(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	require.NoError(t, r.Close())
	require.NoError(t, w.Close())
	orig := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = orig })

	sol := &fakeSOL{chunks: []string{"x"}, readErr: io.EOF, bytesReceived: 1}
	err = runConsoleLogMode(context.Background(), sol, "")
	require.ErrorIs(t, err, os.ErrClosed)
}

func TestRunConsoleLogMode_LogFileOpenError(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "missing-dir", "sol.log")
	err := runConsoleLogMode(context.Background(), &fakeSOL{}, logFile)
	var act ErrBMCConsoleActivate
	require.ErrorAs(t, err, &act)
	require.ErrorIs(t, err, fs.ErrNotExist)
	assert.EqualError(t, err, "bmc: failed to activate SOL console: open "+logFile+": no such file or directory")
}

// Cancelling the context ends a capture whose BMC never closes the session.
func TestRunConsoleLogMode_ContextCancelled(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	sol := &fakeSOL{block: block, readErr: io.EOF, bytesReceived: 1}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := captureStderr(t, func() error {
		return runConsoleLogMode(ctx, sol, filepath.Join(t.TempDir(), "sol.log"))
	})
	require.ErrorIs(t, err, context.Canceled)
}
